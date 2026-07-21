//! Containment: ingest archives and samples without ever executing them.
//!
//! # Safety model
//!
//! Vanguard-RE is **static-only**. It never `exec`s, `spawn`s, or maps sample
//! pages as executable. Passworded ZIP members are decrypted **into RAM** and
//! parsed from byte slices — they are not written to disk as runnable files.
//!
//! A custom “lightweight hypervisor” is intentionally **not** part of this
//! path: building a trustworthy HV is a multi-year systems project, and for
//! static triage it buys nothing over in-memory parsing. If dynamic analysis
//! is added later, isolate it with a battle-tested microVM (Apple
//! Virtualization.framework, Firecracker, or QEMU), never by running the
//! sample on the host.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use walkdir::WalkDir;
use zip::ZipArchive;

use crate::util::map_file;

/// A sample ready for static analysis. Bytes live in process memory only.
#[derive(Debug, Clone)]
pub struct QuarantinedSample {
    /// Display / report label (zip member path or filesystem path).
    pub label: String,
    /// Origin archive, if extracted from one.
    pub archive: Option<String>,
    /// Raw file bytes — never marked executable; never written to disk here.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ContainmentReport {
    pub mode: &'static str,
    pub executes_samples: bool,
    pub writes_samples_to_disk: bool,
    pub notes: Vec<String>,
}

pub fn containment_policy() -> ContainmentReport {
    ContainmentReport {
        mode: "static-in-memory",
        executes_samples: false,
        writes_samples_to_disk: false,
        notes: vec![
            "Samples are memory-mapped or decrypted into RAM only.".into(),
            "No process spawn / CreateProcess / execve of sample bytes.".into(),
            "ZIP members are never extracted with execute permission.".into(),
            "Dynamic analysis would require an external microVM — not host exec.".into(),
        ],
    }
}

fn is_zip(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
        || looks_like_zip_magic(path).unwrap_or(false)
}

fn looks_like_zip_magic(path: &Path) -> Result<bool> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    Ok(n >= 4 && (magic == *b"PK\x03\x04" || (magic[0] == b'P' && magic[1] == b'K')))
}

/// Collect analysis targets. ZIP inputs expand in-memory (password optional).
pub fn collect_samples(
    path: &Path,
    recursive: bool,
    password: Option<&str>,
) -> Result<Vec<QuarantinedSample>> {
    if path.is_file() {
        if is_zip(path) {
            return decrypt_zip_in_memory(path, password);
        }
        let mmap = map_file(path)?;
        return Ok(vec![QuarantinedSample {
            label: path.display().to_string(),
            archive: None,
            data: mmap[..].to_vec(),
        }]);
    }

    if !path.is_dir() {
        bail!("{} is not a file or directory", path.display());
    }

    let walker = if recursive {
        WalkDir::new(path)
    } else {
        WalkDir::new(path).max_depth(1)
    };

    let mut out = Vec::new();
    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if is_zip(p) {
            match decrypt_zip_in_memory(p, password) {
                Ok(mut samples) => out.append(&mut samples),
                Err(e) => eprintln!("skip zip {}: {e:#}", p.display()),
            }
        } else {
            match map_file(p) {
                Ok(mmap) => out.push(QuarantinedSample {
                    label: p.display().to_string(),
                    archive: None,
                    data: mmap[..].to_vec(),
                }),
                Err(e) => eprintln!("skip {}: {e:#}", p.display()),
            }
        }
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(out)
}

/// Decrypt every file member of a ZIP into RAM. Never writes members to disk.
pub fn decrypt_zip_in_memory(path: &Path, password: Option<&str>) -> Result<Vec<QuarantinedSample>> {
    let file = File::open(path).with_context(|| format!("open archive {}", path.display()))?;
    let mut archive =
        ZipArchive::new(file).with_context(|| format!("parse ZIP {}", path.display()))?;

    let archive_label = path.display().to_string();
    let mut samples = Vec::new();
    let mut encrypted_seen = false;
    let mut password_failures = 0usize;

    for i in 0..archive.len() {
        // Raw metadata does not require the password.
        let (name, encrypted, is_dir, size) = {
            let meta = archive
                .by_index_raw(i)
                .with_context(|| format!("ZIP metadata index {i}"))?;
            (
                meta.name().to_string(),
                meta.encrypted(),
                meta.is_dir(),
                meta.size(),
            )
        };

        if is_dir {
            continue;
        }
        if name.contains("..") || Path::new(&name).is_absolute() {
            eprintln!("skip unsafe ZIP path in {}: {name}", path.display());
            continue;
        }

        if encrypted {
            encrypted_seen = true;
            let Some(pw) = password else {
                bail!(
                    "{} contains encrypted members; pass --password / -p (e.g. -p infected)",
                    path.display()
                );
            };

            let mut entry = match archive.by_index_decrypt(i, pw.as_bytes()) {
                Ok(e) => e,
                Err(zip::result::ZipError::InvalidPassword) => {
                    password_failures += 1;
                    continue;
                }
                Err(e) => {
                    // Wrong ZipCrypto password often surfaces as UnsupportedArchive / Io
                    password_failures += 1;
                    eprintln!(
                        "skip {} [{}]: {e} — wrong password?",
                        path.display(),
                        sanitize_member_name(&name)
                    );
                    continue;
                }
            };

            let member = sanitize_member_name(entry.name());
            let mut data = Vec::with_capacity(size as usize);
            if let Err(e) = entry.read_to_end(&mut data) {
                password_failures += 1;
                eprintln!(
                    "skip {} [{member}]: decrypt/read failed ({e}) — wrong password?",
                    path.display()
                );
                continue;
            }

            samples.push(QuarantinedSample {
                label: format!("{archive_label}::{member}"),
                archive: Some(archive_label.clone()),
                data,
            });
        } else {
            let mut entry = archive.by_index(i).with_context(|| format!("ZIP index {i}"))?;
            let member = sanitize_member_name(entry.name());
            let mut data = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut data)
                .with_context(|| format!("read ZIP member {member}"))?;
            samples.push(QuarantinedSample {
                label: format!("{archive_label}::{member}"),
                archive: Some(archive_label.clone()),
                data,
            });
        }
    }

    if encrypted_seen && samples.is_empty() {
        bail!(
            "failed to decrypt any members in {} (password failures: {password_failures})",
            path.display()
        );
    }

    if samples.is_empty() {
        bail!("no file members found in {}", path.display());
    }

    Ok(samples)
}

fn sanitize_member_name(name: &str) -> String {
    // Flatten to a single path component for labels; reject traversal earlier.
    PathBuf::from(name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.replace(['/', '\\'], "_"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_never_executes() {
        let p = containment_policy();
        assert!(!p.executes_samples);
        assert!(!p.writes_samples_to_disk);
    }
}
