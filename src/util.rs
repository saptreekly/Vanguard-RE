//! Shared helpers: memory mapping, hashing, path collection.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

/// Refuse to ingest a single host file larger than this (DoS / sparse-file guard).
pub const MAX_SAMPLE_BYTES: u64 = 512 * 1024 * 1024;
/// Cap total retained sample bytes across one investigation (host files + ZIP
/// children + embedded extracts). Without this, a directory of many near-limit
/// files can OOM despite the per-file cap.
pub const MAX_TOTAL_RETAINED_BYTES: u64 = 512 * 1024 * 1024;

/// Strip C0/C1 control characters (including ESC/CSI) from analyst-facing text.
///
/// Malware-controlled filesystem names and ZIP labels must not be able to
/// hijack terminal output via ANSI / OSC escape sequences.
pub fn sanitize_display_label(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\0' && !c.is_control())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_ansi_and_nul() {
        assert_eq!(sanitize_display_label("a\x1b[31mb\0c"), "a[31mbc");
        assert_eq!(sanitize_display_label("/tmp/\u{07}evil"), "/tmp/evil");
    }
}

/// Memory-map a file for zero-copy analysis.
pub fn map_file(path: &Path) -> Result<Mmap> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let len = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if len > MAX_SAMPLE_BYTES {
        bail!(
            "{} is {len} bytes; exceeds max sample size of {MAX_SAMPLE_BYTES} bytes",
            path.display()
        );
    }
    // SAFETY: read-only mapping of a local file opened above; we never write
    // through the map, and the File stays open for the lifetime of Mmap.
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("mmap {}", path.display()))?;
    Ok(mmap)
}

/// SHA-256 of a byte slice (used for file identity).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Collect files for triage/scan. Directories expand (optionally recursive).
pub fn collect_targets(path: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        anyhow::bail!("{} is not a file or directory", path.display());
    }

    let walker = if recursive {
        WalkDir::new(path).follow_links(false)
    } else {
        WalkDir::new(path).max_depth(1).follow_links(false)
    };

    let mut out = Vec::new();
    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if entry.path_is_symlink() {
            continue;
        }
        if entry.file_type().is_file() {
            out.push(entry.into_path());
        }
    }
    out.sort();
    Ok(out)
}
