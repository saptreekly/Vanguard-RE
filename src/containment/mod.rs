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
use std::io::{Cursor, Read, Seek};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;
use zip::ZipArchive;

use crate::util::map_file;

const MAX_ARCHIVE_DEPTH: usize = 3;
const MAX_ARCHIVE_MEMBERS: usize = 512;
/// Hard cap on central-directory entries inspected (priority scan + listing).
/// Malware can advertise millions of CD entries; never materialize that many.
const MAX_CENTRAL_DIR_SCAN: usize = 4_096;
const MAX_MEMBER_SIZE: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_EXTRACTED: u64 = 512 * 1024 * 1024;
/// Cap carved embedded ZIPs per sample to bound carve/parse work.
const MAX_EMBEDDED_ZIPS: usize = 32;
/// Cap total local-header probes when carving. Dense `PK\x03\x04` noise without
/// a matching EOCD is a classic quadratic DoS against naïve scanners.
const MAX_EMBEDDED_LOCAL_PROBES: usize = 2_048;
/// Cap how far past a local-file header we will scan for an EOCD.
const MAX_EOCD_SEARCH: usize = 4 * 1024 * 1024;
/// Abort carving after this many consecutive LOCAL hits that fail header
/// validation or EOCD matching — dense PK noise fails repeatedly; real
/// embedded archives usually succeed within a few probes.
const MAX_CONSECUTIVE_FAILED_PROBES: usize = 64;
/// Cap total quarantined samples retained for one investigation.
const MAX_QUARANTINED_SAMPLES: usize = 2_048;

/// A sample ready for static analysis. Bytes live in process memory only.
#[derive(Debug, Clone)]
pub struct QuarantinedSample {
    /// Display / report label (zip member path or filesystem path).
    pub label: String,
    /// Origin archive, if extracted from one.
    pub archive: Option<String>,
    /// Raw file bytes — never marked executable; never written to disk here.
    pub data: Vec<u8>,
    /// ZIP archives carved out of this sample's own bytes (overlay / resource
    /// section). Recorded even when members cannot be decrypted, because the
    /// central-directory listing alone is a strong triage signal (e.g. the
    /// WannaCry encryptor embeds a passworded ZIP of `.wnry` payloads).
    pub embedded_archives: Vec<EmbeddedArchive>,
}

impl QuarantinedSample {
    fn new(label: String, archive: Option<String>, data: Vec<u8>) -> Self {
        Self {
            label,
            archive,
            data,
            embedded_archives: Vec::new(),
        }
    }
}

/// A ZIP found embedded inside another sample's bytes.
#[derive(Debug, Clone)]
pub struct EmbeddedArchive {
    /// Synthetic label, e.g. `embedded-1.zip`.
    pub label: String,
    /// Byte offset of the local-file header within the parent sample.
    pub offset: usize,
    /// Carved span length in the parent (bytes).
    pub span: usize,
    /// Central-directory listing (no password required to read this).
    pub members: Vec<EmbeddedMember>,
    /// How many members were successfully decrypted + added as samples.
    pub extracted: usize,
    /// Password recovered from the parent sample's own strings (candidate
    /// attack), if the archive was encrypted and a plaintext password matched.
    pub recovered_password: Option<String>,
}

impl EmbeddedArchive {
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
    pub fn encrypted_count(&self) -> usize {
        self.members.iter().filter(|m| m.encrypted).count()
    }
    pub fn total_size(&self) -> u64 {
        self.members.iter().map(|m| m.size).sum()
    }
}

/// A single member entry read from an embedded ZIP's central directory.
#[derive(Debug, Clone)]
pub struct EmbeddedMember {
    pub name: String,
    pub size: u64,
    pub encrypted: bool,
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
            "Recovered inner-archive payloads stay in RAM; never written as runnable files.".into(),
            "Archive depth, member count, per-member/total bytes, sample count, and host file size are capped.".into(),
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
    // Accept only real ZIP signatures — not every `PK*` blob.
    Ok(n >= 4
        && (magic == *b"PK\x03\x04" // local file header
            || magic == *b"PK\x05\x06" // empty archive EOCD
            || magic == *b"PK\x07\x08")) // spanned archive marker
}

/// Collect analysis targets. ZIP inputs expand in-memory (password optional).
pub fn collect_samples(
    path: &Path,
    recursive: bool,
    password: Option<&str>,
) -> Result<Vec<QuarantinedSample>> {
    if path.is_file() {
        if is_zip(path) {
            let samples = decrypt_zip_in_memory(path, password)?;
            return Ok(expand_embedded_archives(samples, password));
        }
        let mmap = map_file(path)?;
        let samples = vec![QuarantinedSample::new(
            path.display().to_string(),
            None,
            mmap[..].to_vec(),
        )];
        return Ok(expand_embedded_archives(samples, password));
    }

    if !path.is_dir() {
        bail!("{} is not a file or directory", path.display());
    }

    // Never follow directory symlinks into unrelated trees (malicious corpora).
    let walker = if recursive {
        WalkDir::new(path).follow_links(false)
    } else {
        WalkDir::new(path).max_depth(1).follow_links(false)
    };

    let mut out = Vec::new();
    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if out.len() >= MAX_QUARANTINED_SAMPLES {
            eprintln!(
                "sample cap ({MAX_QUARANTINED_SAMPLES}) reached under {}; stopping directory walk",
                path.display()
            );
            break;
        }
        // Skip symlinks entirely — only analyze regular files.
        if entry.path_is_symlink() || !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if is_zip(p) {
            match decrypt_zip_in_memory(p, password) {
                Ok(mut samples) => {
                    let room = MAX_QUARANTINED_SAMPLES.saturating_sub(out.len());
                    if samples.len() > room {
                        samples.truncate(room);
                    }
                    out.append(&mut samples);
                }
                Err(e) => eprintln!("skip zip {}: {e:#}", p.display()),
            }
        } else {
            match map_file(p) {
                Ok(mmap) => out.push(QuarantinedSample::new(
                    p.display().to_string(),
                    None,
                    mmap[..].to_vec(),
                )),
                Err(e) => eprintln!("skip {}: {e:#}", p.display()),
            }
        }
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(expand_embedded_archives(out, password))
}

/// Decrypt every file member of a ZIP into RAM. Never writes members to disk.
pub fn decrypt_zip_in_memory(
    path: &Path,
    password: Option<&str>,
) -> Result<Vec<QuarantinedSample>> {
    let file = File::open(path).with_context(|| format!("open archive {}", path.display()))?;
    let archive_label = path.display().to_string();
    extract_zip_members(file, &archive_label, password)
}

/// Find complete ZIP archives embedded in arbitrary bytes.
///
/// Each returned range begins at a local-file header and ends after the EOCD
/// record (including its comment). This avoids handing unrelated executable
/// suffix bytes to the ZIP parser.
///
/// Malware can sprinkle `PK\x03\x04` throughout a blob. Without probe/search
/// caps, each false local header would scan the remainder of the file for an
/// EOCD — O(n²) CPU against a single sample. Bound probes, EOCD look-ahead,
/// consecutive failures, and reject LOCAL hits that fail a cheap header check
/// before any EOCD scan.
fn embedded_zip_ranges(data: &[u8]) -> Vec<std::ops::Range<usize>> {
    const LOCAL: &[u8] = b"PK\x03\x04";
    const EOCD: &[u8] = b"PK\x05\x06";
    let mut ranges = Vec::new();
    let mut search_from = 0;
    let mut probes = 0usize;
    let mut consecutive_failures = 0usize;

    while search_from + LOCAL.len() <= data.len()
        && ranges.len() < MAX_EMBEDDED_ZIPS
        && probes < MAX_EMBEDDED_LOCAL_PROBES
        && consecutive_failures < MAX_CONSECUTIVE_FAILED_PROBES
    {
        let Some(rel_start) = find_bytes(&data[search_from..], LOCAL) else {
            break;
        };
        let start = search_from + rel_start;
        probes += 1;

        if !looks_like_zip_local_header(data, start) {
            // Cheap reject — do not burn the expensive-failure budget.
            search_from = start + LOCAL.len();
            continue;
        }

        let search_limit = (start.saturating_add(MAX_EOCD_SEARCH)).min(data.len());
        let mut eocd_from = start + LOCAL.len();
        let mut carved = None;

        while eocd_from + 22 <= search_limit {
            let Some(rel_eocd) = find_bytes(&data[eocd_from..search_limit], EOCD) else {
                break;
            };
            let eocd = eocd_from + rel_eocd;
            if eocd + 22 > data.len() {
                break;
            }
            let comment_len = u16::from_le_bytes([data[eocd + 20], data[eocd + 21]]) as usize;
            let end = eocd + 22 + comment_len;
            // Reject absurd EOCD comments that would escape the sample or the
            // look-ahead budget (attacker-controlled u16).
            if end <= data.len() && end.saturating_sub(start) <= MAX_EOCD_SEARCH {
                carved = Some(start..end);
                break;
            }
            eocd_from = eocd + EOCD.len();
        }

        if let Some(range) = carved {
            consecutive_failures = 0;
            search_from = range.end;
            ranges.push(range);
        } else {
            // Plausible local header but no EOCD within budget — expensive miss.
            consecutive_failures += 1;
            search_from = start + LOCAL.len();
        }
    }
    ranges
}

/// Cheap local-file-header sanity check before spending EOCD-scan budget.
///
/// Dense `PK\x03\x04` noise almost never has a plausible compression method /
/// name length; real ZIP members do.
fn looks_like_zip_local_header(data: &[u8], start: usize) -> bool {
    if start + 30 > data.len() {
        return false;
    }
    let method = u16::from_le_bytes([data[start + 8], data[start + 9]]);
    // Store / Deflate / Deflate64 / BZIP2 / LZMA / PPMd / AES (99).
    if !matches!(method, 0 | 8 | 9 | 12 | 14 | 98 | 99) {
        return false;
    }
    let name_len = u16::from_le_bytes([data[start + 26], data[start + 27]]) as usize;
    let extra_len = u16::from_le_bytes([data[start + 28], data[start + 29]]) as usize;
    if name_len > 1_024 || extra_len > 4_096 {
        return false;
    }
    let header_end = start.saturating_add(30).saturating_add(name_len).saturating_add(extra_len);
    if header_end > data.len() {
        return false;
    }
    if name_len > 0 {
        let name = &data[start + 30..start + 30 + name_len];
        // Member names are path-like ASCII; reject mostly binary "names".
        let weird = name
            .iter()
            .filter(|&&b| b == 0 || !(0x20..=0x7e).contains(&b))
            .count();
        if weird > name_len / 4 {
            return false;
        }
    }
    true
}

/// Memchr-style byte-needle search (faster than `windows().position` for short
/// fixed needles used in ZIP carving).
fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Recursively carve embedded ZIPs and add their members as in-memory samples.
///
/// The central-directory listing is always recorded on the parent sample, even
/// when members are encrypted with an unknown password — the listing itself is
/// a high-value triage signal. Members that *can* be decrypted are additionally
/// promoted to standalone samples for full analysis.
fn expand_embedded_archives(
    roots: Vec<QuarantinedSample>,
    password: Option<&str>,
) -> Vec<QuarantinedSample> {
    let mut out = Vec::new();
    let mut pending: Vec<(QuarantinedSample, usize)> =
        roots.into_iter().map(|sample| (sample, 0)).collect();

    while let Some((mut sample, depth)) = pending.pop() {
        if out.len() + pending.len() >= MAX_QUARANTINED_SAMPLES {
            // Keep what we have; drop further expansion to bound memory.
            out.push(sample);
            while let Some((extra, _)) = pending.pop() {
                if out.len() >= MAX_QUARANTINED_SAMPLES {
                    break;
                }
                out.push(extra);
            }
            break;
        }
        if depth < MAX_ARCHIVE_DEPTH {
            for (index, range) in embedded_zip_ranges(&sample.data).into_iter().enumerate() {
                // A sample that is itself exactly a ZIP was already expanded by
                // the outer ingest path; don't add all its members twice.
                if range.start == 0 && range.end == sample.data.len() {
                    continue;
                }
                let label = format!("embedded-{}.zip", index + 1);
                let archive_label = format!("{}::{}", sample.label, label);
                let blob = &sample.data[range.clone()];

                // Listing needs no password; skip malformed carves silently.
                let members = match list_zip_members(Cursor::new(blob)) {
                    Ok(m) if !m.is_empty() => m,
                    Ok(_) => continue,
                    Err(_) => continue,
                };
                let encrypted_members = members.iter().filter(|m| m.encrypted).count();

                // Best-effort decryption with the caller-supplied password first.
                let mut recovered_password = None;
                let mut extracted =
                    match extract_zip_members(Cursor::new(blob), &archive_label, password) {
                        Ok(children) => {
                            let n = children.len();
                            for child in children {
                                if out.len() + pending.len() + 1 >= MAX_QUARANTINED_SAMPLES {
                                    break;
                                }
                                pending.push((child, depth + 1));
                            }
                            n
                        }
                        Err(_) => 0,
                    };

                // If encrypted members remain locked, mount a candidate-password
                // attack using printable strings from the *parent* sample. Many
                // droppers (WannaCry: `WNcry@2ol7`) hardcode the inner password
                // in cleartext elsewhere in the file.
                if extracted == 0 && encrypted_members > 0 {
                    let candidates = harvest_password_candidates(&sample.data);
                    if let Some(pw) = try_recover_zip_password(blob, &candidates) {
                        if let Ok(children) =
                            extract_zip_members(Cursor::new(blob), &archive_label, Some(&pw))
                        {
                            extracted = children.len();
                            for child in children {
                                if out.len() + pending.len() + 1 >= MAX_QUARANTINED_SAMPLES {
                                    break;
                                }
                                pending.push((child, depth + 1));
                            }
                        }
                        recovered_password = Some(pw);
                    }
                }

                sample.embedded_archives.push(EmbeddedArchive {
                    label,
                    offset: range.start,
                    span: range.end - range.start,
                    members,
                    extracted,
                    recovered_password,
                });
            }
        }
        out.push(sample);
    }

    out.sort_by(|a, b| a.label.cmp(&b.label));
    out
}

/// Read an embedded ZIP's central directory without decrypting any member.
/// Names, sizes, and encryption flags are stored in cleartext, so this works
/// even for password-protected archives (e.g. WannaCry's `WNcry@2ol7` bundle).
fn list_zip_members<R: Read + Seek>(reader: R) -> Result<Vec<EmbeddedMember>> {
    let mut archive = ZipArchive::new(reader)?;
    let count = archive.len().min(MAX_ARCHIVE_MEMBERS).min(MAX_CENTRAL_DIR_SCAN);
    let mut members = Vec::with_capacity(count);
    for i in 0..count {
        let meta = archive.by_index_raw(i)?;
        if meta.is_dir() {
            continue;
        }
        members.push(EmbeddedMember {
            name: meta.name().to_string(),
            size: meta.size(),
            encrypted: meta.encrypted(),
        });
    }
    Ok(members)
}

/// Maximum candidate passwords to try (bounds worst-case recovery time).
const MAX_PASSWORD_CANDIDATES: usize = 2_000;
/// Soft cap while scanning so we do not materialize every printable run in a
/// huge binary before ranking/truncating.
const MAX_PASSWORD_HARVEST: usize = 20_000;

/// Harvest printable-ASCII tokens that could plausibly be a password/key.
///
/// Passwords are contiguous non-whitespace printable runs of moderate length.
/// We keep maximal runs (deduped), then rank high-signal tokens first and
/// truncate — WannaCry stores its inner ZIP password `WNcry@2ol7` as exactly
/// such a null-terminated literal.
fn harvest_password_candidates(data: &[u8]) -> Vec<String> {
    const MIN: usize = 4;
    const MAX: usize = 64;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut run_start: Option<usize> = None;

    let mut flush = |start: usize, end: usize, out: &mut Vec<String>| {
        let len = end - start;
        if (MIN..=MAX).contains(&len) {
            if let Ok(tok) = std::str::from_utf8(&data[start..end]) {
                if seen.insert(tok) {
                    out.push(tok.to_string());
                }
            }
        }
    };

    for (i, &b) in data.iter().enumerate() {
        let printable = (0x21..=0x7e).contains(&b);
        match (printable, run_start) {
            (true, None) => run_start = Some(i),
            (false, Some(s)) => {
                flush(s, i, &mut out);
                run_start = None;
                if out.len() >= MAX_PASSWORD_HARVEST {
                    break;
                }
            }
            _ => {}
        }
    }
    if let Some(s) = run_start {
        if out.len() < MAX_PASSWORD_HARVEST {
            flush(s, data.len(), &mut out);
        }
    }

    out.sort_by_key(|s| password_candidate_rank(s));
    out.truncate(MAX_PASSWORD_CANDIDATES);
    out
}

/// Lower is better: prefer medium length + mixed character classes.
fn password_candidate_rank(s: &str) -> (u8, u8, usize) {
    let len = s.len();
    let len_band = if (6..=24).contains(&len) {
        0
    } else if (4..=40).contains(&len) {
        1
    } else {
        2
    };
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_special = s.bytes().any(|b| !b.is_ascii_alphanumeric());
    let has_alpha = s.bytes().any(|b| b.is_ascii_alphabetic());
    let class_score = match (has_alpha, has_digit, has_special) {
        (true, true, true) => 0,
        (true, true, false) | (true, false, true) | (false, true, true) => 1,
        _ => 2,
    };
    (len_band, class_score, len)
}

/// Try each candidate as the password for an embedded ZIP.
///
/// Tests against the smallest encrypted member to minimize per-attempt cost,
/// and confirms success by fully decrypting + CRC-checking it (ZipCrypto's
/// 1-byte header check alone has a ~1/256 false-accept rate). Returns the
/// first password that decrypts cleanly.
fn try_recover_zip_password(blob: &[u8], candidates: &[String]) -> Option<String> {
    let mut archive = ZipArchive::new(Cursor::new(blob)).ok()?;

    // Pick the cheapest encrypted member to probe — bound by declared size so
    // a tiny compressed stream with a huge declared uncompressed size cannot
    // become a decompression bomb during password trials.
    let scan = archive.len().min(MAX_CENTRAL_DIR_SCAN);
    let mut target = None;
    let mut best = u64::MAX;
    for i in 0..scan {
        if let Ok(m) = archive.by_index_raw(i) {
            if m.encrypted()
                && !m.is_dir()
                && m.size() > 0
                && m.size() <= MAX_MEMBER_SIZE
                && m.compressed_size() < best
            {
                best = m.compressed_size();
                target = Some((i, m.size()));
            }
        }
    }
    let (idx, declared) = target?;

    for cand in candidates {
        match archive.by_index_decrypt(idx, cand.as_bytes()) {
            Ok(entry) => {
                // A clean bounded read implies the CRC validated → correct password.
                if read_zip_member_bounded(entry, declared, declared).is_ok() {
                    return Some(cand.clone());
                }
            }
            Err(_) => continue,
        }
    }
    None
}

/// Read at most `limit` decompressed bytes from a ZIP member.
///
/// Declared uncompressed sizes are attacker-controlled. Trusting them for
/// `read_to_end` alone enables classic zip bombs (small compressed payload,
/// huge expansion). We always hard-cap the read and reject oversize streams.
fn read_zip_member_bounded<R: Read>(entry: R, declared: u64, budget: u64) -> Result<Vec<u8>> {
    let limit = declared.min(MAX_MEMBER_SIZE).min(budget);
    if limit == 0 {
        // Empty members are fine; anything that still yields bytes is hostile.
        let mut probe = entry.take(1);
        let mut bump = [0u8; 1];
        let n = probe.read(&mut bump)?;
        if n != 0 {
            bail!("ZIP member produced data despite declared size 0");
        }
        return Ok(Vec::new());
    }

    let mut reader = entry.take(limit.saturating_add(1));
    // Avoid eagerly committing the full declared size (often a lie).
    let mut data = Vec::with_capacity((limit as usize).min(64 * 1024));
    reader.read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        bail!("ZIP member expanded past bound ({limit} bytes; declared {declared})");
    }
    Ok(data)
}

fn extract_zip_members<R: Read + Seek>(
    reader: R,
    archive_label: &str,
    password: Option<&str>,
) -> Result<Vec<QuarantinedSample>> {
    let mut archive =
        ZipArchive::new(reader).with_context(|| format!("parse ZIP {archive_label}"))?;
    let scan_len = archive.len().min(MAX_CENTRAL_DIR_SCAN);
    if archive.len() > MAX_CENTRAL_DIR_SCAN {
        eprintln!(
            "{archive_label} advertises {} central-directory entries; scanning only \
             {MAX_CENTRAL_DIR_SCAN}",
            archive.len()
        );
    }
    let mut indices: Vec<(usize, u8)> = (0..scan_len)
        .map(|i| {
            let priority = archive
                .by_index_raw(i)
                .ok()
                .map(|entry| archive_member_priority(entry.name()))
                .unwrap_or(u8::MAX);
            (i, priority)
        })
        .collect();
    if indices.len() > MAX_ARCHIVE_MEMBERS {
        eprintln!(
            "{archive_label} has {} members; analyzing a prioritized subset of \
             {MAX_ARCHIVE_MEMBERS}",
            indices.len()
        );
        // Prefer runnable/config/document payloads over source, symbols, and
        // metadata while preserving archive order within each priority.
        indices.sort_by_key(|(index, priority)| (*priority, *index));
        indices.truncate(MAX_ARCHIVE_MEMBERS);
        indices.sort_by_key(|(index, _)| *index);
    }

    let mut samples = Vec::new();
    let mut encrypted_seen = false;
    let mut password_failures = 0usize;
    let mut total_extracted = 0u64;

    for (i, _) in indices {
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
        if is_unsafe_zip_path(&name) {
            eprintln!(
                "skip unsafe ZIP path in {archive_label}: {}",
                sanitize_member_name(&name)
            );
            continue;
        }
        if size > MAX_MEMBER_SIZE || total_extracted.saturating_add(size) > MAX_TOTAL_EXTRACTED {
            eprintln!(
                "skip oversized ZIP member in {archive_label}: {} ({size} bytes)",
                sanitize_member_name(&name)
            );
            continue;
        }

        let budget = MAX_TOTAL_EXTRACTED.saturating_sub(total_extracted);

        if encrypted {
            encrypted_seen = true;
            let Some(pw) = password else {
                bail!(
                    "{archive_label} contains encrypted members; provide a password (e.g. infected)"
                );
            };

            let entry = match archive.by_index_decrypt(i, pw.as_bytes()) {
                Ok(e) => e,
                Err(zip::result::ZipError::InvalidPassword) => {
                    password_failures += 1;
                    continue;
                }
                Err(e) => {
                    // Wrong ZipCrypto password often surfaces as UnsupportedArchive / Io
                    password_failures += 1;
                    eprintln!(
                        "skip {archive_label} [{}]: {e} — wrong password?",
                        sanitize_member_name(&name)
                    );
                    continue;
                }
            };

            let member = sanitize_member_name(entry.name());
            let data = match read_zip_member_bounded(entry, size, budget) {
                Ok(data) => data,
                Err(e) => {
                    password_failures += 1;
                    eprintln!(
                        "skip {archive_label} [{member}]: decrypt/read failed ({e}) — wrong password or bomb?"
                    );
                    continue;
                }
            };
            total_extracted = total_extracted.saturating_add(data.len() as u64);

            samples.push(QuarantinedSample::new(
                format!("{archive_label}::{member}"),
                Some(archive_label.to_string()),
                data,
            ));
        } else {
            let entry = archive
                .by_index(i)
                .with_context(|| format!("ZIP index {i}"))?;
            let member = sanitize_member_name(entry.name());
            let data = read_zip_member_bounded(entry, size, budget)
                .with_context(|| format!("read ZIP member {member}"))?;
            total_extracted = total_extracted.saturating_add(data.len() as u64);
            samples.push(QuarantinedSample::new(
                format!("{archive_label}::{member}"),
                Some(archive_label.to_string()),
                data,
            ));
        }
    }

    if encrypted_seen && samples.is_empty() {
        bail!(
            "failed to decrypt any members in {archive_label} \
             (password failures: {password_failures})"
        );
    }

    if samples.is_empty() {
        bail!("no file members found in {archive_label}");
    }

    Ok(samples)
}

fn archive_member_priority(name: &str) -> u8 {
    let extension = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match extension.as_str() {
        // Executables and common active payloads.
        "exe" | "dll" | "sys" | "com" | "scr" | "cpl" | "elf" | "bin" | "apk" | "jar" | "dex"
        | "class" | "js" | "jse" | "vbs" | "vbe" | "ps1" | "bat" | "cmd" | "sh" | "hta" | "msi" => {
            0
        }
        // Likely configs, lures, or embedded content.
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" | "rtf" | "xml" | "json"
        | "ini" | "cfg" | "conf" | "dat" | "db" | "zip" | "rar" | "7z" => 1,
        // Source/build metadata is useful, but less important under a hard cap.
        "c" | "cc" | "cpp" | "h" | "hpp" | "cs" | "java" | "py" | "go" | "rs" | "sln"
        | "vcxproj" | "pdb" | "md" | "txt" => 3,
        _ => 2,
    }
}

/// Reject ZIP member names that look like traversal / absolute / drive paths.
///
/// Members are never written to disk, but unsafe names still poison labels and
/// can confuse downstream tooling that re-parses report paths.
fn is_unsafe_zip_path(name: &str) -> bool {
    if name.is_empty() || name.contains('\0') {
        return true;
    }
    // Windows drive / UNC style must be rejected even when the host is Unix.
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return true;
    }
    if name.starts_with('\\') || name.starts_with("//") || name.starts_with("\\\\") {
        return true;
    }

    let path = Path::new(name);
    if path.is_absolute() {
        return true;
    }
    for component in path.components() {
        match component {
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => return true,
            Component::Normal(part) if part == ".." => return true,
            _ => {}
        }
    }
    // Path::components on Unix treats `\` as a normal character; still split.
    name.split(['/', '\\']).any(|part| part == "..")
}

fn sanitize_member_name(name: &str) -> String {
    // Flatten to a single path component for labels; reject traversal earlier.
    // Strip C0/C1 controls so malware member names cannot hijack terminal output.
    let cleaned: String = name
        .chars()
        .filter(|c| *c != '\0' && !c.is_control())
        .collect();
    let leaf = PathBuf::from(&cleaned)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| cleaned.replace(['/', '\\'], "_"));
    if leaf.is_empty() {
        "unnamed".into()
    } else {
        leaf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    #[test]
    fn policy_never_executes() {
        let p = containment_policy();
        assert!(!p.executes_samples);
        assert!(!p.writes_samples_to_disk);
    }

    fn test_zip(member: &str, contents: &[u8]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file(member, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(contents).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn encrypted_zip(members: &[(&str, &[u8])], password: &str) -> Vec<u8> {
        use zip::AesMode;
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        for (name, contents) in members {
            let opts = SimpleFileOptions::default().with_aes_encryption(AesMode::Aes256, password);
            writer.start_file(*name, opts).unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn detects_and_extracts_zip_embedded_in_binary() {
        let zip = test_zip("c.wnry", b"gx7ekbenv2riucmf.onion");
        let mut binary = b"MZ\x90\x00fake-pe-prefix".to_vec();
        binary.extend_from_slice(&zip);
        binary.extend_from_slice(b"executable-overlay");

        let ranges = embedded_zip_ranges(&binary);
        assert_eq!(ranges.len(), 1);
        assert_eq!(&binary[ranges[0].clone()], zip);

        let roots = vec![QuarantinedSample::new("tasksche.exe".into(), None, binary)];
        let expanded = expand_embedded_archives(roots, Some("infected"));
        assert_eq!(expanded.len(), 2);

        // Decrypted member surfaces as its own sample.
        let member = expanded
            .iter()
            .find(|s| s.label.ends_with("embedded-1.zip::c.wnry"))
            .unwrap();
        assert_eq!(member.data, b"gx7ekbenv2riucmf.onion");
        assert!(member.archive.is_some());

        // Parent records the embedded-archive listing too.
        let parent = expanded.iter().find(|s| s.label == "tasksche.exe").unwrap();
        assert_eq!(parent.embedded_archives.len(), 1);
        let emb = &parent.embedded_archives[0];
        assert_eq!(emb.member_count(), 1);
        assert_eq!(emb.extracted, 1);
        assert_eq!(emb.members[0].name, "c.wnry");
    }

    /// The WannaCry shape: an embedded ZIP we *cannot* decrypt (wrong/unknown
    /// password) must still be reported via its cleartext central-directory
    /// listing, with `extracted == 0`.
    #[test]
    fn reports_undecryptable_embedded_archive_listing() {
        let zip = encrypted_zip(
            &[
                ("c.wnry", b"config"),
                ("taskse.exe", b"MZ payload"),
                ("msg/m_english.wnry", b"ransom note"),
            ],
            "WNcry@2ol7",
        );
        let mut binary = b"MZ\x90\x00pe-header".to_vec();
        binary.extend_from_slice(&zip);

        // Analyst only has the outer pack password, not the inner one.
        let roots = vec![QuarantinedSample::new("ed01ebfb.exe".into(), None, binary)];
        let expanded = expand_embedded_archives(roots, Some("infected"));

        // No member could be promoted to a sample, so only the parent remains.
        assert_eq!(expanded.len(), 1);
        let emb = &expanded[0].embedded_archives[0];
        assert_eq!(emb.member_count(), 3);
        assert_eq!(emb.encrypted_count(), 3);
        assert_eq!(emb.extracted, 0);
        assert!(emb.members.iter().any(|m| m.name == "taskse.exe"));
        assert!(emb.members.iter().any(|m| m.name == "msg/m_english.wnry"));
    }

    /// Candidate-password recovery: the inner ZIP password is hidden in the
    /// parent's plaintext strings (the WannaCry `WNcry@2ol7` pattern). We must
    /// harvest it, decrypt the payload, and promote members to samples.
    #[test]
    fn recovers_password_from_parent_strings() {
        let password = "s3cr3tP@ss";
        let zip = encrypted_zip(&[("c.wnry", b"gx7ekbenv2riucmf.onion")], password);
        let mut binary = b"MZ\x90\x00pe-header".to_vec();
        // Password stored in cleartext elsewhere in the binary (null-delimited).
        binary.extend_from_slice(b"\x00");
        binary.extend_from_slice(password.as_bytes());
        binary.extend_from_slice(b"\x00");
        binary.extend_from_slice(&zip);

        // Analyst supplies only the *outer* password; inner one is unknown.
        let roots = vec![QuarantinedSample::new("dropper.exe".into(), None, binary)];
        let expanded = expand_embedded_archives(roots, Some("infected"));

        let parent = expanded.iter().find(|s| s.label == "dropper.exe").unwrap();
        let emb = &parent.embedded_archives[0];
        assert_eq!(emb.recovered_password.as_deref(), Some(password));
        assert_eq!(emb.extracted, 1);

        // The decrypted member is now a first-class sample with its payload.
        let member = expanded
            .iter()
            .find(|s| s.label.ends_with("c.wnry"))
            .unwrap();
        assert_eq!(member.data, b"gx7ekbenv2riucmf.onion");
    }

    #[test]
    fn harvest_finds_embedded_literal() {
        let data = b"junk\x00WNcry@2ol7\x00more\x01stuff";
        let cands = harvest_password_candidates(data);
        assert!(cands.iter().any(|c| c == "WNcry@2ol7"));
    }

    #[test]
    fn ignores_incomplete_zip_signature() {
        let data = b"MZ...PK\x03\x04not-a-complete-archive";
        assert!(embedded_zip_ranges(data).is_empty());
    }

    #[test]
    fn dense_pk_noise_carve_stays_bounded() {
        // Quadratic-carve bomb: packed local headers, no EOCD. Must finish
        // quickly under the probe/look-ahead/failure caps.
        let n = 256 * 1024;
        let mut data = vec![0u8; n];
        for i in (0..n.saturating_sub(4)).step_by(4) {
            data[i..i + 4].copy_from_slice(b"PK\x03\x04");
        }
        let started = std::time::Instant::now();
        let ranges = embedded_zip_ranges(&data);
        let elapsed = started.elapsed();
        assert!(ranges.is_empty());
        assert!(
            elapsed < std::time::Duration::from_millis(250),
            "dense PK carve took {elapsed:?}; probe/search caps likely regressing"
        );
    }

    #[test]
    fn still_carves_valid_embedded_zip_amid_noise() {
        let zip = test_zip("c.wnry", b"gx7ekbenv2riucmf.onion");
        let mut data = Vec::new();
        // Leading false PK signatures that fail header validation.
        for _ in 0..32 {
            data.extend_from_slice(b"PK\x03\x04XXXX");
        }
        data.extend_from_slice(&zip);
        let ranges = embedded_zip_ranges(&data);
        assert_eq!(ranges.len(), 1);
        assert_eq!(&data[ranges[0].clone()], zip.as_slice());
    }

    #[test]
    fn sanitize_strips_control_chars_from_member_names() {
        assert_eq!(sanitize_member_name("evil\x1b[31m.exe"), "evil[31m.exe");
        assert_eq!(sanitize_member_name("a\nb.exe"), "ab.exe");
        assert_eq!(sanitize_member_name("\x01\x02"), "unnamed");
    }

    #[test]
    fn zip_magic_rejects_bare_pk_prefix() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("vanguard-zip-magic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let junk = dir.join("junk.bin");
        {
            let mut f = File::create(&junk).unwrap();
            f.write_all(b"PKXY").unwrap();
        }
        assert!(!looks_like_zip_magic(&junk).unwrap());
        let empty = dir.join("empty.zip");
        {
            let mut f = File::create(&empty).unwrap();
            f.write_all(b"PK\x05\x06").unwrap();
            f.write_all(&[0u8; 18]).unwrap();
        }
        assert!(looks_like_zip_magic(&empty).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn password_rank_prefers_mixed_tokens() {
        let ranked = password_candidate_rank("WNcry@2ol7");
        let weak = password_candidate_rank("aaaaaaaa");
        assert!(ranked < weak);
    }

    #[test]
    fn bounded_read_rejects_oversize_stream() {
        // Simulated member: claims 4 bytes but keeps yielding data.
        let evil = std::io::repeat(b'A');
        let err = read_zip_member_bounded(evil, 4, 4).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("expanded past bound") || msg.contains("past bound"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn bounded_read_accepts_exact_stream() {
        let data = b"abcd";
        let got = read_zip_member_bounded(Cursor::new(data.as_slice()), 4, 4).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn bounded_read_rejects_nonzero_when_declared_zero() {
        let err = read_zip_member_bounded(Cursor::new(b"x"), 0, 0).unwrap_err();
        assert!(format!("{err:#}").contains("declared size 0"));
    }

    #[test]
    fn unsafe_zip_paths_are_rejected() {
        assert!(is_unsafe_zip_path(""));
        assert!(is_unsafe_zip_path("/etc/passwd"));
        assert!(is_unsafe_zip_path("../evil.exe"));
        assert!(is_unsafe_zip_path("foo/../../evil.exe"));
        assert!(is_unsafe_zip_path("foo\\..\\evil.exe"));
        assert!(is_unsafe_zip_path("C:\\Windows\\evil.exe"));
        assert!(is_unsafe_zip_path("\\\\server\\share\\evil.exe"));
        assert!(is_unsafe_zip_path("evil\0.exe"));
        // Legitimate nested members must still be allowed.
        assert!(!is_unsafe_zip_path("msg/m_english.wnry"));
        assert!(!is_unsafe_zip_path("taskse.exe"));
        // ".." inside a filename is not traversal.
        assert!(!is_unsafe_zip_path("foo..bar.exe"));
    }

    #[test]
    fn extract_skips_traversal_member_names() {
        let zip = test_zip("../evil.exe", b"MZ");
        let samples = extract_zip_members(Cursor::new(zip), "t.zip", None);
        // Sole member rejected → empty archive error.
        assert!(samples.is_err());
    }

    #[test]
    fn map_file_rejects_oversize_sample() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = std::env::temp_dir().join(format!("vanguard-oversized-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("huge.bin");
        {
            let mut f = File::create(&path).unwrap();
            // Sparse-ish grow: seek past the limit and write one byte.
            f.seek(SeekFrom::Start(crate::util::MAX_SAMPLE_BYTES)).unwrap();
            f.write_all(&[1]).unwrap();
        }
        let err = map_file(&path).unwrap_err();
        assert!(format!("{err:#}").contains("exceeds max sample size"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
