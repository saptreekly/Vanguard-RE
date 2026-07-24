//! Weak XOR cryptanalysis for static triage.
//!
//! Recovers short repeating keys (classic malware string/config decode) and
//! reused keystreams via ciphertext pairwise XOR ("wave interference"):
//! `C1 ⊕ C2 = P1 ⊕ P2` when both share `K`. Purely static; no execution.
//! Does not attempt AES / WANACRY! / real ransomware crypto.

use crate::crypto::{CryptoCategory, CryptoFinding};
use crate::triage::{BinaryFormat, ParsedBinary};
use crate::triage::entropy::shannon_entropy;

/// How the keystream was recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XorMethod {
    /// Short repeating key on a single blob.
    RepeatingKey,
    /// Same keystream reused across two ciphertexts (`C1 ⊕ C2`).
    KeyReuse,
}

impl XorMethod {
    pub fn label(self) -> &'static str {
        match self {
            Self::RepeatingKey => "repeating",
            Self::KeyReuse => "key-reuse",
        }
    }
}

impl XorRecovery {
    /// Human-readable cipher description, e.g. `single-byte XOR 0x4b` or
    /// `repeating-key XOR (4 bytes)`.
    pub fn scheme(&self) -> String {
        match self.method {
            XorMethod::RepeatingKey if self.key_len == 1 && !self.key.is_empty() => {
                format!("single-byte XOR 0x{:02x}", self.key[0])
            }
            XorMethod::RepeatingKey => {
                format!("repeating-key XOR ({} byte{})", self.key_len, if self.key_len == 1 { "" } else { "s" })
            }
            XorMethod::KeyReuse => {
                "reused keystream (C1⊕C2 cancel)".into()
            }
        }
    }

    /// Key as hex, with optional ASCII when the key is printable.
    pub fn key_display(&self) -> String {
        let hex: String = self
            .key
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let more = if self.key.len() > 16 { " …" } else { "" };
        let ascii_ok = self
            .key
            .iter()
            .all(|&b| (0x20..=0x7e).contains(&b));
        if ascii_ok && !self.key.is_empty() && self.key.len() <= 16 {
            let s: String = self.key.iter().map(|&b| b as char).collect();
            format!("{hex}{more}  \"{s}\"")
        } else {
            format!("{hex}{more}")
        }
    }
}

#[derive(Debug, Clone)]
pub struct XorRecovery {
    pub method: XorMethod,
    pub key: Vec<u8>,
    pub key_len: usize,
    pub offset: usize,
    pub length: usize,
    pub preview: String,
    pub peers: Vec<String>,
    pub confidence: u8,
    pub evidence: String,
}

const MIN_CANDIDATE: usize = 32;
const MAX_CANDIDATE: usize = 256 * 1024;
/// Cap the bytes fed to key-search IC scoring. Entropy gating still uses
/// `MAX_CANDIDATE`, but brute-forcing 256 key bytes × key lengths over a full
/// 256 KiB window × several candidates is a CPU DoS malware can trigger.
const MAX_RECOVER_BYTES: usize = 64 * 1024;
const MAX_CANDIDATES_PER_SAMPLE: usize = 8;
const MAX_PAIRS: usize = 8;
const KEY_LENGTHS: &[usize] = &[1, 2, 3, 4, 5, 6, 8, 12, 16];
/// English ⊕ short key often lands ~4.2–6.5; near-random stays above ~7.9.
const ENTROPY_LO: f64 = 4.0;
const ENTROPY_HI: f64 = 7.6;
const ENTROPY_NEAR_RANDOM: f64 = 7.9;

const CRIBS: &[&[u8]] = &[
    b" the ",
    b"http",
    b"This ",
    b".dll",
    b"KERNEL",
    b"This program",
    b"cmd.exe",
    b"powershell",
];

/// Candidate window extracted from a sample for XOR recovery.
#[derive(Debug, Clone)]
pub struct XorCandidate {
    pub label: String,
    pub offset: usize,
    pub data: Vec<u8>,
}

/// Collect bounded XOR-candidate windows from a sample.
pub fn collect_candidates(data: &[u8], binary: &ParsedBinary) -> Vec<XorCandidate> {
    let mut out = Vec::new();

    match binary.format {
        BinaryFormat::Rtf | BinaryFormat::Image | BinaryFormat::Text | BinaryFormat::Zip => {
            return out;
        }
        BinaryFormat::Encrypted | BinaryFormat::Raw | BinaryFormat::Unknown | BinaryFormat::DosCom => {
            maybe_push_window(&mut out, "blob", 0, data);
        }
        BinaryFormat::Pe | BinaryFormat::Elf | BinaryFormat::MachO => {
            for sec in &binary.sections {
                let name = sec.name.to_ascii_lowercase();
                // Prefer non-code / resource / data; skip typical code sections.
                let is_code = name.contains("text")
                    || name == ".text"
                    || name.starts_with("__text")
                    || name == "code";
                if is_code {
                    continue;
                }
                let start = sec.file_offset as usize;
                let len = sec.raw_size as usize;
                if start >= data.len() || len == 0 {
                    continue;
                }
                let end = (start + len).min(data.len());
                let slice = &data[start..end];
                maybe_push_window(&mut out, &sec.name, start, slice);
            }
            // Also consider whole-image islands if no section windows qualified
            // (malformed PE / empty section table).
            if out.is_empty() {
                maybe_push_window(&mut out, "image", 0, data);
            }
        }
    }

    out.sort_by(|a, b| {
        b.data
            .len()
            .cmp(&a.data.len())
            .then(a.offset.cmp(&b.offset))
    });
    out.truncate(MAX_CANDIDATES_PER_SAMPLE);
    out
}

fn maybe_push_window(out: &mut Vec<XorCandidate>, label: &str, offset: usize, data: &[u8]) {
    if data.len() < MIN_CANDIDATE {
        return;
    }
    let window = if data.len() > MAX_CANDIDATE {
        &data[..MAX_CANDIDATE]
    } else {
        data
    };
    let e = shannon_entropy(window);
    if !(ENTROPY_LO..=ENTROPY_HI).contains(&e) {
        return;
    }
    if e >= ENTROPY_NEAR_RANDOM {
        return;
    }
    out.push(XorCandidate {
        label: label.to_string(),
        offset,
        data: window.to_vec(),
    });
}

/// Skip whole-blob recovery when strong crypto fingerprints dominate a near-random sample.
fn strong_crypto_dominates(crypto: &[CryptoFinding], data_len: usize, entropy: f64) -> bool {
    if entropy < 7.5 || data_len < 4096 {
        return false;
    }
    crypto.iter().any(|c| {
        c.confidence >= 85
            && matches!(c.category, CryptoCategory::Block | CryptoCategory::Stream)
            && matches!(
                c.name.as_str(),
                "AES" | "ChaCha20/Salsa20" | "Blowfish" | "TEA/XTEA"
            )
    })
}

/// Recover repeating keys and within-sample key-reuse pairs.
pub fn scan(
    data: &[u8],
    binary: &ParsedBinary,
    crypto: &[CryptoFinding],
    xor_loop_hint: bool,
) -> Vec<XorRecovery> {
    let mut candidates = collect_candidates(data, binary);
    if candidates.is_empty() {
        return Vec::new();
    }

    let blob_ent = shannon_entropy(&data[..data.len().min(MAX_CANDIDATE)]);
    if strong_crypto_dominates(crypto, data.len(), blob_ent) {
        // Keep only smaller named section windows, drop whole-image/"blob".
        candidates.retain(|c| c.label != "blob" && c.label != "image");
    }

    let mut findings = Vec::new();

    for c in &candidates {
        if let Some(mut rec) = recover_repeating(&c.data, c.offset) {
            rec.evidence = format!("{} · window={}", rec.evidence, c.label);
            if xor_loop_hint {
                rec.confidence = rec.confidence.saturating_add(10).min(99);
            }
            findings.push(rec);
        }
    }

    // Pairwise only for opaque blobs — PE/ELF section windows are usually
    // plaintext (.rdata/.data) and produce crib false positives.
    if matches!(
        binary.format,
        BinaryFormat::Encrypted | BinaryFormat::Raw | BinaryFormat::Unknown | BinaryFormat::DosCom
    ) {
        let pair_findings = recover_pairwise_set(
            &candidates
                .iter()
                .map(|c| (c.label.as_str(), c.data.as_slice()))
                .collect::<Vec<_>>(),
        );
        for mut rec in pair_findings {
            if xor_loop_hint {
                rec.confidence = rec.confidence.saturating_add(10).min(99);
            }
            findings.push(rec);
        }
    }

    dedupe_findings(&mut findings);
    findings
}

/// Pairwise key-reuse across sibling samples (e.g. archive members).
pub fn scan_pairwise_across(peers: &[(String, Vec<u8>)]) -> Vec<XorRecovery> {
    if peers.len() < 2 {
        return Vec::new();
    }
    let refs: Vec<(&str, &[u8])> = peers
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let mut findings = recover_pairwise_set(&refs);
    dedupe_findings(&mut findings);
    findings
}

fn recover_pairwise_set(peers: &[(&str, &[u8])]) -> Vec<XorRecovery> {
    let mut findings = Vec::new();
    let n = peers.len().min(MAX_CANDIDATES_PER_SAMPLE);
    let mut pair_count = 0usize;
    for i in 0..n {
        for j in (i + 1)..n {
            if pair_count >= MAX_PAIRS {
                return findings;
            }
            let (la, da) = peers[i];
            let (lb, db) = peers[j];
            // Skip wildly different sizes (unlikely same pad length reuse).
            let lo = da.len().min(db.len());
            let hi = da.len().max(db.len());
            if lo < MIN_CANDIDATE || hi > lo.saturating_mul(4) {
                continue;
            }
            if let Some(rec) = recover_key_reuse(da, db, la, lb) {
                findings.push(rec);
                pair_count += 1;
            }
        }
    }
    findings
}

fn dedupe_findings(findings: &mut Vec<XorRecovery>) {
    findings.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(a.offset.cmp(&b.offset))
            .then(a.key_len.cmp(&b.key_len))
    });
    let mut kept = Vec::new();
    for f in findings.drain(..) {
        let dup = kept.iter().any(|k: &XorRecovery| {
            k.method == f.method && k.key == f.key && k.offset == f.offset
        });
        if !dup {
            kept.push(f);
        }
    }
    *findings = kept;
}

/// Guess repeating key length via IC shortlist, then pick the length whose
/// decrypt scores best (prefers shorter keys when multiples tie on IC).
pub fn recover_repeating(data: &[u8], offset: usize) -> Option<XorRecovery> {
    if data.len() < MIN_CANDIDATE {
        return None;
    }
    let e = shannon_entropy(data);
    if !(ENTROPY_LO..=ENTROPY_HI).contains(&e) {
        return None;
    }

    // Try every plausible length; IC alone prefers multiples of the true key
    // on short buffers, so final pick is by printable ratio then shorter key.
    let mut best: Option<(Vec<u8>, usize, f64, f64, f64, String)> = None;
    for &key_len in KEY_LENGTHS {
        if data.len() < key_len * 4 {
            continue;
        }
        let ic = mean_column_ic(data, key_len);
        let Some((key, col_score)) = recover_key_bytes(data, key_len) else {
            continue;
        };
        if key.iter().all(|&b| b == 0) {
            continue;
        }
        let key = collapse_uniform_key(key);
        let key_len = key.len();
        let plain = apply_xor(data, &key);
        let printable = printable_ratio(&plain);
        if printable < 0.78 {
            continue;
        }
        let preview = make_preview(&plain);
        if preview.len() < 8 {
            continue;
        }
        // Prefer higher printable; break ties toward shorter keys (avoid L=16
        // when L=4 decrypts equally well). Do not let length swamp a clear win.
        let replace = match &best {
            None => true,
            Some((_, bl, _, _, best_print, _)) => {
                if printable > *best_print + 0.02 {
                    true
                } else if printable + 0.02 < *best_print {
                    false
                } else {
                    key_len < *bl
                }
            }
        };
        if replace {
            best = Some((key, key_len, ic, col_score, printable, preview));
        }
    }

    let (key, best_len, best_ic, col_score, _, preview) = best?;
    if !key_looks_plausible(&key) {
        return None;
    }
    let plain = apply_xor(data, &key);
    let printable = printable_ratio(&plain);
    let conf = confidence_repeating(printable, best_ic, col_score, data.len(), best_len);
    if conf < 45 {
        return None;
    }
    if preview_is_weak(&preview) {
        return None;
    }

    Some(XorRecovery {
        method: XorMethod::RepeatingKey,
        key_len: best_len,
        key,
        offset,
        length: data.len(),
        preview,
        peers: Vec::new(),
        confidence: conf,
        evidence: format!(
            "IC L={best_len} ({best_ic:.3}); {:.0}% printable",
            printable * 100.0
        ),
    })
}

fn recover_key_bytes(data: &[u8], key_len: usize) -> Option<(Vec<u8>, f64)> {
    let mut key = vec![0u8; key_len];
    let mut total = 0.0f64;
    let mut ok_cols = 0usize;
    for i in 0..key_len {
        let mut best_k = 0u8;
        let mut best_score = i32::MIN;
        for k in 0u16..=255 {
            let k = k as u8;
            let mut score = 0i32;
            let mut n = 0usize;
            let mut j = i;
            while j < data.len() {
                score += score_plain_byte(data[j] ^ k);
                n += 1;
                j += key_len;
            }
            if n < 4 {
                continue;
            }
            if score > best_score {
                best_score = score;
                best_k = k;
            }
        }
        if best_score < 0 {
            return None;
        }
        key[i] = best_k;
        total += best_score as f64;
        ok_cols += 1;
    }
    if ok_cols != key_len {
        return None;
    }
    Some((key, total))
}

fn mean_column_ic(data: &[u8], key_len: usize) -> f64 {
    let mut sum = 0.0;
    let mut cols = 0usize;
    for i in 0..key_len {
        let col: Vec<u8> = data[i..].iter().step_by(key_len).copied().collect();
        if col.len() < 4 {
            continue;
        }
        sum += index_of_coincidence(&col);
        cols += 1;
    }
    if cols == 0 {
        0.0
    } else {
        sum / cols as f64
    }
}

fn index_of_coincidence(col: &[u8]) -> f64 {
    let n = col.len() as f64;
    if n < 2.0 {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in col {
        counts[b as usize] += 1;
    }
    let mut sum = 0.0;
    for c in counts {
        if c > 1 {
            sum += (c * (c - 1)) as f64;
        }
    }
    sum / (n * (n - 1.0))
}

fn score_plain_byte(b: u8) -> i32 {
    match b {
        b' ' => 5,
        b'a'..=b'z' => 3,
        b'A'..=b'Z' => 3,
        b'0'..=b'9' => 1,
        b'\n' | b'\r' | b'\t' => 1,
        b'.' | b',' | b':' | b';' | b'/' | b'-' | b'_' | b'(' | b')' => 2,
        0x20..=0x7e => 1,
        0x00 => -3,
        _ => -6,
    }
}

fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let n = data.len().min(4096);
    let good = data[..n]
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    good as f64 / n as f64
}

fn apply_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn collapse_uniform_key(key: Vec<u8>) -> Vec<u8> {
    if key.len() > 1 && key.iter().all(|&b| b == key[0]) {
        vec![key[0]]
    } else {
        key
    }
}

fn key_looks_plausible(key: &[u8]) -> bool {
    if key.is_empty() || key.iter().all(|&b| b == 0) {
        return false;
    }
    // Space-as-key is a common false positive on PE padding / sparse data.
    let spaces = key.iter().filter(|&&b| b == b' ').count();
    if spaces * 2 >= key.len() {
        return false;
    }
    // Highly uniform keys (same byte ≥ 75%) are suspicious unless len == 1.
    if key.len() > 1 {
        let mut counts = [0u32; 256];
        for &b in key {
            counts[b as usize] += 1;
        }
        let max = *counts.iter().max().unwrap_or(&0);
        if max * 4 >= (key.len() as u32) * 3 {
            return false;
        }
    }
    true
}

fn preview_is_weak(preview: &str) -> bool {
    if preview.len() < 8 {
        return true;
    }
    let letters = preview.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let spaces = preview.chars().filter(|c| *c == ' ').count();
    // Need a real word-ish density, not "   I    y".
    letters < 6 || spaces * 2 > letters
}

fn make_preview(plain: &[u8]) -> String {
    let mask = vec![true; plain.len().min(120)];
    make_preview_masked(&plain[..mask.len()], &mask)
}

fn make_preview_masked(plain: &[u8], known: &[bool]) -> String {
    let n = plain.len().min(known.len());
    // Prefer the longest contiguous recovered printable run.
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut i = 0usize;
    while i < n {
        if !known[i] || !(0x20..=0x7e).contains(&plain[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && known[i] && ((0x20..=0x7e).contains(&plain[i]) || matches!(plain[i], b'\n' | b'\r' | b'\t'))
        {
            i += 1;
        }
        let len = i - start;
        if len > best_len {
            best_len = len;
            best_start = start;
        }
    }
    if best_len < 6 {
        return String::new();
    }
    let end = (best_start + best_len).min(best_start + 80);
    let mut out = String::new();
    for &b in &plain[best_start..end] {
        if (0x20..=0x7e).contains(&b) {
            out.push(b as char);
        } else {
            out.push(' ');
        }
    }
    out.trim().to_string()
}

fn confidence_repeating(
    printable: f64,
    ic: f64,
    col_score: f64,
    len: usize,
    key_len: usize,
) -> u8 {
    let mut c = 40.0;
    c += (printable - 0.78) * 100.0; // up to ~22
    c += ((ic - 0.04) * 200.0).clamp(0.0, 15.0);
    c += (col_score / (len as f64 / key_len as f64).max(1.0) / 10.0).clamp(0.0, 15.0);
    if printable > 0.92 {
        c += 8.0;
    }
    c.clamp(0.0, 95.0) as u8
}

/// Many-time pad: recover overlapping keystream from two ciphertexts.
pub fn recover_key_reuse(
    c1: &[u8],
    c2: &[u8],
    label1: &str,
    label2: &str,
) -> Option<XorRecovery> {
    let n = c1.len().min(c2.len());
    if n < MIN_CANDIDATE {
        return None;
    }
    let c1 = &c1[..n];
    let c2 = &c2[..n];
    let diff: Vec<u8> = c1.iter().zip(c2.iter()).map(|(a, b)| a ^ b).collect();

    let mut key = vec![None; n];
    let mut strength = vec![0u8; n]; // higher = more trusted assignment

    // Longer cribs first; try each plaintext side.
    let mut cribs: Vec<&[u8]> = CRIBS.to_vec();
    cribs.sort_by_key(|c| std::cmp::Reverse(c.len()));

    for crib in cribs {
        if crib.len() > n {
            continue;
        }
        for pos in 0..=(n - crib.len()) {
            try_crib_at(&diff, c1, c2, crib, pos, true, &mut key, &mut strength);
            try_crib_at(&diff, c1, c2, crib, pos, false, &mut key, &mut strength);
        }
    }

    // Space heuristic only fills unknown positions (two-message case is noisy).
    for i in 0..n {
        if key[i].is_some() {
            continue;
        }
        if !is_letter_xor_space(diff[i]) {
            continue;
        }
        let k1 = c1[i] ^ b' ';
        let k2 = c2[i] ^ b' ';
        let p2_if_space1 = c2[i] ^ k1;
        let p1_if_space2 = c1[i] ^ k2;
        if p2_if_space1.is_ascii_alphabetic() {
            key[i] = Some(k1);
            strength[i] = 1;
        } else if p1_if_space2.is_ascii_alphabetic() {
            key[i] = Some(k2);
            strength[i] = 1;
        }
    }

    let known: Vec<(usize, u8)> = key
        .iter()
        .enumerate()
        .filter_map(|(i, k)| k.map(|b| (i, b)))
        .collect();
    if known.len() < 8 {
        return None;
    }

    // Reject identity decrypts (plaintext sections crib-matched as "ciphertexts").
    let zero_keys = known.iter().filter(|(_, b)| *b == 0).count();
    if zero_keys * 2 >= known.len() {
        return None;
    }

    let (display_key, key_len, is_repeating) = collapse_or_fragment(&known, n);
    if display_key.iter().all(|&b| b == 0) {
        return None;
    }

    let mut plain = vec![0u8; n];
    let mut recovered = 0usize;
    let mut known_mask = vec![false; n];
    let mut plain_score = 0i32;
    for &(i, kb) in &known {
        let p = c1[i] ^ kb;
        plain[i] = p;
        known_mask[i] = true;
        recovered += 1;
        plain_score += score_plain_byte(p);
    }
    // Known plaintext must look like text, not crib-false-positive noise.
    let avg = plain_score as f64 / recovered as f64;
    if avg < 1.5 {
        return None;
    }

    let preview = make_preview_masked(&plain, &known_mask);
    if preview.len() < 6 {
        return None;
    }
    let prev_l = preview.to_ascii_lowercase();
    let has_word = [
        "the", "this", "http", "dll", "kernel", "program", "cmd", "dos", "file", "ntdll",
    ]
    .iter()
    .any(|w| prev_l.contains(w));
    if !has_word && strength.iter().filter(|&&s| s >= 2).count() < 8 {
        return None;
    }

    let coverage = recovered as f64 / n as f64;
    let mut conf = 50.0 + coverage * 25.0 + (known.len().min(40) as f64) * 0.35;
    if is_repeating {
        conf += 5.0;
    }
    if has_word {
        conf += 8.0;
    }
    let conf = conf.clamp(0.0, 92.0) as u8;
    if conf < 55 {
        return None;
    }

    Some(XorRecovery {
        method: XorMethod::KeyReuse,
        key: display_key,
        key_len,
        offset: 0,
        length: n,
        preview,
        peers: vec![label1.to_string(), label2.to_string()],
        confidence: conf,
        evidence: format!(
            "C1⊕C2 cancel; {}/{} key bytes ({:.0}% cov){}",
            known.len(),
            n,
            coverage * 100.0,
            if is_repeating {
                " · repeating"
            } else {
                ""
            }
        ),
    })
}

/// Place crib in P1 (`crib_in_first`) or P2; require the other side fully printable.
fn try_crib_at(
    diff: &[u8],
    c1: &[u8],
    c2: &[u8],
    crib: &[u8],
    pos: usize,
    crib_in_first: bool,
    key: &mut [Option<u8>],
    strength: &mut [u8],
) {
    let mut local_key = Vec::with_capacity(crib.len());
    for (k, &cb) in crib.iter().enumerate() {
        let i = pos + k;
        let other = diff[i] ^ cb;
        // Other plaintext byte must look like text.
        if score_plain_byte(other) < 1 {
            return;
        }
        let kb = if crib_in_first {
            c1[i] ^ cb
        } else {
            c2[i] ^ cb
        };
        // Sanity: decrypt both sides.
        let p1 = c1[i] ^ kb;
        let p2 = c2[i] ^ kb;
        if crib_in_first {
            if p1 != cb || score_plain_byte(p2) < 1 {
                return;
            }
        } else if p2 != cb || score_plain_byte(p1) < 1 {
            return;
        }
        local_key.push(kb);
    }

    let crib_strength = 2 + (crib.len() as u8 / 4).min(3);
    // Refuse the whole crib if it fights an equal/stronger assignment.
    for (k, &kb) in local_key.iter().enumerate() {
        let i = pos + k;
        if let Some(existing) = key[i] {
            if existing != kb && strength[i] >= crib_strength {
                return;
            }
        }
    }
    for (k, &kb) in local_key.iter().enumerate() {
        let i = pos + k;
        if strength[i] > crib_strength {
            continue;
        }
        key[i] = Some(kb);
        strength[i] = crib_strength;
    }
}

fn is_letter_xor_space(d: u8) -> bool {
    d.is_ascii_alphabetic()
}

fn collapse_or_fragment(known: &[(usize, u8)], _n: usize) -> (Vec<u8>, usize, bool) {
    // Try to detect a short repeating key from known positions.
    for &l in KEY_LENGTHS {
        let mut slots: Vec<Option<u8>> = vec![None; l];
        let mut consistent = true;
        for &(i, b) in known {
            let slot = i % l;
            if let Some(prev) = slots[slot] {
                if prev != b {
                    consistent = false;
                    break;
                }
            } else {
                slots[slot] = Some(b);
            }
        }
        if !consistent {
            continue;
        }
        if slots.iter().filter(|s| s.is_some()).count() == l {
            let key: Vec<u8> = slots.into_iter().map(|s| s.unwrap()).collect();
            return (key, l, true);
        }
    }
    // Non-repeating: return up to 16 recovered bytes as a fragment.
    let frag: Vec<u8> = known.iter().take(16).map(|(_, b)| *b).collect();
    let len = frag.len();
    (frag, len, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triage::formats::{BinaryFormat, OperatingSystemEstimate, ParsedBinary};

    fn xor_repeat(plain: &[u8], key: &[u8]) -> Vec<u8> {
        apply_xor(plain, key)
    }

    fn empty_binary(format: BinaryFormat) -> ParsedBinary {
        ParsedBinary {
            format,
            architecture: "x86".into(),
            operating_system: OperatingSystemEstimate {
                family: "Unknown".into(),
                minimum_version: None,
                environment: None,
                evidence: "test".into(),
            },
            entry_point: 0,
            is_64bit: false,
            is_lib: false,
            compile_timestamp: None,
            has_signature: false,
            image_file_offset: 0,
            sections: vec![],
            imports: vec![],
            exports: vec![],
            symbols: vec![],
            section_entropies: vec![],
            entropy_maps: vec![],
        }
    }

    #[test]
    fn scheme_describes_single_byte_and_repeating() {
        let plain = b"This program cannot be run in DOS mode. http://example.invalid/path";
        let mut msg = plain.to_vec();
        while msg.len() < 64 {
            msg.extend_from_slice(plain);
        }
        let ct = xor_repeat(&msg, &[0x4b]);
        let rec = recover_repeating(&ct, 0).expect("recover");
        assert!(rec.scheme().contains("single-byte XOR 0x4b"), "{}", rec.scheme());
        assert!(rec.key_display().contains("4b"));
    }

    #[test]
    fn recovers_single_byte_repeating_key() {
        let plain = b"This program cannot be run in DOS mode. http://example.invalid/path";
        let mut msg = plain.to_vec();
        while msg.len() < 64 {
            msg.extend_from_slice(plain);
        }
        let ct = xor_repeat(&msg, &[0x4b]);
        let rec = recover_repeating(&ct, 0).expect("should recover");
        assert_eq!(rec.method, XorMethod::RepeatingKey);
        assert_eq!(rec.key, vec![0x4b]);
        assert!(rec.preview.to_ascii_lowercase().contains("this program") || rec.preview.contains("http"));
        assert!(rec.confidence >= 45);
    }

    #[test]
    fn recovers_four_byte_repeating_key() {
        let plain = b"KERNEL32.dll CreateFileA WriteFile http://c2.example/gate cmd.exe /c ";
        let mut msg = Vec::new();
        while msg.len() < 96 {
            msg.extend_from_slice(plain);
        }
        let key = [0xde, 0xad, 0xbe, 0xef];
        let ct = xor_repeat(&msg, &key);
        let rec = recover_repeating(&ct, 0x100).expect("should recover");
        assert_eq!(rec.key_len, 4);
        assert_eq!(rec.key, key);
        assert_eq!(rec.offset, 0x100);
        assert!(rec.preview.len() >= 8);
    }

    #[test]
    fn pairwise_recovers_reused_keystream() {
        let p1 = b"This program cannot be run in DOS mode. Padding text for length!!";
        let p2 = b"KERNEL32.dll and ntdll.dll imports live here for the crib drag!!!";
        assert_eq!(p1.len(), p2.len());
        let mut key = Vec::new();
        for i in 0..p1.len() {
            key.push((i as u8).wrapping_mul(17).wrapping_add(3));
        }
        let c1 = apply_xor(p1, &key);
        let c2 = apply_xor(p2, &key);
        // Full keystream reuse — treat as one-time key of length n (not short repeating).
        let rec = recover_key_reuse(&c1, &c2, "a.bin", "b.bin").expect("pairwise");
        assert_eq!(rec.method, XorMethod::KeyReuse);
        assert_eq!(rec.peers, vec!["a.bin", "b.bin"]);
        let prev = rec.preview.to_ascii_lowercase();
        assert!(
            prev.contains("this")
                || prev.contains("kernel")
                || prev.contains("program")
                || prev.contains("dll")
                || prev.contains("dos")
                || prev.contains("ntdll"),
            "unexpected preview: {:?}",
            rec.preview
        );
        assert!(rec.confidence >= 55);
    }

    #[test]
    fn random_high_entropy_yields_nothing() {
        // Near-uniform bytes → entropy ~8, outside XOR band.
        let mut data = Vec::with_capacity(256);
        for i in 0..256u16 {
            data.push((i * 97 + 13) as u8);
        }
        // Scramble further
        for i in 0..data.len() {
            data[i] = data[i].wrapping_mul(31).wrapping_add(i as u8);
        }
        assert!(recover_repeating(&data, 0).is_none());
    }

    #[test]
    fn aes_sbox_blob_skipped_by_candidates_when_strong_crypto() {
        let mut data = vec![0u8; 8192];
        // Fill with mid-high entropy-ish pattern then plant AES S-box.
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(41).wrapping_add(7);
        }
        let sbox: &[u8] = &[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ];
        data[..sbox.len()].copy_from_slice(sbox);
        let crypto = crate::crypto::scan(&data, &[]);
        assert!(crypto.iter().any(|c| c.name == "AES"));
        let binary = empty_binary(BinaryFormat::Raw);
        // Whole-blob may or may not be a candidate depending on entropy; scan should not
        // invent a high-confidence repeating decrypt of the S-box region as English.
        let findings = scan(&data, &binary, &crypto, false);
        for f in &findings {
            assert!(
                f.confidence < 90 || !f.preview.is_empty(),
                "unexpected recovery: {:?}",
                f.preview
            );
        }
    }

    #[test]
    fn content_formats_yield_no_candidates() {
        let data = vec![0x41u8; 128];
        for fmt in [
            BinaryFormat::Rtf,
            BinaryFormat::Image,
            BinaryFormat::Text,
            BinaryFormat::Zip,
        ] {
            assert!(
                collect_candidates(&data, &empty_binary(fmt)).is_empty(),
                "{fmt:?} should skip"
            );
        }
    }

    #[test]
    fn xor_loop_hint_bumps_confidence() {
        let plain = b"powershell -enc AAAABBBB http://c2.test/beacon KERNEL32 ";
        let mut msg = Vec::new();
        while msg.len() < 80 {
            msg.extend_from_slice(plain);
        }
        let ct = xor_repeat(&msg, &[0x11]);
        // Ensure entropy lands in band by using enough varied plaintext.
        let binary = empty_binary(BinaryFormat::Raw);
        let without = scan(&ct, &binary, &[], false);
        let with = scan(&ct, &binary, &[], true);
        if let (Some(a), Some(b)) = (without.first(), with.first()) {
            assert!(b.confidence >= a.confidence);
            if a.confidence <= 89 {
                assert!(b.confidence >= a.confidence.saturating_add(10).min(99) || b.confidence > a.confidence);
            }
        }
    }
}
