//! Heuristic credential / secret candidate detection.
//!
//! Complements the precise candidate-password *recovery* in `containment`
//! (which proves a password by decrypting a lock). Here there is no lock to
//! test against, so we can only rank strings by how password/key-*shaped* they
//! are. This is a lead generator, not proof: hardcoded passwords, API keys, and
//! connection-string credentials tend to mix character classes, avoid
//! whitespace, and sit in a mid-entropy band between dictionary words and
//! random binary. Purely static; nothing is contacted.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// Mixed-class password-shaped literal (e.g. `WNcry@2ol7`).
    Password,
    /// High-entropy token near a key/secret keyword.
    ApiKey,
}

impl SecretKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Password => "PASS?",
            Self::ApiKey => "KEY?",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretCandidate {
    pub value: String,
    pub kind: SecretKind,
    /// 0–100 password/secret likelihood.
    pub score: u8,
}

/// Scan raw bytes for password/credential-shaped strings, ranked by likelihood.
pub fn scan(data: &[u8]) -> Vec<SecretCandidate> {
    let mut found: BTreeMap<String, SecretCandidate> = BTreeMap::new();
    for (offset, tok) in harvest_tokens(data) {
        // A real hardcoded password lives in a string table / data section
        // surrounded by other readable text. Password-shaped tokens that are
        // isolated islands inside a high-entropy (packed / compressed /
        // encrypted) region are almost always noise, so require the local
        // neighborhood to be "stringy".
        if !in_string_region(data, offset, offset + tok.len()) {
            continue;
        }
        if let Some(cand) = classify(&tok) {
            if cand.kind == SecretKind::Password
                && !password_keyword_nearby(data, offset, offset + tok.len())
            {
                continue;
            }
            found
                .entry(cand.value.clone())
                .and_modify(|e| e.score = e.score.max(cand.score))
                .or_insert(cand);
        }
    }
    let mut out: Vec<SecretCandidate> = found.into_values().collect();
    out.sort_by(|a, b| b.score.cmp(&a.score).then(a.value.cmp(&b.value)));
    out.truncate(8);
    out
}

/// True if the bytes surrounding `[start,end)` are predominantly printable —
/// i.e. the token sits in a text/string region, not a packed island.
fn in_string_region(data: &[u8], start: usize, end: usize) -> bool {
    const PAD: usize = 48;
    let from = start.saturating_sub(PAD);
    let to = (end + PAD).min(data.len());
    // Count printable/whitespace bytes in the surrounding context only
    // (excluding the token itself, which is printable by construction).
    let mut printable = 0usize;
    let mut total = 0usize;
    for (i, &b) in data[from..to].iter().enumerate() {
        let abs = from + i;
        if abs >= start && abs < end {
            continue;
        }
        total += 1;
        if (0x20..=0x7e).contains(&b) || b == 0 {
            // NUL counts as a benign string terminator, not entropy.
            if b != 0 {
                printable += 1;
            }
        }
    }
    if total == 0 {
        return false;
    }
    printable * 100 / total >= 60
}

/// True when a credential-ish keyword sits near the token (config / UI strings).
fn password_keyword_nearby(data: &[u8], start: usize, end: usize) -> bool {
    const PAD: usize = 96;
    let from = start.saturating_sub(PAD);
    let to = (end + PAD).min(data.len());
    let window = data[from..to].to_ascii_lowercase();
    const KEYS: &[&[u8]] = &[
        b"password",
        b"passwd",
        b"pass:",
        b"pwd",
        b"secret",
        b"credential",
        b"login",
        b"auth",
    ];
    KEYS.iter().any(|k| window.windows(k.len()).any(|w| w == *k))
}

/// Longest run of consecutive ASCII letters — a proxy for a word-like stem.
/// Deliberate passwords usually contain a pronounceable core (`WNcry`), while
/// packed-section noise is symbol/case salad with no real letter run.
fn longest_alpha_run(s: &str) -> usize {
    let mut best = 0;
    let mut cur = 0;
    for b in s.bytes() {
        if b.is_ascii_alphabetic() {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

/// Maximal printable-ASCII runs (no whitespace) of plausible secret length,
/// paired with their byte offset in `data`.
fn harvest_tokens(data: &[u8]) -> Vec<(usize, String)> {
    const MIN: usize = 6;
    const MAX: usize = 64;
    const CAP: usize = 60_000;
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x21..=0x7e).contains(&b);
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if (MIN..=MAX).contains(&(i - s)) {
                if let Ok(t) = std::str::from_utf8(&data[s..i]) {
                    out.push((s, t.to_string()));
                    if out.len() >= CAP {
                        return out;
                    }
                }
            }
        }
    }
    if let Some(s) = start {
        if (MIN..=MAX).contains(&(data.len() - s)) {
            if let Ok(t) = std::str::from_utf8(&data[s..]) {
                out.push((s, t.to_string()));
            }
        }
    }
    out
}

/// Shannon entropy (bits/char) over a string's bytes.
fn shannon_bits(s: &str) -> f32 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            p * p.log2()
        })
        .sum::<f32>()
}

/// Obvious non-secrets we should never flag.
fn is_benign(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();

    // Paths, URLs, and file/module names.
    if s.contains('/') || s.contains('\\') || lower.starts_with("http") {
        return true;
    }
    for ext in [".dll", ".exe", ".sys", ".xml", ".txt", ".dat", ".wnry", ".ini"] {
        if lower.ends_with(ext) {
            return true;
        }
    }

    // GUID: 8-4-4-4-12 hex with dashes.
    let dash_groups: Vec<&str> = s.split('-').collect();
    if dash_groups.len() == 5
        && dash_groups.iter().all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return true;
    }

    // Pure hex (hash / digest) of even length ≥ 16.
    if s.len() >= 16 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }

    // Dotted version / numeric quad (1.2.3, 6.0.0.0).
    if s.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
        return true;
    }

    false
}

/// Symbols that realistically appear in passwords. Anything outside this set
/// (quotes, backticks, tildes, angle brackets, control-ish punctuation) marks
/// the token as packed/binary noise rather than a credential.
const PASSWORD_SYMBOLS: &[u8] = b"!@#$%^&*()-_=+.";

fn classify(s: &str) -> Option<SecretCandidate> {
    let len = s.len();
    if !(6..=48).contains(&len) || is_benign(s) {
        return None;
    }
    let bytes = s.as_bytes();

    // Shape gates that separate deliberate credentials from the endless
    // "complex-looking" runs high-entropy/packed sections produce:
    //   • must start with a letter and end alphanumeric,
    //   • only common password symbols, never two in a row,
    //   • ≥70% of characters alphanumeric.
    if !bytes[0].is_ascii_alphabetic() || !bytes[len - 1].is_ascii_alphanumeric() {
        return None;
    }
    let mut symbol = 0usize;
    let mut prev_symbol = false;
    for &b in bytes {
        if b.is_ascii_alphanumeric() {
            prev_symbol = false;
            continue;
        }
        if !PASSWORD_SYMBOLS.contains(&b) || prev_symbol {
            return None;
        }
        prev_symbol = true;
        symbol += 1;
    }

    let lower = bytes.iter().filter(|b| b.is_ascii_lowercase()).count();
    let upper = bytes.iter().filter(|b| b.is_ascii_uppercase()).count();
    let digit = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    let alnum = lower + upper + digit;
    if alnum * 100 / len < 70 {
        return None;
    }
    // A real password/key mixes letters with digits (and often a symbol).
    if digit == 0 || (lower + upper) == 0 {
        return None;
    }
    let classes = [lower > 0, upper > 0, digit > 0, symbol > 0]
        .iter()
        .filter(|&&x| x)
        .count();
    if classes < 3 {
        return None;
    }

    let ent = shannon_bits(s);
    if !(2.3..=6.5).contains(&ent) {
        return None;
    }

    // Symbol-less tokens are too ambiguous on packed binaries; keep only long
    // high-entropy ones (API-key shaped). Symbol-bearing tokens are the classic
    // password shape (`WNcry@2ol7`) and are kept.
    let kind = if symbol == 0 {
        if len >= 20 && ent >= 4.3 {
            SecretKind::ApiKey
        } else {
            return None;
        }
    } else {
        SecretKind::Password
    };

    // A word-like letter stem is the strongest cheap signal that a token is a
    // chosen password rather than random symbol/case salad.
    let stem = longest_alpha_run(s);
    if kind == SecretKind::Password && stem < 4 {
        return None;
    }

    let mut score: i32 = 30 + (classes as i32) * 8;
    score += (stem.min(8) as i32) * 4;
    if (8..=24).contains(&len) {
        score += 8;
    }
    // Penalize symbol-dense tokens (`Or@YX0%0`); reward a single tasteful one.
    let sym_ratio = symbol * 100 / len;
    if sym_ratio > 25 {
        score -= 30;
    } else if symbol > 0 {
        score += 6;
    }

    let score = score.clamp(0, 100) as u8;
    if score < 72 {
        return None;
    }
    Some(SecretCandidate {
        value: s.to_string(),
        kind,
        score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(cands: &[SecretCandidate], v: &str) -> bool {
        cands.iter().any(|c| c.value == v)
    }

    #[test]
    fn flags_wannacry_password() {
        let data = b"password\x00WNcry@2ol7\x00KERNEL32.DLL";
        let cands = scan(data);
        assert!(has(&cands, "WNcry@2ol7"), "should flag the WannaCry password");
    }

    #[test]
    fn flags_mixed_complexity_password() {
        let data = b"login\x00Adm1n!Pass2024\x00end";
        let cands = scan(data);
        assert!(has(&cands, "Adm1n!Pass2024"));
    }

    #[test]
    fn ignores_shaped_token_without_keyword() {
        let data = b"xxxx\x00Adm1n!Pass2024\x00yyyy";
        let cands = scan(data);
        assert!(
            !has(&cands, "Adm1n!Pass2024"),
            "password-shaped token without nearby keyword must drop: {cands:?}"
        );
    }

    #[test]
    fn ignores_dictionary_and_identifiers() {
        // Plain words, snake_case identifiers, and versions must not flag.
        let data = b"GetProcAddress\x00current_version\x00encryption\x006.0.0.0\x00";
        let cands = scan(data);
        assert!(cands.is_empty(), "unexpected: {cands:?}");
    }

    #[test]
    fn ignores_hex_hashes_and_guids() {
        let data =
            b"d41d8cd98f00b204e9800998ecf8427e\x00550e8400-e29b-41d4-a716-446655440000\x00";
        let cands = scan(data);
        assert!(cands.is_empty(), "unexpected: {cands:?}");
    }
}
