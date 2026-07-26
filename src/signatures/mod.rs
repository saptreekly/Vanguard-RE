//! Signature engine: ImpHash, file hashes, lightweight builtin pattern rules.

mod ordlookup;
mod yara_rules;

use md5::{Digest, Md5};
use sha2::Sha256;

use crate::triage::ImportEntry;

pub use yara_rules::{scan_builtin_rules, scan_yara_file};

#[derive(Debug, Clone)]
pub struct HashBundle {
    pub md5: String,
    pub sha256: String,
    /// PE ImpHash (MD5 of canonicalized import string).
    pub imphash: Option<String>,
    pub ssdeep: Option<String>,
    pub tlsh: Option<String>,
}

pub fn hash_file(data: &[u8]) -> (String, String) {
    let mut md5 = Md5::new();
    md5.update(data);
    let md5_hex = hex::encode(md5.finalize());

    let mut sha = Sha256::new();
    sha.update(data);
    let sha_hex = hex::encode(sha.finalize());

    (md5_hex, sha_hex)
}

/// Mandiant ImpHash: lowercase `dll.function` entries in **IAT order** (no
/// alphabetical sort — reordering imports changes the hash and is the point).
///
/// Ordinals for `oleaut32` / `ws2_32` / `wsock32` are resolved via the frozen
/// pefile/YARA tables so values match VirusTotal.
pub fn compute_imphash(imports: &[ImportEntry]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }

    let mut parts = Vec::with_capacity(imports.len());
    for imp in imports {
        if imp.function == "*" {
            continue;
        }
        let dll = normalize_dll(&imp.library);
        let func = normalize_func(&dll, &imp.function);
        if dll.is_empty() || func.is_empty() {
            continue;
        }
        parts.push(format!("{dll}.{func}"));
    }
    if parts.is_empty() {
        return None;
    }

    let joined = parts.join(",");
    let mut hasher = Md5::new();
    hasher.update(joined.as_bytes());
    Some(hex::encode(hasher.finalize()))
}

fn normalize_dll(dll: &str) -> String {
    let lower = dll.to_ascii_lowercase();
    lower
        .strip_suffix(".dll")
        .or_else(|| lower.strip_suffix(".sys"))
        .or_else(|| lower.strip_suffix(".ocx"))
        .unwrap_or(&lower)
        .to_string()
}

fn normalize_func(dll_stem: &str, func: &str) -> String {
    if let Some(ord) = ordlookup::parse_ordinal_label(func) {
        // Lookup keys include the extension, matching pefile's imphash_ords.
        let dll_key = format!("{dll_stem}.dll");
        return ordlookup::resolve_imphash_ordinal(&dll_key, ord);
    }
    func.trim().to_ascii_lowercase()
}

pub fn build_hash_bundle(data: &[u8], imports: &[ImportEntry]) -> HashBundle {
    let (md5, sha256) = hash_file(data);
    HashBundle {
        md5,
        sha256,
        imphash: compute_imphash(imports),
        ssdeep: None,
        tlsh: None,
    }
}

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: Option<String>,
    pub tags: Vec<String>,
}

pub fn scan_yara(data: &[u8], rules_path: Option<&std::path::Path>) -> Vec<YaraMatch> {
    scan_yara_file(data, rules_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imphash_deterministic() {
        let imports = vec![
            ImportEntry {
                library: "KERNEL32.dll".into(),
                function: "CreateFileA".into(),
            },
            ImportEntry {
                library: "kernel32.dll".into(),
                function: "ReadFile".into(),
            },
        ];
        let h1 = compute_imphash(&imports).unwrap();
        let h2 = compute_imphash(&imports).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
        // Golden MD5 of "kernel32.createfilea,kernel32.readfile" (IAT order).
        assert_eq!(h1, "2d7133194ae83ab7306b73f323242785");
    }

    #[test]
    fn imphash_preserves_iat_order() {
        let a = vec![
            ImportEntry {
                library: "kernel32.dll".into(),
                function: "CreateFileA".into(),
            },
            ImportEntry {
                library: "kernel32.dll".into(),
                function: "ReadFile".into(),
            },
        ];
        let b = vec![
            ImportEntry {
                library: "kernel32.dll".into(),
                function: "ReadFile".into(),
            },
            ImportEntry {
                library: "kernel32.dll".into(),
                function: "CreateFileA".into(),
            },
        ];
        assert_ne!(compute_imphash(&a), compute_imphash(&b));
        assert_eq!(
            compute_imphash(&b).unwrap(),
            "b1c7936280315755bcad849d77149970"
        );
    }

    #[test]
    fn imphash_resolves_ws2_32_ordinals() {
        // Without resolution this would hash `ws2_32.ordinal 8` (wrong).
        let imports = vec![ImportEntry {
            library: "WS2_32.dll".into(),
            function: "ORDINAL 8".into(),
        }];
        let joined_md5 = {
            let mut h = Md5::new();
            h.update(b"ws2_32.htonl");
            hex::encode(h.finalize())
        };
        assert_eq!(compute_imphash(&imports).unwrap(), joined_md5);
    }

    #[test]
    fn fanny_imphash_matches_virustotal() {
        // Regression: Fanny's sole ordinal import is WS2_32!8 → htonl.
        // Full IAT is large; this asserts the live sample when present.
        let path = std::path::Path::new(
            "/Users/jackweekly/Documents/Malware/EquationGroup.Fanny/EquationGroup.Fanny.zip",
        );
        if !path.exists() {
            return;
        }
        let samples =
            crate::containment::collect_samples(path, false, Some("infected")).expect("collect");
        let pe = samples
            .iter()
            .find(|s| s.data.len() > 2 && s.data[..2] == *b"MZ")
            .expect("PE member");
        let parsed = crate::triage::parse_binary_named(&pe.data, false, Some(&pe.label))
            .expect("parse");
        let hash = compute_imphash(&parsed.imports).expect("imphash");
        assert_eq!(
            hash, "1f5e76572fad36553733428ca3571f53",
            "Fanny ImpHash must match VirusTotal / pefile"
        );
    }
}
