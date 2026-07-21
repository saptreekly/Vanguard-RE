//! Signature engine: ImpHash, file hashes, lightweight builtin pattern rules.

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
        let func = normalize_func(&imp.function);
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

fn normalize_func(func: &str) -> String {
    let f = func.trim();
    if let Some(rest) = f.strip_prefix('#') {
        return format!("ord{rest}");
    }
    if let Some(rest) = f.strip_prefix("Ordinal ") {
        return format!("ord{rest}");
    }
    f.to_ascii_lowercase()
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
}
