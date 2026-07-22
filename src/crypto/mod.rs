//! Crypto scheme identification via constant fingerprints.
//!
//! Static, read-only detection: most crypto implementations bake distinctive
//! constants into the binary — S-boxes, init vectors, round-constant tables,
//! stream-cipher sigma strings, and PEM headers. We also flag CryptoAPI/CNG
//! imports. Nothing is executed; this only tells an analyst *what* a sample is
//! likely built to encrypt/hash with (e.g. ransomware key/stream ciphers).
//!
//! Weak XOR recovery (repeating key + keystream reuse) lives in [`xor`].

pub mod xor;

use std::collections::BTreeMap;

use crate::triage::ImportEntry;

pub use xor::{XorMethod, XorRecovery, scan as scan_xor, scan_pairwise_across};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoCategory {
    /// Block cipher (AES, Blowfish, …).
    Block,
    /// Stream cipher (ChaCha20, Salsa20, RC4, …).
    Stream,
    /// Cryptographic hash / MAC (SHA family, MD5, …).
    Hash,
    /// Non-cryptographic checksum (CRC32).
    Checksum,
    /// Encoding (Base64) — often wraps encrypted payloads.
    Encoding,
    /// Public-key / PKI material (PEM keys, certificates).
    Pki,
    /// Platform crypto API usage (Windows CAPI / CNG).
    Api,
    /// Known crypto library embedded.
    Library,
}

impl CryptoCategory {
    pub fn label(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Stream => "stream",
            Self::Hash => "hash",
            Self::Checksum => "checksum",
            Self::Encoding => "encoding",
            Self::Pki => "pki",
            Self::Api => "api",
            Self::Library => "library",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CryptoFinding {
    /// Algorithm / scheme name, e.g. "AES", "SHA-256", "ChaCha20/Salsa20".
    pub name: String,
    pub category: CryptoCategory,
    /// 0–100 confidence this scheme is present.
    pub confidence: u8,
    /// What matched, e.g. "S-box table", "init vector (LE)".
    pub evidence: String,
}

struct Sig {
    name: &'static str,
    category: CryptoCategory,
    confidence: u8,
    evidence: &'static str,
    pattern: &'static [u8],
}

/// Constant/byte-pattern signatures. Multi-byte word constants are matched in
/// both little-endian (x86 in-memory) and big-endian (canonical) orders.
const SIGNATURES: &[Sig] = &[
    // ── AES ──────────────────────────────────────────────────────────────
    Sig {
        name: "AES",
        category: CryptoCategory::Block,
        confidence: 95,
        evidence: "forward S-box table",
        pattern: &[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ],
    },
    Sig {
        name: "AES",
        category: CryptoCategory::Block,
        confidence: 95,
        evidence: "inverse S-box table",
        pattern: &[
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
            0xd7, 0xfb,
        ],
    },
    // ── ChaCha20 / Salsa20 (sigma constants) ─────────────────────────────
    Sig {
        name: "ChaCha20/Salsa20",
        category: CryptoCategory::Stream,
        confidence: 92,
        evidence: "\"expand 32-byte k\" sigma",
        pattern: b"expand 32-byte k",
    },
    Sig {
        name: "ChaCha20/Salsa20",
        category: CryptoCategory::Stream,
        confidence: 92,
        evidence: "\"expand 16-byte k\" sigma",
        pattern: b"expand 16-byte k",
    },
    // ── SHA-256 init vector ───────────────────────────────────────────────
    Sig {
        name: "SHA-256",
        category: CryptoCategory::Hash,
        confidence: 90,
        evidence: "init vector (LE)",
        pattern: &[
            0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5,
            0x4f, 0xa5,
        ],
    },
    Sig {
        name: "SHA-256",
        category: CryptoCategory::Hash,
        confidence: 90,
        evidence: "init vector (BE)",
        pattern: &[
            0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f,
            0xf5, 0x3a,
        ],
    },
    // ── SHA-512 init vector (first 64-bit word) ──────────────────────────
    Sig {
        name: "SHA-512",
        category: CryptoCategory::Hash,
        confidence: 90,
        evidence: "init vector (LE)",
        pattern: &[0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a],
    },
    Sig {
        name: "SHA-512",
        category: CryptoCategory::Hash,
        confidence: 90,
        evidence: "init vector (BE)",
        pattern: &[0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08],
    },
    // ── SHA-1 init vector (5 words incl. C3D2E1F0) ───────────────────────
    Sig {
        name: "SHA-1",
        category: CryptoCategory::Hash,
        confidence: 88,
        evidence: "init vector (LE)",
        pattern: &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xf0, 0xe1, 0xd2, 0xc3,
        ],
    },
    Sig {
        name: "SHA-1",
        category: CryptoCategory::Hash,
        confidence: 88,
        evidence: "init vector (BE)",
        pattern: &[
            0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32,
            0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0,
        ],
    },
    // ── MD5 (sine round-constant table) ──────────────────────────────────
    Sig {
        name: "MD5",
        category: CryptoCategory::Hash,
        confidence: 88,
        evidence: "T-table sine constants (LE)",
        pattern: &[
            0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8, 0xdb, 0x70, 0x20, 0x24, 0xee, 0xce,
            0xbd, 0xc1,
        ],
    },
    // ── Blowfish (P-array = digits of pi) ────────────────────────────────
    Sig {
        name: "Blowfish",
        category: CryptoCategory::Block,
        confidence: 85,
        evidence: "P-array (pi) init (LE)",
        pattern: &[
            0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85, 0x2e, 0x8a, 0x19, 0x13, 0x44, 0x73,
            0x70, 0x03,
        ],
    },
    Sig {
        name: "Blowfish",
        category: CryptoCategory::Block,
        confidence: 85,
        evidence: "P-array (pi) init (BE)",
        pattern: &[
            0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x44,
        ],
    },
    // ── CRC32 (reflected + normal polynomials) ───────────────────────────
    Sig {
        name: "CRC32",
        category: CryptoCategory::Checksum,
        confidence: 55,
        evidence: "reflected polynomial 0xEDB88320",
        pattern: &[0x20, 0x83, 0xb8, 0xed],
    },
    Sig {
        name: "CRC32",
        category: CryptoCategory::Checksum,
        confidence: 50,
        evidence: "polynomial 0x04C11DB7",
        pattern: &[0xb7, 0x1d, 0xc1, 0x04],
    },
    // ── TEA / XTEA delta (also golden-ratio constant) ────────────────────
    Sig {
        name: "TEA/XTEA",
        category: CryptoCategory::Block,
        confidence: 50,
        evidence: "delta 0x9E3779B9",
        pattern: &[0xb9, 0x79, 0x37, 0x9e],
    },
    // ── Base64 alphabets ─────────────────────────────────────────────────
    Sig {
        name: "Base64",
        category: CryptoCategory::Encoding,
        confidence: 80,
        evidence: "standard alphabet",
        pattern: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    },
    Sig {
        name: "Base64",
        category: CryptoCategory::Encoding,
        confidence: 80,
        evidence: "URL-safe alphabet",
        pattern: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    },
    // ── PEM / PKI key material ───────────────────────────────────────────
    Sig {
        name: "RSA/PKI",
        category: CryptoCategory::Pki,
        confidence: 85,
        evidence: "PEM public key header",
        pattern: b"-----BEGIN PUBLIC KEY-----",
    },
    Sig {
        name: "RSA/PKI",
        category: CryptoCategory::Pki,
        confidence: 88,
        evidence: "PEM RSA private key header",
        pattern: b"-----BEGIN RSA PRIVATE KEY-----",
    },
    Sig {
        name: "RSA/PKI",
        category: CryptoCategory::Pki,
        confidence: 80,
        evidence: "PEM certificate header",
        pattern: b"-----BEGIN CERTIFICATE-----",
    },
    Sig {
        name: "RSA/PKI",
        category: CryptoCategory::Pki,
        confidence: 82,
        evidence: "PEM EC private key header",
        pattern: b"-----BEGIN EC PRIVATE KEY-----",
    },
    // ── Embedded crypto libraries ────────────────────────────────────────
    Sig {
        name: "OpenSSL",
        category: CryptoCategory::Library,
        confidence: 65,
        evidence: "version/build string",
        pattern: b"OpenSSL",
    },
    Sig {
        name: "libsodium",
        category: CryptoCategory::Library,
        confidence: 70,
        evidence: "library string",
        pattern: b"libsodium",
    },
    Sig {
        name: "mbedTLS",
        category: CryptoCategory::Library,
        confidence: 68,
        evidence: "library string",
        pattern: b"mbed TLS",
    },
    Sig {
        name: "Crypto++",
        category: CryptoCategory::Library,
        confidence: 68,
        evidence: "library string",
        pattern: b"Crypto++",
    },
    Sig {
        name: "WolfSSL",
        category: CryptoCategory::Library,
        confidence: 68,
        evidence: "library string",
        pattern: b"wolfSSL",
    },
];

/// Windows CAPI/CNG import substrings (case-insensitive) that indicate the
/// sample delegates crypto to the OS. Value = human note.
const CRYPTO_API_FUNCS: &[&str] = &[
    "cryptencrypt",
    "cryptdecrypt",
    "cryptgenkey",
    "cryptderivekey",
    "cryptacquirecontext",
    "cryptimportkey",
    "cryptexportkey",
    "cryptgenrandom",
    "bcryptencrypt",
    "bcryptdecrypt",
    "bcryptgeneratesymmetrickey",
    "bcryptimportkey",
    "bcryptgenrandom",
    "bcryptderivekey",
    "rtlencryptmemory",
];

/// Scan a sample for crypto scheme fingerprints (constants + imports).
pub fn scan(data: &[u8], imports: &[ImportEntry]) -> Vec<CryptoFinding> {
    // Constants can live anywhere; cap the window so huge samples stay cheap.
    let window = &data[..data.len().min(16 * 1024 * 1024)];

    let mut best: BTreeMap<&str, CryptoFinding> = BTreeMap::new();
    let mut upsert = |name: &'static str, category, confidence: u8, evidence: String| {
        best.entry(name)
            .and_modify(|f| {
                if confidence > f.confidence {
                    f.confidence = confidence;
                    f.evidence = evidence.clone();
                }
            })
            .or_insert(CryptoFinding {
                name: name.to_string(),
                category,
                confidence,
                evidence,
            });
    };

    for sig in SIGNATURES {
        if contains_seq(window, sig.pattern) {
            upsert(
                sig.name,
                sig.category,
                sig.confidence,
                sig.evidence.to_string(),
            );
        }
    }

    // CryptoAPI / CNG imports.
    let mut api_hits: Vec<String> = Vec::new();
    for imp in imports {
        let f = imp.function.to_ascii_lowercase();
        if CRYPTO_API_FUNCS.iter().any(|a| f.contains(a)) {
            api_hits.push(imp.function.clone());
        }
    }
    if !api_hits.is_empty() {
        api_hits.sort();
        api_hits.dedup();
        let sample = api_hits
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let more = if api_hits.len() > 3 {
            format!(" (+{} more)", api_hits.len() - 3)
        } else {
            String::new()
        };
        upsert(
            "Windows CryptoAPI/CNG",
            CryptoCategory::Api,
            72,
            format!("imports {sample}{more}"),
        );
    }

    let mut out: Vec<CryptoFinding> = best.into_values().collect();
    out.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(a.name.cmp(&b.name))
    });
    out
}

/// Substring search with a cheap first-byte skip.
fn contains_seq(hay: &[u8], needle: &[u8]) -> bool {
    let n = needle.len();
    if n == 0 || hay.len() < n {
        return false;
    }
    let first = needle[0];
    let mut i = 0;
    while i + n <= hay.len() {
        if hay[i] == first && &hay[i..i + n] == needle {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(f: &[CryptoFinding]) -> Vec<&str> {
        f.iter().map(|c| c.name.as_str()).collect()
    }

    #[test]
    fn detects_aes_sbox() {
        let mut data = vec![0u8; 64];
        data.extend_from_slice(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ]);
        let f = scan(&data, &[]);
        assert!(names(&f).contains(&"AES"));
        assert!(f.iter().find(|c| c.name == "AES").unwrap().confidence >= 90);
    }

    #[test]
    fn detects_sha256_iv_le() {
        let data = [
            0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5,
            0x4f, 0xa5,
        ];
        assert!(names(&scan(&data, &[])).contains(&"SHA-256"));
    }

    #[test]
    fn detects_chacha_sigma() {
        let data = b"....expand 32-byte k....";
        assert!(names(&scan(data, &[])).contains(&"ChaCha20/Salsa20"));
    }

    #[test]
    fn detects_base64_alphabet() {
        let data = b"table=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/;";
        assert!(names(&scan(data, &[])).contains(&"Base64"));
    }

    #[test]
    fn detects_cryptoapi_imports() {
        let imports = vec![ImportEntry {
            library: "advapi32.dll".into(),
            function: "CryptEncrypt".into(),
        }];
        let f = scan(&[], &imports);
        assert!(names(&f).contains(&"Windows CryptoAPI/CNG"));
    }

    #[test]
    fn clean_data_yields_nothing() {
        let data = b"the quick brown fox jumps over the lazy dog 12345";
        assert!(scan(data, &[]).is_empty());
    }
}
