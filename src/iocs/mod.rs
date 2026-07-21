//! Network IOC extraction — hardcoded IPs, ip:port pairs, URLs, domains,
//! onion services, and emails pulled from sample strings (C2 candidates).
//!
//! Static, read-only string analysis for defensive triage. Nothing is
//! resolved or contacted; candidates are ranked so analysts can pivot.

use std::collections::BTreeMap;

use crate::disasm::extract_strings_ranked;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocKind {
    Url,
    Ipv4Port,
    Ipv4,
    Onion,
    Domain,
    Email,
    /// Bitcoin wallet address (ransom payment).
    Bitcoin,
}

impl IocKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Url => "URL",
            Self::Ipv4Port => "IP:PORT",
            Self::Ipv4 => "IPV4",
            Self::Onion => "ONION",
            Self::Domain => "DOMAIN",
            Self::Email => "EMAIL",
            Self::Bitcoin => "BTC",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkIoc {
    pub kind: IocKind,
    pub value: String,
    /// 0–100 likelihood this is a real network indicator.
    pub confidence: u8,
    /// Occurrences across extracted strings.
    pub count: u32,
    /// Private / loopback / reserved address space (down-weighted as C2).
    pub private: bool,
}

/// Vendor / documentation hosts that are almost never C2.
const NOISE_HOSTS: &[&str] = &[
    "schemas.microsoft.com",
    "www.w3.org",
    "purl.org",
    "xmlsoap.org",
    "microsoft.com",
    "windows.com",
    "w3.org",
    "apache.org",
    "gnu.org",
    "openssl.org",
];

fn is_noise_host(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    NOISE_HOSTS.iter().any(|h| lower.contains(h))
}

/// Extract network IOCs from raw sample bytes (ASCII + UTF-16LE strings).
pub fn scan_data(data: &[u8]) -> Vec<NetworkIoc> {
    // Large ranked set — packer noise must not starve C2 domains.
    let strings = extract_strings_ranked(data, 12_000);
    let mut found: BTreeMap<String, NetworkIoc> = BTreeMap::new();
    for s in &strings {
        scan_text(&s.value, &mut found);
    }
    // Raw byte passes catch indicators that survived packing as contiguous
    // printable runs but were outranked / filtered from the string list.
    scan_raw_domains(data, &mut found);
    scan_raw_onions(data, &mut found);
    scan_raw_bitcoin(data, &mut found);

    // Drop bare domains/IPs that already appear inside a captured URL.
    let urls: Vec<String> = found
        .values()
        .filter(|i| i.kind == IocKind::Url)
        .map(|i| i.value.clone())
        .collect();
    found.retain(|_, ioc| {
        !is_noise_host(&ioc.value)
            && (ioc.kind == IocKind::Url || !urls.iter().any(|u| u.contains(&ioc.value)))
    });

    let mut out: Vec<NetworkIoc> = found.into_values().collect();
    out.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(b.count.cmp(&a.count))
            .then(a.value.cmp(&b.value))
    });
    out.truncate(40);
    out
}

fn add(found: &mut BTreeMap<String, NetworkIoc>, ioc: NetworkIoc) {
    found
        .entry(ioc.value.clone())
        .and_modify(|e| {
            e.count += 1;
            e.confidence = e.confidence.max(ioc.confidence);
        })
        .or_insert(ioc);
}

fn scan_text(text: &str, found: &mut BTreeMap<String, NetworkIoc>) {
    scan_urls(text, found);
    scan_ipv4(text, found);
    scan_tokens(text, found);
    scan_bitcoin_text(text, found);
}

const URL_SCHEMES: &[&str] = &["http://", "https://", "ftp://", "ws://", "wss://"];

fn scan_urls(text: &str, found: &mut BTreeMap<String, NetworkIoc>) {
    for scheme in URL_SCHEMES {
        for (start, _) in text.match_indices(scheme) {
            let rest = &text[start..];
            let end = rest
                .find(|c: char| {
                    c.is_whitespace()
                        || c.is_control()
                        || matches!(c, '"' | '\'' | '<' | '>' | ')' | '}' | '|')
                })
                .unwrap_or(rest.len());
            let url = rest[..end].trim_end_matches(['.', ',', ';']);
            let host = &url[scheme.len()..];
            if host.len() < 4 {
                continue;
            }
            let host_only = host.split(['/', ':', '?']).next().unwrap_or("");
            let (confidence, private) = match parse_ipv4(host_only) {
                Some(octets) => {
                    let private = is_private(octets);
                    (if private { 40 } else { 95 }, private)
                }
                None => (85, false),
            };
            add(
                found,
                NetworkIoc {
                    kind: IocKind::Url,
                    value: url.to_string(),
                    confidence,
                    count: 1,
                    private,
                },
            );
        }
    }
}

/// Parse a full string as a dotted-quad IPv4.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        octets[i] = p.parse().ok()?;
    }
    Some(octets)
}

fn is_private(o: [u8; 4]) -> bool {
    o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || o[0] >= 224 // multicast + reserved
}

/// Scan free text for dotted-quad IPs with optional `:port`.
fn scan_ipv4(text: &str, found: &mut BTreeMap<String, NetworkIoc>) {
    // Version strings ("ProductVersion 6.1.7600.16385") are the main FP source.
    let versionish = text.to_ascii_lowercase().contains("version");

    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Must start on a digit-run boundary (previous char not digit/dot).
        if i > 0 && (b[i - 1].is_ascii_digit() || b[i - 1] == b'.') {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            continue;
        }

        let start = i;
        let mut octets = [0u8; 4];
        let mut ok = true;
        for (k, slot) in octets.iter_mut().enumerate() {
            let mut val: u32 = 0;
            let mut len = 0;
            while i < b.len() && b[i].is_ascii_digit() && len < 3 {
                val = val * 10 + u32::from(b[i] - b'0');
                i += 1;
                len += 1;
            }
            if len == 0 || val > 255 || (i < b.len() && b[i].is_ascii_digit()) {
                ok = false;
                break;
            }
            *slot = val as u8;
            if k < 3 {
                if i < b.len() && b[i] == b'.' {
                    i += 1;
                } else {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            // Skip the rest of this digit/dot run to avoid re-matching a suffix.
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            continue;
        }
        // A fifth dotted group means it's not an IP (version / OID-ish).
        if i + 1 < b.len() && b[i] == b'.' && b[i + 1].is_ascii_digit() {
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            continue;
        }
        if octets == [0, 0, 0, 0] || octets == [255, 255, 255, 255] {
            continue;
        }

        // Optional :port
        let ip_end = i;
        let mut port: Option<u32> = None;
        if i < b.len() && b[i] == b':' {
            let mut j = i + 1;
            let mut val: u32 = 0;
            let mut len = 0;
            while j < b.len() && b[j].is_ascii_digit() && len < 5 {
                val = val * 10 + u32::from(b[j] - b'0');
                j += 1;
                len += 1;
            }
            if len > 0 && val > 0 && val <= 65535 && !(j < b.len() && b[j].is_ascii_digit()) {
                port = Some(val);
                i = j;
            }
        }

        let private = is_private(octets);
        // A bare private/version IP with no port is almost never a real IOC.
        if versionish && port.is_none() {
            continue;
        }
        let (kind, value, confidence) = match port {
            Some(_) => (
                IocKind::Ipv4Port,
                text[start..i].to_string(),
                if private { 35 } else { 90 },
            ),
            None => (
                IocKind::Ipv4,
                text[start..ip_end].to_string(),
                if private { 25 } else { 70 },
            ),
        };
        add(
            found,
            NetworkIoc {
                kind,
                value,
                confidence,
                count: 1,
                private,
            },
        );
    }
}

/// Common TLDs used to recognize bare domains and validate onion/email hosts.
const DOMAIN_TLDS: &[&str] = &[
    "com", "net", "org", "io", "ru", "cn", "su", "xyz", "top", "info", "biz",
    "cc", "tk", "pw", "me", "to", "co", "in", "de", "uk", "fr", "nl", "eu",
    "us", "br", "app", "dev", "site", "online", "club", "shop", "gov", "edu",
    "mil", "ml", "ga", "cf", "gq", "onion",
];

/// Whitespace-split token scan for `.onion`, emails, and bare domains.
fn scan_tokens(text: &str, found: &mut BTreeMap<String, NetworkIoc>) {
    for raw in text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')' | ',' | ';' | '|')) {
        let tok = raw.trim_matches(|c: char| matches!(c, '.' | '/' | ':' | '=' | '[' | ']'));
        if tok.len() < 4 || tok.len() > 253 {
            continue;
        }
        let lower = tok.to_ascii_lowercase();

        // Email: local@domain.tld
        if let Some((local, domain)) = lower.split_once('@') {
            if !local.is_empty()
                && !local.contains('@')
                && looks_like_domain(domain)
            {
                add(
                    found,
                    NetworkIoc {
                        kind: IocKind::Email,
                        value: lower.clone(),
                        confidence: 75,
                        count: 1,
                        private: false,
                    },
                );
                continue;
            }
        }

        // Onion service: <base32>.onion (v2=16, v3=56 chars before .onion)
        if let Some(host) = lower.strip_suffix(".onion").or_else(|| {
            lower.split('/').next().filter(|h| h.ends_with(".onion"))
                .map(|h| h.trim_end_matches(".onion"))
        }) {
            let sub = host.rsplit('.').next().unwrap_or(host);
            if (sub.len() == 16 || sub.len() == 56)
                && sub.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                add(
                    found,
                    NetworkIoc {
                        kind: IocKind::Onion,
                        value: lower.clone(),
                        confidence: 95,
                        count: 1,
                        private: false,
                    },
                );
                continue;
            }
        }

        // Bare domain (no scheme). Strip an optional path for the check.
        let host = lower.split('/').next().unwrap_or(&lower);
        if looks_like_domain(host) {
            add(
                found,
                NetworkIoc {
                    kind: IocKind::Domain,
                    value: host.to_string(),
                    confidence: domain_confidence(host),
                    count: 1,
                    private: false,
                },
            );
        }
    }
}

fn domain_confidence(host: &str) -> u8 {
    let labels: Vec<&str> = host.split('.').collect();
    let tld = labels.last().copied().unwrap_or("");
    let sld = labels.get(labels.len().saturating_sub(2)).copied().unwrap_or("");
    let suspicious_tld =
        matches!(tld, "tk" | "top" | "xyz" | "gq" | "ml" | "ga" | "cf" | "pw" | "su");
    // Long random SLD (WannaCry kill-switch style) is a strong C2/beacon IOC.
    if sld.len() >= 20
        && sld.bytes().filter(|b| b.is_ascii_alphabetic()).count() * 100 / sld.len() >= 80
    {
        return 88;
    }
    if suspicious_tld {
        70
    } else {
        55
    }
}

/// Walk raw bytes looking for `.tld` anchors and backtrack a hostname.
fn scan_raw_domains(data: &[u8], found: &mut BTreeMap<String, NetworkIoc>) {
    const TLDS: &[&[u8]] = &[
        b".com", b".net", b".org", b".info", b".biz", b".xyz", b".top", b".onion", b".ru",
        b".cn", b".io",
    ];
    let window = &data[..data.len().min(16 * 1024 * 1024)];
    for tld in TLDS {
        let mut start = 0;
        while let Some(rel) = find_bytes(&window[start..], tld) {
            let abs = start + rel;
            let end = abs + tld.len();
            // Require a non-hostname character (or EOF) after the TLD.
            if end < window.len() {
                let n = window[end];
                if n.is_ascii_alphanumeric() || n == b'.' || n == b'-' {
                    start = abs + 1;
                    continue;
                }
            }
            // Backtrack over hostname chars.
            let mut i = abs;
            while i > 0 {
                let b = window[i - 1];
                if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' {
                    i -= 1;
                } else {
                    break;
                }
            }
            if abs > i {
                if let Ok(host) = std::str::from_utf8(&window[i..end]) {
                    let host = host.to_ascii_lowercase();
                    if looks_like_domain(&host) && !is_noise_host(&host) {
                        add(
                            found,
                            NetworkIoc {
                                kind: if host.ends_with(".onion") {
                                    IocKind::Onion
                                } else {
                                    IocKind::Domain
                                },
                                value: host.clone(),
                                confidence: if host.ends_with(".onion") {
                                    95
                                } else {
                                    domain_confidence(&host)
                                },
                                count: 1,
                                private: false,
                            },
                        );
                    }
                }
            }
            start = abs + 1;
        }
    }
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// ── Tor onion services ───────────────────────────────────────────────────

fn is_base32_onion(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'2'..=b'7')
}

/// Raw byte scan for `<base32>.onion` (v2 = 16 chars, v3 = 56 chars).
fn scan_raw_onions(data: &[u8], found: &mut BTreeMap<String, NetworkIoc>) {
    let window = &data[..data.len().min(16 * 1024 * 1024)];
    let mut start = 0;
    while let Some(rel) = find_bytes(&window[start..], b".onion") {
        let dot = start + rel;
        // Backtrack over base32 label chars.
        let mut i = dot;
        while i > 0 && is_base32_onion(window[i - 1]) {
            i -= 1;
        }
        let label_len = dot - i;
        if label_len == 16 || label_len == 56 {
            if let Ok(label) = std::str::from_utf8(&window[i..dot]) {
                let host = format!("{}.onion", label.to_ascii_lowercase());
                add(
                    found,
                    NetworkIoc {
                        kind: IocKind::Onion,
                        value: host,
                        confidence: 95,
                        count: 1,
                        private: false,
                    },
                );
            }
        }
        start = dot + 1;
    }
}

// ── Bitcoin wallet addresses (ransom payment IOCs) ─────────────────────────

const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn is_base58(b: u8) -> bool {
    B58_ALPHABET.contains(&b)
}

/// Decode base58 to bytes (no checksum). `None` on invalid character.
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let val = B58_ALPHABET.iter().position(|&a| a == c)? as u32;
        let mut carry = val;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading '1's map to leading zero bytes.
    for c in s.bytes() {
        if c == b'1' {
            bytes.push(0);
        } else {
            break;
        }
    }
    bytes.reverse();
    Some(bytes)
}

/// Validate a P2PKH/P2SH Base58Check address by its double-SHA256 checksum.
fn is_valid_btc_base58(s: &str) -> bool {
    if s.len() < 26 || s.len() > 35 || !(s.starts_with('1') || s.starts_with('3')) {
        return false;
    }
    let Some(decoded) = base58_decode(s) else {
        return false;
    };
    if decoded.len() != 25 {
        return false;
    }
    let (payload, checksum) = decoded.split_at(21);
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    second[..4] == *checksum
}

/// Lightweight bech32 (`bc1…`) validation: prefix + charset + length.
/// Full polymod checksum is skipped; length/charset already rule out noise.
fn is_probable_bech32(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if !lower.starts_with("bc1") || lower.len() < 14 || lower.len() > 74 {
        return false;
    }
    const BECH32: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    lower.bytes().skip(3).all(|b| BECH32.contains(&b))
}

fn add_bitcoin(found: &mut BTreeMap<String, NetworkIoc>, addr: &str, confidence: u8) {
    add(
        found,
        NetworkIoc {
            kind: IocKind::Bitcoin,
            value: addr.to_string(),
            confidence,
            count: 1,
            private: false,
        },
    );
}

/// Token-level Bitcoin scan over an extracted string.
fn scan_bitcoin_text(text: &str, found: &mut BTreeMap<String, NetworkIoc>) {
    for raw in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if raw.len() < 14 {
            continue;
        }
        if is_valid_btc_base58(raw) {
            add_bitcoin(found, raw, 96);
        } else if is_probable_bech32(raw) {
            add_bitcoin(found, &raw.to_ascii_lowercase(), 85);
        }
    }
}

/// Raw byte scan for Base58Check Bitcoin addresses (checksum-validated).
fn scan_raw_bitcoin(data: &[u8], found: &mut BTreeMap<String, NetworkIoc>) {
    let window = &data[..data.len().min(16 * 1024 * 1024)];
    let mut i = 0;
    while i < window.len() {
        if !is_base58(window[i]) {
            i += 1;
            continue;
        }
        let s = i;
        while i < window.len() && is_base58(window[i]) {
            i += 1;
        }
        let run = &window[s..i];
        if run.len() < 26 || run.len() > 35 {
            continue;
        }
        if let Ok(tok) = std::str::from_utf8(run) {
            if is_valid_btc_base58(tok) {
                add_bitcoin(found, tok, 96);
            }
        }
    }
}

/// Heuristic: `label(.label)+.tld` with a known TLD and no spaces.
fn looks_like_domain(host: &str) -> bool {
    if host.len() < 4 || host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    // Reject dotted-quads (handled as IPv4) and non-hostname characters.
    if parse_ipv4(host).is_some() {
        return false;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let tld = *labels.last().unwrap();
    if !DOMAIN_TLDS.contains(&tld) {
        return false;
    }
    if labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return false;
    }
    let sld = labels[labels.len() - 2];
    // The registrable label must have real substance: ≥3 chars and at least
    // one vowel. This rejects fragments like "hs.uk" / "x.co" that a naive
    // TLD match would otherwise accept as domains.
    if sld.len() < 3 {
        return false;
    }
    if !sld.bytes().any(|b| matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u' | b'y')) {
        return false;
    }
    // Overall host should be plausibly long enough to be a real FQDN.
    host.len() >= 6
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(iocs: &[NetworkIoc], v: &str) -> Option<IocKind> {
        iocs.iter().find(|i| i.value == v).map(|i| i.kind)
    }

    #[test]
    fn finds_public_ip_port_as_high_confidence() {
        let data = b"connect 185.220.101.5:443 now";
        let iocs = scan_data(data);
        let hit = iocs.iter().find(|i| i.value == "185.220.101.5:443").unwrap();
        assert_eq!(hit.kind, IocKind::Ipv4Port);
        assert!(hit.confidence >= 85);
        assert!(!hit.private);
    }

    #[test]
    fn flags_private_ip_as_low_and_private() {
        let data = b"gateway 192.168.1.1 lan";
        let iocs = scan_data(data);
        let hit = iocs.iter().find(|i| i.value == "192.168.1.1").unwrap();
        assert!(hit.private);
        assert!(hit.confidence < 40);
    }

    #[test]
    fn ignores_version_quads() {
        let data = b"FileVersion 6.1.7600.16385 build";
        let iocs = scan_data(data);
        assert!(iocs.is_empty(), "version string must not yield IOCs: {iocs:?}");
    }

    #[test]
    fn captures_url_and_dedupes_bare_host() {
        let data = b"beacon https://evil.example.com/gate.php host evil.example.com";
        let iocs = scan_data(data);
        assert_eq!(
            kinds(&iocs, "https://evil.example.com/gate.php"),
            Some(IocKind::Url)
        );
        // Bare domain is folded into the URL.
        assert!(kinds(&iocs, "evil.example.com").is_none());
    }

    #[test]
    fn finds_wannacry_style_killswitch_domain() {
        // Classic WannaCry kill-switch domain shape (long random SLD).
        let host = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com";
        let mut blob = vec![0u8; 64];
        blob.extend_from_slice(host.as_bytes());
        blob.push(0);
        blob.extend_from_slice(b"KERNEL32.dll\0");
        let iocs = scan_data(&blob);
        let hit = iocs.iter().find(|i| i.value == host).unwrap();
        assert_eq!(hit.kind, IocKind::Domain);
        assert!(hit.confidence >= 80, "kill-switch domain should be high confidence");
    }

    #[test]
    fn rejects_short_sld_fragments() {
        // Two-letter SLD fragments (seen as "hs.uk") are not domains.
        assert!(!looks_like_domain("hs.uk"));
        assert!(!looks_like_domain("x.co"));
        assert!(!looks_like_domain("aa.ru"));
        // But real short-ccTLD domains still pass.
        assert!(looks_like_domain("evil.ru"));
        assert!(looks_like_domain("router.io"));
    }

    #[test]
    fn detects_real_wannacry_bitcoin_addresses() {
        // The three hardcoded WannaCry ransom wallets (public IOCs).
        for addr in [
            "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94",
            "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw",
            "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn",
        ] {
            assert!(is_valid_btc_base58(addr), "should validate {addr}");
            let blob = format!("send btc to {addr} now").into_bytes();
            let iocs = scan_data(&blob);
            let hit = iocs.iter().find(|i| i.value == addr).unwrap();
            assert_eq!(hit.kind, IocKind::Bitcoin);
            assert!(hit.confidence >= 90);
        }
    }

    #[test]
    fn rejects_invalid_base58check() {
        // Valid alphabet, right length, but checksum fails.
        assert!(!is_valid_btc_base58("13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb95"));
        assert!(!is_valid_btc_base58("1111111111111111111111111111111111"));
    }

    #[test]
    fn detects_real_wannacry_onions() {
        // Hardcoded WannaCry v2 onion C2 addresses (16-char base32).
        for onion in ["gx7ekbenv2riucmf.onion", "57g7spgrzlojinas.onion"] {
            let blob = format!("c2\x00{onion}\x00next").into_bytes();
            let iocs = scan_data(&blob);
            let hit = iocs.iter().find(|i| i.value == onion).unwrap();
            assert_eq!(hit.kind, IocKind::Onion);
            assert!(hit.confidence >= 90);
        }
    }

    #[test]
    fn drops_microsoft_schema_noise() {
        let data = b"http://schemas.microsoft.com/SMI/2005/WindowsSettings";
        let iocs = scan_data(data);
        assert!(
            iocs.is_empty(),
            "vendor schema URLs must not surface as C2: {iocs:?}"
        );
    }

    #[test]
    fn detects_onion_v3() {
        let host = "a".repeat(56);
        let s = format!("hidden {host}.onion done");
        let iocs = scan_data(s.as_bytes());
        assert!(iocs.iter().any(|i| i.kind == IocKind::Onion));
    }
}
