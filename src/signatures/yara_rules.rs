//! Built-in signature rules — fast string/byte patterns, no YARA-X runtime.
//!
//! External `.yar` files are accepted for future CLI-yara integration; today they
//! are skipped with a note so clean builds stay free of Wasmtime/cranelift.

use super::YaraMatch;

/// Scan bytes with embedded rules (lightweight matcher).
pub fn scan_builtin_rules(data: &[u8]) -> Vec<YaraMatch> {
    scan_lightweight(data)
}

/// Optional external `.yar` path. Full YARA is not linked; builtins always run.
pub fn scan_yara_file(data: &[u8], rules_path: Option<&std::path::Path>) -> Vec<YaraMatch> {
    let hits = scan_builtin_rules(data);
    if let Some(path) = rules_path {
        eprintln!(
            "note: external YARA file {} ignored (embedded YARA-X removed for faster builds; builtins still apply)",
            path.display()
        );
    }
    hits
}

fn ascii_lower_lossy(data: &[u8]) -> String {
    // Cap scan window so huge samples stay cheap.
    let slice = if data.len() > 8 * 1024 * 1024 {
        &data[..8 * 1024 * 1024]
    } else {
        data
    };
    String::from_utf8_lossy(slice).to_ascii_lowercase()
}

fn is_pe(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'M' && data[1] == b'Z'
}

fn contains_ascii_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    let nlen = needle.len();
    hay.windows(nlen).any(|w| {
        w.iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

fn hit(rule: &str, severity: &str) -> YaraMatch {
    YaraMatch {
        rule: rule.into(),
        namespace: None,
        tags: vec![format!("severity:{severity}")],
    }
}

fn scan_lightweight(data: &[u8]) -> Vec<YaraMatch> {
    let text = ascii_lower_lossy(data);
    let pe = is_pe(data);
    let mut hits = Vec::new();

    // ElectroRAT / Electron RAT string indicators — need ≥3
    let mut electro_n = 0usize;
    if text.contains("electrora") {
        electro_n += 2; // ElectroRAT + electrora
    }
    for s in [
        "discord.com/api/webhooks",
        "api.telegram.org/bot",
        "keylog",
        "screenshot",
        "webcam",
        "password",
        "wallet",
    ] {
        if text.contains(s) {
            electro_n += 1;
        }
    }
    if text.contains("user32.dll") {
        electro_n += 1;
    }
    if electro_n >= 3 {
        hits.push(hit("ElectroRAT_String_Indicators", "high"));
    }

    if pe {
        let wininet = [
            b"InternetOpen".as_slice(),
            b"InternetConnect".as_slice(),
            b"HttpOpenRequest".as_slice(),
            b"HttpSendRequest".as_slice(),
            b"InternetReadFile".as_slice(),
        ];
        let n = wininet.iter().filter(|s| contains_ascii_ci(data, s)).count();
        if n >= 3 {
            hits.push(hit("RAT_WinINet_C2_Imports", "medium"));
        }

        let has = |s: &[u8]| contains_ascii_ci(data, s);
        let inj = has(b"VirtualAllocEx")
            && has(b"WriteProcessMemory")
            && (has(b"CreateRemoteThread") || has(b"SetThreadContext"));
        let hollow = has(b"WriteProcessMemory")
            && (has(b"NtUnmapViewOfSection") || has(b"ZwUnmapViewOfSection"));
        if inj || hollow {
            hits.push(hit("RAT_Process_Injection_Imports", "high"));
        }

        if ["WSAStartup", "socket", "connect", "send", "recv"]
            .iter()
            .all(|s| contains_ascii_ci(data, s.as_bytes()))
        {
            hits.push(hit("RAT_Socket_Client", "medium"));
        }

        if contains_ascii_ci(data, b"CODE")
            && contains_ascii_ci(data, b"DATA")
            && contains_ascii_ci(data, b".idata")
        {
            hits.push(hit("Suspicious_Delphi_CODE_Section", "low"));
        }
    }

    let stealer = [
        "login data",
        "cookies",
        "web data",
        "local storage",
        "chrome",
        "firefox",
        "mozill",
        "wallet.dat",
        "seed",
        "mnemonic",
    ]
    .iter()
    .filter(|s| text.contains(*s))
    .count();
    if stealer >= 4 {
        hits.push(hit("Common_Stealer_Keywords", "medium"));
    }

    hits
}
