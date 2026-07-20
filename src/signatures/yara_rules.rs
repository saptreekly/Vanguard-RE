//! Built-in YARA-X rules for common RATs / ElectroRAT-class tooling.

use super::YaraMatch;

const BUILTIN_RULES: &str = r#"
rule ElectroRAT_String_Indicators
{
    meta:
        description = "ElectroRAT / Electron RAT string indicators"
        severity = "high"
    strings:
        $e1 = "ElectroRAT" nocase ascii wide
        $e2 = "electrora" nocase ascii wide
        $e3 = "discord.com/api/webhooks" nocase ascii wide
        $e4 = "api.telegram.org/bot" nocase ascii wide
        $e5 = "user32.dll" ascii wide
        $e6 = "keylog" nocase ascii wide
        $e7 = "screenshot" nocase ascii wide
        $e8 = "webcam" nocase ascii wide
        $e9 = "password" nocase ascii wide
        $e10 = "wallet" nocase ascii wide
    condition:
        3 of ($e*)
}

rule RAT_WinINet_C2_Imports
{
    meta:
        description = "PE imports WinINet HTTP client APIs typical of RATs"
        severity = "medium"
    strings:
        $a = "InternetOpen" ascii
        $b = "InternetConnect" ascii
        $c = "HttpOpenRequest" ascii
        $d = "HttpSendRequest" ascii
        $e = "InternetReadFile" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule RAT_Process_Injection_Imports
{
    meta:
        description = "PE imports classic remote process injection APIs"
        severity = "high"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
        $d = "SetThreadContext" ascii
        $e = "NtUnmapViewOfSection" ascii
        $f = "ZwUnmapViewOfSection" ascii
    condition:
        uint16(0) == 0x5A4D and
        ($a and $b and ($c or $d)) or ($b and ($e or $f))
}

rule RAT_Socket_Client
{
    meta:
        description = "Winsock client primitives often used for C2"
        severity = "medium"
    strings:
        $a = "WSAStartup" ascii
        $b = "socket" ascii
        $c = "connect" ascii
        $d = "send" ascii
        $e = "recv" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Suspicious_Delphi_CODE_Section
{
    meta:
        description = "Delphi-style CODE section name in PE"
        severity = "low"
    strings:
        $code = "CODE" ascii
        $data = "DATA" ascii
        $idata = ".idata" ascii
    condition:
        uint16(0) == 0x5A4D and $code and $data and $idata
}

rule Common_Stealer_Keywords
{
    meta:
        description = "Credential stealer keyword cluster"
        severity = "medium"
    strings:
        $s1 = "Login Data" ascii wide
        $s2 = "Cookies" ascii wide
        $s3 = "Web Data" ascii wide
        $s4 = "Local Storage" ascii wide
        $s5 = "Chrome" ascii wide
        $s6 = "Firefox" ascii wide
        $s7 = "Mozill" ascii wide
        $s8 = "wallet.dat" ascii wide
        $s9 = "Seed" ascii wide
        $s10 = "mnemonic" nocase ascii wide
    condition:
        4 of them
}
"#;

/// Scan bytes with embedded YARA-X rules.
pub fn scan_builtin_rules(data: &[u8]) -> Vec<YaraMatch> {
    match scan_with_yara_x(data) {
        Ok(hits) => hits,
        Err(e) => {
            // Fall back to a tiny string matcher so investigation never fails open empty.
            eprintln!("note: YARA-X scan fallback ({e}); using lightweight string rules");
            scan_lightweight(data)
        }
    }
}

fn scan_with_yara_x(data: &[u8]) -> Result<Vec<YaraMatch>, String> {
    use yara_x::{Compiler, Scanner};

    let mut compiler = Compiler::new();
    compiler
        .add_source(BUILTIN_RULES)
        .map_err(|e| format!("compile builtin rules: {e}"))?;
    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner
        .scan(data)
        .map_err(|e| format!("scan: {e}"))?;

    let mut out = Vec::new();
    for rule in results.matching_rules() {
        let ident = rule.identifier().to_string();
        let mut tags: Vec<String> = rule.tags().map(|t| t.identifier().to_string()).collect();
        let severity = rule
            .metadata()
            .find(|(k, _)| *k == "severity")
            .and_then(|(_, v)| match v {
                yara_x::MetaValue::String(s) => Some(s.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "info".into());
        tags.push(format!("severity:{severity}"));
        out.push(YaraMatch {
            rule: ident,
            namespace: None,
            tags,
        });
    }
    Ok(out)
}

fn scan_lightweight(data: &[u8]) -> Vec<YaraMatch> {
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    let mut hits = Vec::new();

    let electro = [
        "electrora",
        "discord.com/api/webhooks",
        "api.telegram.org/bot",
        "keylog",
        "screenshot",
        "webcam",
    ]
    .iter()
    .filter(|s| text.contains(*s))
    .count();
    if electro >= 3 {
        hits.push(YaraMatch {
            rule: "ElectroRAT_String_Indicators".into(),
            namespace: None,
            tags: vec!["severity:high".into(), "fallback".into()],
        });
    }

    let inj = ["virtualallocex", "writeprocessmemory", "setthreadcontext", "createremotethread"];
    let inj_n = inj.iter().filter(|s| text.contains(*s)).count();
    if inj_n >= 3 {
        hits.push(YaraMatch {
            rule: "RAT_Process_Injection_Imports".into(),
            namespace: None,
            tags: vec!["severity:high".into(), "fallback".into()],
        });
    }

    let sock = ["wsastartup", "connect", "send", "recv"];
    if sock.iter().all(|s| text.contains(s)) {
        hits.push(YaraMatch {
            rule: "RAT_Socket_Client".into(),
            namespace: None,
            tags: vec!["severity:medium".into(), "fallback".into()],
        });
    }

    hits
}

/// Optional external `.yar` file alongside builtins.
pub fn scan_yara_file(data: &[u8], rules_path: Option<&std::path::Path>) -> Vec<YaraMatch> {
    let mut hits = scan_builtin_rules(data);
    let Some(path) = rules_path else {
        return hits;
    };
    match std::fs::read_to_string(path) {
        Ok(src) => match scan_source(data, &src) {
            Ok(mut extra) => hits.append(&mut extra),
            Err(e) => eprintln!("note: failed to load {}: {e}", path.display()),
        },
        Err(e) => eprintln!("note: cannot read {}: {e}", path.display()),
    }
    hits
}

fn scan_source(data: &[u8], source: &str) -> Result<Vec<YaraMatch>, String> {
    use yara_x::{Compiler, Scanner};
    let mut compiler = Compiler::new();
    compiler
        .add_source(source)
        .map_err(|e| format!("compile: {e}"))?;
    let rules = compiler.build();
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(data).map_err(|e| format!("scan: {e}"))?;
    Ok(results
        .matching_rules()
        .map(|rule| YaraMatch {
            rule: rule.identifier().to_string(),
            namespace: None,
            tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
        })
        .collect())
}
