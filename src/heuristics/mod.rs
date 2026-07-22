//! Heuristic & API threat scoring (IAT behavioral profiling).

mod capabilities;

pub use capabilities::{capability_summary, tag_capabilities, CapabilityTag};

use crate::triage::ImportEntry;

/// A scored behavioral pattern matched against the import table.
#[derive(Debug, Clone)]
pub struct BehaviorMatch {
    pub name: String,
    pub severity: u8,
    pub description: String,
    pub matched_apis: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ThreatScore {
    /// 0–100 aggregate risk score
    pub score: u8,
    pub label: String,
    pub behaviors: Vec<BehaviorMatch>,
    pub suspicious_apis: Vec<String>,
    /// CAPA-style capability tags derived from imports.
    pub capabilities: Vec<CapabilityTag>,
}

/// High-risk Windows APIs frequently abused by malware.
const SUSPICIOUS_APIS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "SetThreadContext",
    "RtlCreateUserThread",
    "OpenProcess",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "ReadProcessMemory",
    "CreateToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "GetTickCount",
    "QueryPerformanceCounter",
    "CryptEncrypt",
    "CryptDecrypt",
    "BCryptEncrypt",
    "BCryptDecrypt",
    "CryptAcquireContextA",
    "CryptAcquireContextW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "HttpSendRequestA",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcessA",
    "CreateProcessW",
    "WinHttpOpen",
    "socket",
    "connect",
    "send",
    "recv",
    "WSAStartup",
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "AdjustTokenPrivileges",
    "LookupPrivilegeValueA",
    "OpenProcessToken",
    "CreateServiceA",
    "CreateServiceW",
    "StartServiceA",
    "DeviceIoControl",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyState",
    "BitBlt",
    "GetDC",
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualAlloc",
    "NtAllocateVirtualMemory",
];

struct Pattern {
    name: &'static str,
    severity: u8,
    description: &'static str,
    /// All of these APIs must be present (case-insensitive substring match on function name)
    required: &'static [&'static str],
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        name: "process_injection_classic",
        severity: 90,
        description: "Classic process injection (alloc + write + remote thread)",
        required: &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ],
    },
    Pattern {
        name: "process_injection_context",
        severity: 92,
        description: "Process injection / hollow-style (remote alloc + write + SetThreadContext)",
        required: &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "SetThreadContext",
        ],
    },
    Pattern {
        name: "process_injection_create",
        severity: 88,
        description: "CreateProcess + remote memory write (hollow / runPE precursor)",
        required: &["CreateProcess", "WriteProcessMemory", "VirtualAllocEx"],
    },
    Pattern {
        name: "process_hollowing",
        severity: 88,
        description: "Process hollowing indicators (unmap + write + context)",
        required: &["NtUnmapViewOfSection", "WriteProcessMemory", "SetThreadContext"],
    },
    Pattern {
        name: "process_hollowing_zw",
        severity: 88,
        description: "Process hollowing indicators (ZwUnmap + write)",
        required: &["ZwUnmapViewOfSection", "WriteProcessMemory"],
    },
    Pattern {
        name: "apc_injection",
        severity: 80,
        description: "APC injection via QueueUserAPC",
        required: &["QueueUserAPC", "VirtualAllocEx"],
    },
    Pattern {
        name: "anti_debug",
        severity: 55,
        description: "Anti-debugging API usage",
        required: &["IsDebuggerPresent"],
    },
    Pattern {
        name: "credential_token",
        severity: 70,
        description: "Token privilege escalation APIs",
        required: &["AdjustTokenPrivileges", "OpenProcessToken"],
    },
    Pattern {
        name: "keylogger_hooks",
        severity: 75,
        description: "Keyboard hook / key-state APIs",
        required: &["SetWindowsHookEx", "GetAsyncKeyState"],
    },
    Pattern {
        name: "network_http_client",
        severity: 50,
        description: "HTTP client APIs (WinINet)",
        required: &["InternetOpen", "HttpSendRequest"],
    },
    Pattern {
        name: "network_http_connect",
        severity: 55,
        description: "WinINet connect + HTTP send",
        required: &["InternetConnect", "HttpSendRequest"],
    },
    Pattern {
        name: "raw_socket_client",
        severity: 60,
        description: "Raw Winsock client (WSAStartup + socket + connect)",
        required: &["WSAStartup", "socket", "connect"],
    },
    Pattern {
        name: "unix_socket_bot",
        severity: 65,
        description: "Unix socket client (IoT/botnet style)",
        required: &["socket", "connect", "send"],
    },
    Pattern {
        name: "dynamic_api_resolve",
        severity: 40,
        description: "Dynamic API resolution (LoadLibrary + GetProcAddress)",
        required: &["LoadLibrary", "GetProcAddress"],
    },
    Pattern {
        name: "dynamic_api_resolve_ex",
        severity: 40,
        description: "Dynamic API resolution (LoadLibraryEx + GetProcAddress)",
        required: &["LoadLibraryEx", "GetProcAddress"],
    },
    Pattern {
        name: "service_persistence",
        severity: 65,
        description: "Windows service creation for persistence",
        required: &["CreateService", "StartService"],
    },
    Pattern {
        name: "mass_file_delete",
        severity: 55,
        description: "File enumeration + delete (cleanup / ransomware helper)",
        required: &["FindFirstFile", "DeleteFile"],
    },
    Pattern {
        name: "shell_execute",
        severity: 45,
        description: "ShellExecute / WinExec process launch",
        required: &["ShellExecute"],
    },
];

fn api_names(imports: &[ImportEntry]) -> Vec<String> {
    imports
        .iter()
        .map(|i| i.function.clone())
        .filter(|f| f != "*" && !f.is_empty())
        .collect()
}

/// Normalize Win32/Unix API names so `CreateServiceA` ≡ `CreateService` and
/// short needles like `send` do **not** match `SendMessageA`.
///
/// Deliberately does **not** strip trailing `Ex`: `VirtualAlloc` must not match
/// `VirtualAllocEx`, and `LoadLibrary` must not match `LoadLibraryEx`. Call sites
/// that want both list both names.
pub(crate) fn normalize_api(name: &str) -> String {
    let mut s = name.to_ascii_lowercase();
    // Strip stdcall decoration: _Foo@8 / Foo@4
    if let Some(at) = s.find('@') {
        s.truncate(at);
    }
    s = s.trim_start_matches('_').to_string();
    // Strip trailing A/W wide/ANSI suffix.
    if s.len() > 2 {
        let last = s.as_bytes()[s.len() - 1];
        if last == b'a' || last == b'w' {
            let prev = s.as_bytes()[s.len() - 2];
            if prev.is_ascii_alphabetic() {
                s.pop();
            }
        }
    }
    s
}

/// True when `api` is the same function as `needle` after Win32 suffix normalization.
pub(crate) fn api_matches(api: &str, needle: &str) -> bool {
    normalize_api(api) == normalize_api(needle)
}

fn has_api(apis: &[String], needle: &str) -> bool {
    apis.iter().any(|a| api_matches(a, needle))
}

/// Score a binary's import table against known malicious operational patterns.
pub fn score_imports(imports: &[ImportEntry]) -> ThreatScore {
    let apis = api_names(imports);

    let suspicious_apis: Vec<String> = apis
        .iter()
        .filter(|a| SUSPICIOUS_APIS.iter().any(|s| api_matches(a, s)))
        .cloned()
        .collect();

    let mut behaviors = Vec::new();
    for pat in PATTERNS {
        if pat.required.iter().all(|r| has_api(&apis, r)) {
            let matched: Vec<String> = pat
                .required
                .iter()
                .filter_map(|r| apis.iter().find(|a| api_matches(a, r)).cloned())
                .collect();
            behaviors.push(BehaviorMatch {
                name: pat.name.into(),
                severity: pat.severity,
                description: pat.description.into(),
                matched_apis: matched,
            });
        }
    }

    // Aggregate: max pattern severity, plus small bump for suspicious API density
    let max_sev = behaviors.iter().map(|b| b.severity).max().unwrap_or(0);
    let density_bump = (suspicious_apis.len().min(20) as u8).saturating_mul(2);
    let capabilities = tag_capabilities(imports);
    // Capability diversity bump (high-signal tags weigh more).
    let cap_bump: u8 = capabilities
        .iter()
        .map(|c| match c.id.as_str() {
            "injection" => 12,
            "c2_suspect" | "keylog" | "privilege" => 8,
            "socket_client" | "http_client" | "smb_enum" => 7,
            "persistence" | "crypto" | "anti_debug" | "file_delete" => 6,
            _ => 3,
        })
        .fold(0u8, |a, b| a.saturating_add(b))
        .min(24);
    let score = max_sev
        .saturating_add(density_bump)
        .saturating_add(cap_bump)
        .min(100);

    let label = compose_label(score, &capabilities, &behaviors);

    ThreatScore {
        score,
        label,
        behaviors,
        suspicious_apis,
        capabilities,
    }
}

/// Severity band only — never invents techniques the IAT did not match.
fn risk_band(score: u8) -> &'static str {
    match score {
        0..=19 => "benign / low interest",
        20..=39 => "suspicious",
        40..=69 => "likely malicious tooling",
        70..=89 => "high risk",
        _ => "critical",
    }
}

fn is_network_cap(id: &str) -> bool {
    matches!(
        id,
        "smb_enum" | "socket_client" | "http_client" | "c2_suspect"
    )
}

/// Pick up to 3 capability ids for the ranking label: highest confidence first,
/// then prefer including one network-class tag when present so Conti-style SMB
/// discovery is visible beside crypto/file_drop.
fn label_capability_ids(capabilities: &[CapabilityTag]) -> Vec<&str> {
    if capabilities.is_empty() {
        return Vec::new();
    }
    let mut chosen: Vec<&str> = Vec::with_capacity(3);
    chosen.push(capabilities[0].id.as_str());

    if let Some(net) = capabilities
        .iter()
        .find(|c| is_network_cap(&c.id) && c.id != chosen[0])
    {
        chosen.push(net.id.as_str());
    }

    for cap in capabilities.iter().skip(1) {
        if chosen.len() >= 3 {
            break;
        }
        if chosen.contains(&cap.id.as_str()) {
            continue;
        }
        chosen.push(cap.id.as_str());
    }
    chosen
}

/// Build prose from matched capabilities / behaviors so a score of 93 cannot
/// claim "injection / hollow" when those patterns were never hit.
fn compose_label(
    score: u8,
    capabilities: &[CapabilityTag],
    behaviors: &[BehaviorMatch],
) -> String {
    let band = risk_band(score);
    let top = label_capability_ids(capabilities);
    if !top.is_empty() {
        return format!("{band} — {}", top.join("/"));
    }
    if !behaviors.is_empty() {
        let top: Vec<_> = behaviors.iter().take(2).map(|b| b.name.as_str()).collect();
        return format!("{band} — {}", top.join("/"));
    }
    band.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triage::ImportEntry;

    fn imports(fns: &[&str]) -> Vec<ImportEntry> {
        fns.iter()
            .map(|f| ImportEntry {
                library: "kernel32.dll".into(),
                function: (*f).into(),
            })
            .collect()
    }

    #[test]
    fn send_does_not_match_send_message() {
        assert!(api_matches("send", "send"));
        assert!(api_matches("sendA", "send"));
        assert!(!api_matches("SendMessageA", "send"));
        assert!(!api_matches("HttpSendRequestA", "send"));
    }

    #[test]
    fn create_service_matches_ansi_wide() {
        assert!(api_matches("CreateServiceA", "CreateService"));
        assert!(api_matches("StartServiceW", "StartService"));
    }

    #[test]
    fn virtual_alloc_does_not_match_virtual_alloc_ex() {
        assert!(!api_matches("VirtualAlloc", "VirtualAllocEx"));
        assert!(!api_matches("VirtualAllocA", "VirtualAllocEx"));
        assert!(api_matches("VirtualAllocEx", "VirtualAllocEx"));
        assert!(api_matches("VirtualAllocExW", "VirtualAllocEx"));
        assert!(!api_matches("LoadLibraryExW", "LoadLibrary"));
        assert!(api_matches("LoadLibraryExW", "LoadLibraryEx"));
    }

    #[test]
    fn virtual_alloc_alone_is_not_injection() {
        let score = score_imports(&imports(&[
            "VirtualAlloc",
            "QueryPerformanceCounter",
            "IsDebuggerPresent",
            "GetProcAddress",
            "LoadLibraryExW",
            "CryptAcquireContextA",
            "CryptDecrypt",
            "CryptImportKey",
            "CreateFileW",
            "WriteFile",
            "NetShareEnum",
        ]));
        assert!(
            !score.capabilities.iter().any(|c| c.id == "injection"),
            "VirtualAlloc must not tag injection: {:?}",
            score.capabilities
        );
        assert!(
            score.capabilities.iter().any(|c| c.id == "smb_enum"),
            "expected smb_enum: {:?}",
            score.capabilities
        );
        assert!(
            score.label.contains("smb_enum"),
            "label should surface smb_enum: {}",
            score.label
        );
        assert!(
            !score.label.to_ascii_lowercase().contains("injection"),
            "label invented injection: {}",
            score.label
        );
    }

    #[test]
    fn virtual_alloc_ex_plus_write_still_tags_injection() {
        let score = score_imports(&imports(&[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ]));
        assert!(
            score.capabilities.iter().any(|c| c.id == "injection"),
            "classic triad should tag injection: {:?}",
            score.capabilities
        );
        assert!(score.score >= 70, "injection triad score too low: {}", score.score);
    }

    #[test]
    fn risk_label_never_invents_injection() {
        // High score from crypto + persistence — must not say injection/hollow.
        let score = score_imports(&imports(&[
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptAcquireContextA",
            "CreateServiceA",
            "StartServiceA",
            "CreateFileA",
            "WriteFile",
            "DeleteFileA",
            "FindFirstFileA",
        ]));
        assert!(score.score >= 70, "expected high score, got {}", score.score);
        assert!(
            !score.label.to_ascii_lowercase().contains("injection"),
            "label invented injection: {}",
            score.label
        );
        assert!(
            !score.label.to_ascii_lowercase().contains("hollow"),
            "label invented hollow: {}",
            score.label
        );
    }

    #[test]
    fn send_message_alone_is_not_socket_c2() {
        let score = score_imports(&imports(&["SendMessageA", "GetMessageA", "DispatchMessageA"]));
        assert!(
            !score.capabilities.iter().any(|c| c.id == "socket_client" || c.id == "c2_suspect"),
            "SendMessage must not tag network/C2: {:?}",
            score.capabilities
        );
        assert!(score.score < 20, "UI-only imports scored too high: {}", score.score);
    }

    #[test]
    fn mass_file_delete_scores_taskdl_style() {
        let score = score_imports(&imports(&[
            "FindFirstFileW",
            "FindNextFileW",
            "DeleteFileW",
            "MoveFileExW",
        ]));
        assert!(score.score >= 55, "taskdl-style helper scored {}", score.score);
        assert!(
            score.behaviors.iter().any(|b| b.name == "mass_file_delete"),
            "missing mass_file_delete: {:?}",
            score.behaviors
        );
    }

    #[test]
    fn unix_socket_bot_scores_mirai_style() {
        let score = score_imports(&imports(&["socket", "connect", "send", "recv", "fork"]));
        assert!(score.score >= 65, "Mirai-style ELF scored {}", score.score);
        assert!(
            score.capabilities.iter().any(|c| c.id == "socket_client"),
            "expected socket_client: {:?}",
            score.capabilities
        );
    }
}
