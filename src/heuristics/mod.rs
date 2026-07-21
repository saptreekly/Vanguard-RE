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
        name: "network_exfil",
        severity: 50,
        description: "Network client APIs (C2 / exfil capable)",
        required: &["InternetOpen", "HttpSendRequest"],
    },
    Pattern {
        name: "network_exfil_wininet",
        severity: 55,
        description: "WinINet connect + HTTP send (C2 capable)",
        required: &["InternetConnect", "HttpSendRequest"],
    },
    Pattern {
        name: "raw_socket_c2",
        severity: 60,
        description: "Raw Winsock client (socket + connect + send)",
        required: &["WSAStartup", "socket", "connect", "send"],
    },
    Pattern {
        name: "dynamic_api_resolve",
        severity: 40,
        description: "Dynamic API resolution (LoadLibrary + GetProcAddress)",
        required: &["LoadLibrary", "GetProcAddress"],
    },
    Pattern {
        name: "service_persistence",
        severity: 65,
        description: "Windows service creation for persistence",
        required: &["CreateService", "StartService"],
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

fn has_api(apis: &[String], needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    apis.iter()
        .any(|a| a.to_ascii_lowercase().contains(&needle))
}

/// Score a binary's import table against known malicious operational patterns.
pub fn score_imports(imports: &[ImportEntry]) -> ThreatScore {
    let apis = api_names(imports);

    let suspicious_apis: Vec<String> = apis
        .iter()
        .filter(|a| {
            let lower = a.to_ascii_lowercase();
            SUSPICIOUS_APIS
                .iter()
                .any(|s| lower.contains(&s.to_ascii_lowercase()))
        })
        .cloned()
        .collect();

    let mut behaviors = Vec::new();
    for pat in PATTERNS {
        if pat.required.iter().all(|r| has_api(&apis, r)) {
            let matched: Vec<String> = pat
                .required
                .iter()
                .filter_map(|r| {
                    apis.iter()
                        .find(|a| a.to_ascii_lowercase().contains(&r.to_ascii_lowercase()))
                        .cloned()
                })
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
            "c2" | "keylog" | "privilege" => 8,
            "persistence" | "crypto" | "anti_debug" => 6,
            _ => 3,
        })
        .fold(0u8, |a, b| a.saturating_add(b))
        .min(24);
    let score = max_sev
        .saturating_add(density_bump)
        .saturating_add(cap_bump)
        .min(100);

    let label = if !capabilities.is_empty() && score >= 40 {
        let top: Vec<_> = capabilities.iter().take(3).map(|c| c.id.as_str()).collect();
        format!("{} — {}", risk_label(score), top.join("/"))
    } else {
        risk_label(score).to_string()
    };

    ThreatScore {
        score,
        label,
        behaviors,
        suspicious_apis,
        capabilities,
    }
}

fn risk_label(score: u8) -> &'static str {
    match score {
        0..=19 => "benign / low interest",
        20..=39 => "suspicious",
        40..=69 => "likely malicious tooling",
        70..=89 => "high risk",
        _ => "critical — injection / hollow patterns",
    }
}
