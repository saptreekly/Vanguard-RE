//! CAPA-style capability tags derived from the import table.

use super::api_matches;
use crate::triage::ImportEntry;

/// A high-level capability inferred from imported APIs.
#[derive(Debug, Clone)]
pub struct CapabilityTag {
    /// Stable id: `injection`, `socket_client`, `persistence`, …
    pub id: String,
    pub label: String,
    /// 0–100 confidence from evidence density.
    pub confidence: u8,
    pub evidence: Vec<String>,
}

struct CapRule {
    id: &'static str,
    label: &'static str,
    /// Exact API names (Win32 A/W/Ex suffixes normalized via `api_matches`).
    apis: &'static [&'static str],
    /// Minimum distinct evidence hits to emit the tag.
    min_hits: usize,
}

const RULES: &[CapRule] = &[
    CapRule {
        id: "injection",
        label: "Process injection",
        apis: &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtCreateThreadEx",
            "QueueUserAPC",
            "SetThreadContext",
            "RtlCreateUserThread",
            "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection",
            "NtMapViewOfSection",
            "VirtualProtectEx",
        ],
        // Classic triad needs corroboration — a lone VirtualAllocEx is common CRT.
        min_hits: 2,
    },
    CapRule {
        id: "http_client",
        label: "HTTP client",
        apis: &[
            "InternetOpen",
            "InternetConnect",
            "HttpSendRequest",
            "HttpOpenRequest",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpSendRequest",
            "URLDownloadToFile",
        ],
        min_hits: 1,
    },
    CapRule {
        id: "socket_client",
        label: "Socket client",
        apis: &[
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
            "WSASend",
            "WSARecv",
            "WSAConnect",
        ],
        // Require two hits so a lone UI API can never tag networking.
        min_hits: 2,
    },
    CapRule {
        id: "smb_enum",
        label: "SMB / share discovery",
        apis: &[
            "NetShareEnum",
            "WNetEnumResource",
            "NetServerEnum",
            "WNetAddConnection",
            "NetUseAdd",
        ],
        min_hits: 1,
    },
    CapRule {
        id: "c2_suspect",
        label: "C2-suspect HTTP",
        // Stronger than a bare socket — download-to-file or multi-API WinINet.
        apis: &[
            "URLDownloadToFile",
            "InternetOpen",
            "HttpSendRequest",
            "WinHttpSendRequest",
            "InternetReadFile",
        ],
        min_hits: 2,
    },
    CapRule {
        id: "persistence",
        label: "Persistence",
        apis: &[
            "RegSetValueEx",
            "RegCreateKeyEx",
            "CreateService",
            "StartService",
            "ITaskService",
            "SchTasks",
            "SetFileAttributes",
        ],
        min_hits: 1,
    },
    CapRule {
        id: "anti_debug",
        label: "Anti-debug / anti-analysis",
        apis: &[
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugString",
            "NtSetInformationThread",
        ],
        min_hits: 1,
    },
    CapRule {
        id: "crypto",
        label: "Crypto / encoding",
        apis: &[
            "CryptEncrypt",
            "CryptDecrypt",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "CryptAcquireContext",
            "CryptGenKey",
            "CryptImportKey",
            "CryptStringToBinary",
            "SystemFunction032",
        ],
        min_hits: 1,
    },
    CapRule {
        id: "keylog",
        label: "Keylogging / input capture",
        apis: &[
            "SetWindowsHookEx",
            "GetAsyncKeyState",
            "GetKeyState",
            "GetKeyboardState",
            "MapVirtualKey",
        ],
        min_hits: 1,
    },
    CapRule {
        id: "screenshot",
        label: "Screen / desktop capture",
        apis: &["BitBlt", "GetDC", "CreateCompatibleBitmap", "GetDesktopWindow", "PrintWindow"],
        min_hits: 1,
    },
    CapRule {
        id: "privilege",
        label: "Privilege / token abuse",
        apis: &[
            "AdjustTokenPrivileges",
            "LookupPrivilegeValue",
            "OpenProcessToken",
            "DuplicateToken",
            "ImpersonateLoggedOnUser",
        ],
        min_hits: 1,
    },
    CapRule {
        id: "dyn_resolve",
        label: "Dynamic API resolve",
        apis: &[
            "LoadLibrary",
            "LoadLibraryEx",
            "GetProcAddress",
            "LdrLoadDll",
            "LdrGetProcedureAddress",
        ],
        min_hits: 2,
    },
    CapRule {
        id: "process_enum",
        label: "Process discovery",
        apis: &[
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32Next",
            "EnumProcesses",
            "NtQuerySystemInformation",
            "OpenProcess",
        ],
        min_hits: 1,
    },
    CapRule {
        id: "file_drop",
        label: "File drop / write",
        apis: &[
            "CreateFile",
            "WriteFile",
            "CopyFile",
            "MoveFile",
            "DeleteFile",
            "URLDownloadToFile",
        ],
        min_hits: 2,
    },
    CapRule {
        id: "file_delete",
        label: "File deletion",
        apis: &["DeleteFile", "RemoveDirectory", "MoveFileEx"],
        min_hits: 1,
    },
    CapRule {
        id: "exec",
        label: "Process execution",
        apis: &[
            "CreateProcess",
            "WinExec",
            "ShellExecute",
            "NtCreateUserProcess",
            "system",
            "execl",
            "execv",
            "fork",
        ],
        min_hits: 1,
    },
];

fn api_names(imports: &[ImportEntry]) -> Vec<String> {
    imports
        .iter()
        .map(|i| i.function.clone())
        .filter(|f| f != "*" && !f.is_empty())
        .collect()
}

/// Tag capabilities from imports (CAPA-style summary for triage).
pub fn tag_capabilities(imports: &[ImportEntry]) -> Vec<CapabilityTag> {
    let apis = api_names(imports);
    let mut tags = Vec::new();

    for rule in RULES {
        let mut evidence = Vec::new();
        for api in &apis {
            for needle in rule.apis {
                if api_matches(api, needle) {
                    evidence.push(api.clone());
                    break;
                }
            }
        }
        evidence.sort();
        evidence.dedup();
        if evidence.len() < rule.min_hits {
            continue;
        }
        // Confidence: base 40 + 12 per evidence hit, capped.
        let confidence = (40u8)
            .saturating_add((evidence.len().min(5) as u8).saturating_mul(12))
            .min(100);
        tags.push(CapabilityTag {
            id: rule.id.into(),
            label: rule.label.into(),
            confidence,
            evidence,
        });
    }

    tags.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.id.cmp(&b.id)));
    tags
}

/// Compact display list: `injection · socket_client · persistence`
pub fn capability_summary(tags: &[CapabilityTag]) -> String {
    if tags.is_empty() {
        return "(none)".into();
    }
    tags.iter()
        .take(8)
        .map(|t| t.id.as_str())
        .collect::<Vec<_>>()
        .join(" · ")
}
