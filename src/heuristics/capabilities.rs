//! CAPA-style capability tags derived from the import table.

use crate::triage::ImportEntry;

/// A high-level capability inferred from imported APIs.
#[derive(Debug, Clone)]
pub struct CapabilityTag {
    /// Stable id: `injection`, `c2`, `persistence`, …
    pub id: String,
    pub label: String,
    /// 0–100 confidence from evidence density.
    pub confidence: u8,
    pub evidence: Vec<String>,
}

struct CapRule {
    id: &'static str,
    label: &'static str,
    /// Any of these substrings (case-insensitive) on the function name count as evidence.
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
        min_hits: 1,
    },
    CapRule {
        id: "c2",
        label: "Network / C2",
        apis: &[
            "InternetOpen",
            "InternetConnect",
            "HttpSendRequest",
            "HttpOpenRequest",
            "WinHttpOpen",
            "WinHttpConnect",
            "URLDownloadToFile",
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
            "WSASend",
            "WSARecv",
        ],
        min_hits: 1,
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
        apis: &["LoadLibrary", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"],
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
        id: "exec",
        label: "Process execution",
        apis: &[
            "CreateProcess",
            "WinExec",
            "ShellExecute",
            "NtCreateUserProcess",
            "system",
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

/// Tag capabilities from imports (CAPA-style summary for triage UI).
pub fn tag_capabilities(imports: &[ImportEntry]) -> Vec<CapabilityTag> {
    let apis = api_names(imports);
    let mut tags = Vec::new();

    for rule in RULES {
        let mut evidence = Vec::new();
        for api in &apis {
            let lower = api.to_ascii_lowercase();
            for needle in rule.apis {
                if lower.contains(&needle.to_ascii_lowercase()) {
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

/// Compact display list: `injection · c2 · persistence`
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
