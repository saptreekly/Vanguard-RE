//! Automated code-pattern analysis over recovered instructions.
//!
//! Complements import/string heuristics by reading the disassembly itself for
//! implementation-level techniques: PEB walking, API-name hashing loops,
//! inline XOR decryptors, stack-built strings, direct syscalls, register-
//! indirect dispatch, and GetPC/call-pop shellcode thunks. Purely static.

use std::collections::BTreeMap;

use super::{DisasmLine, FlowKind};

#[derive(Debug, Clone)]
pub struct CodeInsight {
    /// Stable id, e.g. `peb_access`, `api_hashing`.
    pub id: String,
    pub label: String,
    /// 0–100 analyst weight.
    pub severity: u8,
    /// Addresses where the pattern was observed (capped).
    pub hits: Vec<u64>,
}

const MAX_HITS: usize = 12;

struct Acc {
    order: Vec<&'static str>,
    map: BTreeMap<&'static str, (&'static str, u8, Vec<u64>)>,
}

impl Acc {
    fn new() -> Self {
        Self {
            order: Vec::new(),
            map: BTreeMap::new(),
        }
    }

    fn add(&mut self, id: &'static str, label: &'static str, severity: u8, addr: u64) {
        let entry = self.map.entry(id).or_insert_with(|| {
            self.order.push(id);
            (label, severity, Vec::new())
        });
        if entry.2.len() < MAX_HITS {
            entry.2.push(addr);
        }
    }

    fn finish(self) -> Vec<CodeInsight> {
        let mut out: Vec<CodeInsight> = self
            .order
            .iter()
            .map(|id| {
                let (label, severity, hits) = &self.map[id];
                CodeInsight {
                    id: (*id).to_string(),
                    label: (*label).to_string(),
                    severity: *severity,
                    hits: hits.clone(),
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.hits.len().cmp(&a.hits.len()))
        });
        out
    }
}

fn mnemonic(line: &DisasmLine) -> &str {
    line.text.split_whitespace().next().unwrap_or("")
}

/// Operands as trimmed, lowercased strings (`text` is already lowercase-mnemonic).
fn operands(line: &DisasmLine) -> Vec<String> {
    match line.text.find(char::is_whitespace) {
        Some(sp) => line.text[sp..]
            .trim()
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
        None => Vec::new(),
    }
}

/// True for a register-indirect operand (`eax`, `[eax]`, `[rbx+8]`) but not an
/// absolute memory cell (`[0x401000]`) — the latter is ordinary IAT/global use.
fn is_register_indirect(op: &str) -> bool {
    let inner = op
        .trim_start_matches(|c: char| c.is_alphabetic() || c == ' ')
        .trim();
    if let Some(stripped) = inner.strip_prefix('[') {
        let body = stripped.trim_end_matches(']');
        // Absolute address inside brackets → not dynamic dispatch.
        if body.starts_with("0x")
            || body
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == 'h' || c == 'x')
        {
            return false;
        }
        return true;
    }
    // Bare register: short alnum token, not a size keyword or address.
    let tok = op.split_whitespace().last().unwrap_or(op);
    !tok.is_empty()
        && tok.len() <= 4
        && tok.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && !matches!(tok, "short" | "near" | "far" | "byte" | "word")
        && !tok.contains("0x")
}

fn is_immediate(op: &str) -> bool {
    let t = op.trim();
    t.starts_with("0x")
        || t.chars().next().is_some_and(|c| c.is_ascii_digit())
        || (t.ends_with('h') && t.len() > 1 && t[..t.len() - 1].chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_stack_mem(op: &str) -> bool {
    op.contains("bp-") || op.contains("bp+") || op.contains("sp-") || op.contains("sp+")
}

/// Run the code-pattern pass. `instructions` is in decode (address) order.
pub fn analyze(instructions: &[DisasmLine]) -> Vec<CodeInsight> {
    if instructions.is_empty() {
        return Vec::new();
    }
    let addr_to_idx: BTreeMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, l)| (l.address, i))
        .collect();

    // Loop spans from backward branches: [target_idx, source_idx].
    let mut loop_spans: Vec<(usize, usize)> = Vec::new();
    for (i, line) in instructions.iter().enumerate() {
        if matches!(line.flow, FlowKind::CondJump | FlowKind::Jump) {
            if let Some(t) = line.branch_target {
                if t <= line.address {
                    if let Some(&ti) = addr_to_idx.get(&t) {
                        loop_spans.push((ti, i));
                    }
                }
            }
        }
    }
    let in_loop = |idx: usize| loop_spans.iter().any(|&(s, e)| idx >= s && idx <= e);

    let mut acc = Acc::new();
    let mut rot_in_loop: Vec<u64> = Vec::new();
    let mut xor_in_loop = false;
    let mut stack_run = 0usize;
    let mut stack_run_start = 0u64;

    for (i, line) in instructions.iter().enumerate() {
        let m = mnemonic(line);
        let ops = operands(line);

        // PEB/TEB segment access (fs:[0x30] / gs:[0x60]).
        if line.text.contains("fs:[") || line.text.contains("gs:[") {
            acc.add(
                "peb_access",
                "PEB/TEB access (fs/gs) — manual API resolution / anti-debug",
                60,
                line.address,
            );
        }

        // Direct syscalls (EDR/userland-hook evasion).
        if m == "syscall" || m == "sysenter" {
            acc.add(
                "direct_syscall",
                "direct syscall (syscall/sysenter) — userland-hook evasion",
                70,
                line.address,
            );
        } else if m == "int" && ops.first().is_some_and(|o| o == "2eh" || o == "0x2e") {
            acc.add(
                "direct_syscall",
                "direct syscall (int 2Eh) — legacy syscall gate",
                65,
                line.address,
            );
        }

        // GetPC / call-pop thunk: call to the immediately following instruction.
        if line.flow == FlowKind::Call {
            if let Some(t) = line.branch_target {
                if t == line.address + (line.bytes.len() as u64 / 2) {
                    acc.add(
                        "getpc_thunk",
                        "GetPC / call-pop thunk — position-independent shellcode",
                        55,
                        line.address,
                    );
                }
            }
        }

        // Register-indirect call/jump (dynamic API dispatch).
        if matches!(line.flow, FlowKind::Call | FlowKind::Jump)
            && line.branch_target.is_none()
            && ops.first().is_some_and(|o| is_register_indirect(o))
        {
            let sev = if line.flow == FlowKind::Call { 45 } else { 40 };
            acc.add(
                "indirect_dispatch",
                "register-indirect call/jump — dynamic API dispatch",
                sev,
                line.address,
            );
        }

        // Context save/restore (shellcode-style).
        if matches!(m, "pushad" | "popad" | "pushal" | "popal") {
            acc.add(
                "context_save",
                "pushad/popad — full context save (shellcode-style)",
                25,
                line.address,
            );
        }

        // Loop-body signals.
        if in_loop(i) {
            if m == "xor" && ops.len() == 2 && ops[0] != ops[1] {
                xor_in_loop = true;
                acc.add(
                    "xor_loop",
                    "XOR loop — inline decryption / string decoding",
                    55,
                    line.address,
                );
            }
            if matches!(m, "rol" | "ror" | "rcl" | "rcr") {
                rot_in_loop.push(line.address);
            }
        }

        // Stack-string construction: run of movs writing immediates to stack.
        let is_stack_store = m == "mov"
            && ops.len() == 2
            && is_stack_mem(&ops[0])
            && is_immediate(&ops[1]);
        if is_stack_store {
            if stack_run == 0 {
                stack_run_start = line.address;
            }
            stack_run += 1;
        } else {
            if stack_run >= 4 {
                acc.add(
                    "stack_strings",
                    "stack-built strings — obfuscated inline literals",
                    50,
                    stack_run_start,
                );
            }
            stack_run = 0;
        }
    }
    if stack_run >= 4 {
        acc.add(
            "stack_strings",
            "stack-built strings — obfuscated inline literals",
            50,
            stack_run_start,
        );
    }

    // API-name hashing: rotation(s) + XOR inside the same looping region.
    if xor_in_loop && !rot_in_loop.is_empty() {
        for a in rot_in_loop.into_iter().take(MAX_HITS) {
            acc.add(
                "api_hashing",
                "rotate+XOR hashing loop — API-name hashing",
                70,
                a,
            );
        }
    }

    acc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(addr: u64, text: &str, flow: FlowKind, target: Option<u64>) -> DisasmLine {
        DisasmLine {
            address: addr,
            bytes: "90".into(),
            text: text.to_string(),
            tokens: Vec::new(),
            anti_debug: false,
            flow,
            branch_target: target,
            is_function_start: false,
        }
    }

    #[test]
    fn flags_peb_access() {
        let ins = vec![line(0x1000, "mov     eax,fs:[0x30]", FlowKind::Fallthrough, None)];
        let out = analyze(&ins);
        assert!(out.iter().any(|i| i.id == "peb_access"));
    }

    #[test]
    fn flags_indirect_call_but_not_iat() {
        let ins = vec![
            line(0x10, "call    eax", FlowKind::Call, None),
            line(0x12, "call    [0x00401000]", FlowKind::Call, None),
        ];
        let out = analyze(&ins);
        let ind = out.iter().find(|i| i.id == "indirect_dispatch").unwrap();
        // Only the register-indirect call counts.
        assert_eq!(ind.hits, vec![0x10]);
    }

    #[test]
    fn detects_xor_loop_and_hashing() {
        // Backward CondJump at 0x20 -> 0x10 forms a loop over 0x10..=0x20.
        let ins = vec![
            line(0x10, "ror     edx,0dh", FlowKind::Fallthrough, None),
            line(0x14, "xor     eax,edx", FlowKind::Fallthrough, None),
            line(0x20, "jne     short 0x10", FlowKind::CondJump, Some(0x10)),
        ];
        let out = analyze(&ins);
        assert!(out.iter().any(|i| i.id == "xor_loop"));
        assert!(out.iter().any(|i| i.id == "api_hashing"));
    }

    #[test]
    fn detects_stack_strings() {
        let ins = vec![
            line(0x10, "mov     byte [ebp-4],48h", FlowKind::Fallthrough, None),
            line(0x14, "mov     byte [ebp-3],65h", FlowKind::Fallthrough, None),
            line(0x18, "mov     byte [ebp-2],6ch", FlowKind::Fallthrough, None),
            line(0x1c, "mov     byte [ebp-1],6ch", FlowKind::Fallthrough, None),
            line(0x20, "ret", FlowKind::Return, None),
        ];
        let out = analyze(&ins);
        assert!(out.iter().any(|i| i.id == "stack_strings"));
    }

    #[test]
    fn clean_code_is_quiet() {
        let ins = vec![
            line(0x10, "push    ebp", FlowKind::Fallthrough, None),
            line(0x11, "mov     ebp,esp", FlowKind::Fallthrough, None),
            line(0x13, "ret", FlowKind::Return, None),
        ];
        assert!(analyze(&ins).is_empty());
    }
}
