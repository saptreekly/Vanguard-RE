//! High-speed static disassembler (iced-x86) + function recovery + strings.

mod analysis;
mod cluster;

pub use analysis::CodeInsight;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, FormatterOutput, FormatterTextKind,
    Instruction, NasmFormatter, OpKind,
};
use crate::triage::{parse_binary, BinaryFormat, ParsedBinary};

use cluster::{choose_k, function_features, kmeans, label_cluster, FEATURE_DIM};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    Fallthrough,
    Call,
    Jump,
    CondJump,
    Return,
    Interrupt,
    Other,
}

/// Coarse token classes for syntax highlighting (mapped from iced-x86).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Mnemonic,
    Register,
    Number,
    Keyword,
    Punct,
    Address,
    Text,
}

#[derive(Debug, Clone)]
pub struct DisasmLine {
    pub address: u64,
    pub bytes: String,
    pub text: String,
    /// Formatter tokens for syntax highlighting; concatenation equals `text`.
    pub tokens: Vec<(String, TokenKind)>,
    pub anti_debug: bool,
    pub flow: FlowKind,
    /// Near/branch target when statically resolvable.
    pub branch_target: Option<u64>,
    pub is_function_start: bool,
}

/// Collects formatter output as plain text plus typed tokens.
#[derive(Default)]
struct TokenSink {
    text: String,
    tokens: Vec<(String, TokenKind)>,
}

impl TokenSink {
    fn clear(&mut self) {
        self.text.clear();
        self.tokens.clear();
    }
}

impl FormatterOutput for TokenSink {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        self.text.push_str(text);
        let k = match kind {
            FormatterTextKind::Mnemonic | FormatterTextKind::Prefix => TokenKind::Mnemonic,
            FormatterTextKind::Register => TokenKind::Register,
            FormatterTextKind::Number => TokenKind::Number,
            FormatterTextKind::Keyword
            | FormatterTextKind::Directive
            | FormatterTextKind::Decorator
            | FormatterTextKind::SelectorValue => TokenKind::Keyword,
            FormatterTextKind::Operator | FormatterTextKind::Punctuation => TokenKind::Punct,
            FormatterTextKind::LabelAddress
            | FormatterTextKind::FunctionAddress
            | FormatterTextKind::Label
            | FormatterTextKind::Function => TokenKind::Address,
            _ => TokenKind::Text,
        };
        // Merge adjacent same-kind fragments (whitespace, multi-part operands).
        if let Some((last, lk)) = self.tokens.last_mut() {
            if *lk == k {
                last.push_str(text);
                return;
            }
        }
        self.tokens.push((text.to_string(), k));
    }
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub start: u64,
    pub end: u64,
    /// Inclusive index range into [`DisasmReport::instructions`].
    pub insn_start: usize,
    pub insn_end: usize,
    pub callees: Vec<u64>,
    pub callers: Vec<u64>,
    /// 0–100 analyst interest (calls, anti-debug, string xrefs, entry).
    pub interest: u8,
    /// k-means cluster id (within this binary).
    pub cluster_id: u8,
    pub cluster_label: String,
}

#[derive(Debug, Clone)]
pub struct FunctionCluster {
    pub id: u8,
    pub label: String,
    pub members: Vec<String>,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: String,
    pub value: String,
    /// Code offsets that contain an immediate / displacement referencing this string RVA/offset.
    pub xrefs: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct DisasmReport {
    pub path: String,
    pub architecture: String,
    pub start_address: u64,
    pub instructions: Vec<DisasmLine>,
    pub functions: Vec<FunctionInfo>,
    /// Visual clustering layer over recovered functions.
    pub clusters: Vec<FunctionCluster>,
    pub strings: Vec<ExtractedString>,
    /// Automated code-pattern findings (PEB access, API hashing, XOR loops, …).
    pub insights: Vec<CodeInsight>,
}

/// Anti-debug / anti-analysis mnemonics we flag during linear decode.
fn is_anti_debug(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("rdtsc")
        || t.contains("rdtscp")
        || t.contains("cpuid")
        || t.contains("int3")
        || t.contains("icebp")
        || t.contains("sidt")
        || t.contains("sgdt")
        || t.contains("sldt")
}

fn classify_flow(instr: &Instruction) -> (FlowKind, Option<u64>) {
    let target = match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instr.near_branch_target())
        }
        _ => None,
    };
    let flow = match instr.flow_control() {
        FlowControl::Next => FlowKind::Fallthrough,
        FlowControl::Call => FlowKind::Call,
        FlowControl::UnconditionalBranch => FlowKind::Jump,
        FlowControl::ConditionalBranch => FlowKind::CondJump,
        FlowControl::Return => FlowKind::Return,
        FlowControl::Interrupt => FlowKind::Interrupt,
        _ => FlowKind::Other,
    };
    (flow, target)
}

/// Map a virtual address to `(absolute_file_offset, bytes_from_there, ip)`.
fn locate_va<'a>(
    data: &'a [u8],
    binary: &ParsedBinary,
    va: u64,
) -> Result<(usize, &'a [u8], u64)> {
    for sec in &binary.sections {
        let start = sec.virtual_address;
        let span = sec.virtual_size.max(sec.raw_size).max(1);
        if va >= start && va < start.saturating_add(span) {
            let delta = va - start;
            let off = (binary.image_file_offset as usize)
                .saturating_add(sec.file_offset as usize)
                .saturating_add(delta as usize);
            if off < data.len() {
                return Ok((off, &data[off..], va));
            }
        }
    }

    let off = (binary.image_file_offset as usize).saturating_add(va as usize);
    if off < data.len() {
        return Ok((off, &data[off..], va));
    }
    bail!("cannot map address {va:#x} into file");
}

fn find_pe_raw_offset(data: &[u8], rva: u64) -> Option<usize> {
    let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(data) else {
        return None;
    };
    for s in &pe.sections {
        let start = u64::from(s.virtual_address);
        let size = u64::from(s.virtual_size).max(u64::from(s.size_of_raw_data));
        if rva >= start && rva < start + size {
            let delta = (rva - start) as usize;
            let off = s.pointer_to_raw_data as usize + delta;
            if off < data.len() {
                return Some(off);
            }
        }
    }
    None
}

pub fn disassemble(
    path: &str,
    data: &[u8],
    start_va: Option<u64>,
    count: usize,
    with_strings: bool,
) -> Result<DisasmReport> {
    let binary = parse_binary(data, false)?;
    let start = start_va.unwrap_or(binary.entry_point);

    let bitness: u32 = if matches!(binary.format, BinaryFormat::DosCom) {
        16
    } else if binary.is_64bit {
        64
    } else {
        32
    };
    if matches!(binary.architecture.as_str(), "aarch64" | "arm" | "mips") {
        bail!(
            "architecture '{}' needs the Capstone backend (scaffold); iced-x86 covers x86/x64/16-bit",
            binary.architecture
        );
    }

    let (file_off, slice, ip) = match locate_va(data, &binary, start) {
        Ok(v) => v,
        Err(_) if binary.format == BinaryFormat::Pe => {
            let off = find_pe_raw_offset(data, start)
                .with_context(|| format!("locate PE RVA {start:#x}"))?;
            (off, &data[off..], start)
        }
        Err(e) => return Err(e).with_context(|| format!("locate start VA {start:#x}")),
    };

    let mut decoder = Decoder::with_ip(bitness, slice, ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_uppercase_mnemonics(false);
    formatter.options_mut().set_first_operand_char_index(8);

    let mut instructions = Vec::with_capacity(count);
    let mut instr = Instruction::default();
    let mut sink = TokenSink::default();

    for _ in 0..count {
        if !decoder.can_decode() {
            break;
        }
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }

        sink.clear();
        formatter.format(&instr, &mut sink);

        let start_idx = (instr.ip() - ip) as usize + file_off;
        let end_idx = start_idx + instr.len();
        let raw = data.get(start_idx..end_idx.min(data.len())).unwrap_or(&[]);
        let bytes = hex::encode(raw);

        let (flow, branch_target) = classify_flow(&instr);
        let anti = is_anti_debug(&sink.text);
        instructions.push(DisasmLine {
            address: instr.ip(),
            bytes,
            text: sink.text.clone(),
            tokens: std::mem::take(&mut sink.tokens),
            anti_debug: anti,
            flow,
            branch_target,
            is_function_start: false,
        });
    }

    let mut functions = recover_functions(&mut instructions, start, &binary.exports);
    let strings = if with_strings {
        extract_strings_with_xrefs(data, &instructions)
    } else {
        Vec::new()
    };
    rank_functions(&instructions, &mut functions, &strings, start);
    let clusters = cluster_functions(&instructions, &mut functions);
    let insights = analysis::analyze(&instructions);

    // Surface interesting functions first (keep entry near top via interest bump).
    functions.sort_by(|a, b| {
        b.interest
            .cmp(&a.interest)
            .then(a.start.cmp(&b.start))
    });

    Ok(DisasmReport {
        path: path.to_string(),
        architecture: binary.architecture,
        start_address: start,
        instructions,
        functions,
        clusters,
        strings,
        insights,
    })
}

/// Recover function boundaries from entry + near CALL targets within the decode window.
fn recover_functions(
    instructions: &mut [DisasmLine],
    entry: u64,
    exports: &[String],
) -> Vec<FunctionInfo> {
    if instructions.is_empty() {
        return Vec::new();
    }

    let addr_to_idx: BTreeMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, l)| (l.address, i))
        .collect();

    let min_addr = instructions.first().map(|l| l.address).unwrap_or(0);
    let max_addr = instructions.last().map(|l| l.address).unwrap_or(0);

    let mut starts: BTreeSet<u64> = BTreeSet::new();
    if entry >= min_addr && entry <= max_addr {
        starts.insert(entry);
    } else if let Some(first) = instructions.first() {
        starts.insert(first.address);
    }

    for line in instructions.iter() {
        if line.flow == FlowKind::Call {
            if let Some(t) = line.branch_target {
                if addr_to_idx.contains_key(&t) {
                    starts.insert(t);
                }
            }
        }
    }

    // Mark starts on instruction list.
    for s in &starts {
        if let Some(&idx) = addr_to_idx.get(s) {
            instructions[idx].is_function_start = true;
        }
    }

    let start_list: Vec<u64> = starts.into_iter().collect();
    let mut functions = Vec::with_capacity(start_list.len());

    for (fi, &start_addr) in start_list.iter().enumerate() {
        let Some(&insn_start) = addr_to_idx.get(&start_addr) else {
            continue;
        };
        let insn_end = start_list
            .get(fi + 1)
            .and_then(|next| addr_to_idx.get(next).copied())
            .map(|n| n.saturating_sub(1))
            .unwrap_or(instructions.len().saturating_sub(1))
            .max(insn_start);

        let end = insn_end;

        let mut callees = Vec::new();
        for line in &instructions[insn_start..=end] {
            if line.flow == FlowKind::Call {
                if let Some(t) = line.branch_target {
                    if addr_to_idx.contains_key(&t) {
                        callees.push(t);
                    }
                }
            }
        }
        callees.sort_unstable();
        callees.dedup();

        let name = if start_addr == entry {
            "entry".into()
        } else if let Some(exp) = exports.iter().find(|e| {
            // best-effort: export name hint only when address matches aren't available
            e.contains(&format!("{start_addr:x}"))
        }) {
            exp.clone()
        } else {
            format!("sub_{start_addr:x}")
        };

        functions.push(FunctionInfo {
            name,
            start: start_addr,
            end: instructions[end].address,
            insn_start,
            insn_end: end,
            callees,
            callers: Vec::new(),
            interest: 0,
            cluster_id: 0,
            cluster_label: String::new(),
        });
    }

    // Fill callers from call sites.
    let start_set: BTreeSet<u64> = functions.iter().map(|f| f.start).collect();
    for f in &mut functions {
        let mut callers = Vec::new();
        for line in instructions.iter() {
            if line.flow == FlowKind::Call && line.branch_target == Some(f.start) {
                callers.push(line.address);
            }
        }
        callers.sort_unstable();
        callers.dedup();
        f.callers = callers;
        // Drop callees outside known functions (already filtered) — keep only known starts
        f.callees.retain(|c| start_set.contains(c));
    }

    functions.sort_by_key(|f| f.start);
    functions
}

/// Score functions for analyst interest (higher = look here first).
fn rank_functions(
    instructions: &[DisasmLine],
    functions: &mut [FunctionInfo],
    strings: &[ExtractedString],
    entry: u64,
) {
    for f in functions.iter_mut() {
        let slice = &instructions[f.insn_start..=f.insn_end];
        let mut score: u32 = 0;

        let mut calls = 0u32;
        let mut anti = 0u32;
        for line in slice {
            if line.flow == FlowKind::Call {
                calls += 1;
            }
            if line.anti_debug {
                anti += 1;
            }
        }

        score += calls.min(12) * 5;
        score += anti.min(6) * 18;
        score += f.callees.len().min(8) as u32 * 4;
        score += f.callers.len().min(8) as u32 * 3;

        let xref_hits = strings
            .iter()
            .filter(|s| {
                s.xrefs
                    .iter()
                    .any(|&x| x >= f.start && x <= f.end)
            })
            .count() as u32;
        score += xref_hits.min(10) * 8;

        if f.start == entry || f.name == "entry" {
            score += 25;
        }

        // Tiny stubs are less interesting unless anti-debug.
        let len = slice.len() as u32;
        if len <= 3 && anti == 0 {
            score = score.saturating_sub(15);
        }

        f.interest = score.min(100) as u8;
    }
}

/// k-means over function feature vectors; labels clusters for the TUI.
fn cluster_functions(
    instructions: &[DisasmLine],
    functions: &mut [FunctionInfo],
) -> Vec<FunctionCluster> {
    if functions.is_empty() {
        return Vec::new();
    }

    let features: Vec<[f32; FEATURE_DIM]> = functions
        .iter()
        .map(|f| function_features(instructions, f))
        .collect();

    let k = choose_k(functions.len());
    let assign = kmeans(&features, k, 25);

    for (i, f) in functions.iter_mut().enumerate() {
        f.cluster_id = assign.get(i).copied().unwrap_or(0) as u8;
    }

    let mut clusters = Vec::new();
    for cid in 0..k {
        let member_feats: Vec<[f32; FEATURE_DIM]> = assign
            .iter()
            .enumerate()
            .filter(|(_, a)| **a == cid)
            .map(|(i, _)| features[i])
            .collect();
        let label = label_cluster(&member_feats);
        let members: Vec<String> = functions
            .iter()
            .filter(|f| f.cluster_id as usize == cid)
            .map(|f| f.name.clone())
            .collect();
        let size = members.len();
        for f in functions.iter_mut().filter(|f| f.cluster_id as usize == cid) {
            f.cluster_label = label.clone();
        }
        if size > 0 {
            clusters.push(FunctionCluster {
                id: cid as u8,
                label,
                members,
                size,
            });
        }
    }

    clusters.sort_by_key(|c| c.id);
    clusters
}

/// Index of the highest-interest function (for explorer auto-jump).
pub fn most_interesting_fn(functions: &[FunctionInfo]) -> usize {
    functions
        .iter()
        .enumerate()
        .max_by_key(|(_, f)| f.interest)
        .map(|(i, _)| i)
        .unwrap_or(0)
}

/// Resolve a function name for a target address, if known.
pub fn function_name_at(functions: &[FunctionInfo], addr: u64) -> Option<&str> {
    functions
        .iter()
        .find(|f| f.start == addr)
        .map(|f| f.name.as_str())
}

fn extract_strings_with_xrefs(data: &[u8], instructions: &[DisasmLine]) -> Vec<ExtractedString> {
    let mut strings = extract_strings_only(data);

    for s in &mut strings {
        let needle = format!("{:x}", s.offset);
        for insn in instructions {
            if insn.text.contains(&needle) || insn.bytes.contains(&needle) {
                s.xrefs.push(insn.address);
            }
        }
        s.xrefs.sort_unstable();
        s.xrefs.dedup();
    }

    // Prefer strings that have code xrefs, then length — never the first-N of file order.
    strings.sort_by(|a, b| {
        b.xrefs
            .len()
            .cmp(&a.xrefs.len())
            .then(b.value.len().cmp(&a.value.len()))
    });
    strings.truncate(500);
    strings
}

/// Extract ASCII + UTF-16LE strings without disassembly.
///
/// Packed / high-entropy binaries produce thousands of short printable runs.
/// We score candidates and keep the best `cap` rather than truncating in file
/// order (which buried WannaCry-style C2 domains under packer noise).
pub fn extract_strings_only(data: &[u8]) -> Vec<ExtractedString> {
    extract_strings_ranked(data, 8000)
}

/// Ranked string extraction with an explicit retention cap.
pub fn extract_strings_ranked(data: &[u8], cap: usize) -> Vec<ExtractedString> {
    // min_len 6 skips most 5-char entropy noise; UTF-16 same.
    let mut strings = extract_ascii_strings(data, 6);
    strings.extend(extract_utf16le_strings(data, 6));

    strings.sort_by(|a, b| {
        string_quality(&b.value)
            .cmp(&string_quality(&a.value))
            .then(b.value.len().cmp(&a.value.len()))
            .then(a.offset.cmp(&b.offset))
    });
    strings.dedup_by(|a, b| a.value == b.value);
    strings.truncate(cap);
    strings
}

/// Higher = more likely a real analyst-useful string (vs packer printable noise).
fn string_quality(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let len = bytes.len() as u32;
    if len < 6 {
        return 0;
    }
    let letters = bytes.iter().filter(|b| b.is_ascii_alphabetic()).count() as u32;
    let digits = bytes.iter().filter(|b| b.is_ascii_digit()).count() as u32;
    let spaces = bytes.iter().filter(|&&b| b == b' ').count() as u32;
    let punct = len.saturating_sub(letters + digits + spaces);
    let letter_ratio = letters * 100 / len;

    let mut score = len.min(80);
    // Prefer alphabetic content (domains, paths, API names).
    score += letter_ratio / 2;
    // Paths / URLs / registry keys.
    if s.contains('\\') || s.contains('/') || s.contains(':') {
        score += 40;
    }
    if s.contains('.') {
        score += 15;
    }
    // DLL / EXE / service-ish.
    let lower = s.to_ascii_lowercase();
    if lower.ends_with(".dll")
        || lower.ends_with(".exe")
        || lower.ends_with(".sys")
        || lower.contains("http")
        || lower.contains(".onion")
        || lower.contains("bitcoin")
        || lower.contains("wallet")
        || lower.contains("encrypt")
        || lower.contains("ransom")
    {
        score += 80;
    }
    // Penalize mostly-digit or mostly-punct runs (entropy leftovers).
    if digits * 2 > letters {
        score = score.saturating_sub(30);
    }
    if punct * 2 > letters + digits {
        score = score.saturating_sub(40);
    }
    // Very long random alphabetic domains (kill-switch style) are valuable.
    if letter_ratio >= 85 && len >= 24 && s.contains('.') {
        score += 50;
    }
    score
}

/// Keep IOC-ish / analyst-interesting strings only.
pub fn interesting_strings(all: &[ExtractedString]) -> Vec<ExtractedString> {
    let mut out: Vec<_> = all
        .iter()
        .filter(|s| is_interesting(&s.value))
        .cloned()
        .collect();
    out.sort_by(|a, b| {
        string_quality(&b.value)
            .cmp(&string_quality(&a.value))
            .then(b.value.len().cmp(&a.value.len()))
    });
    out.truncate(120);
    out
}

fn is_interesting(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if s.len() < 6 || s.len() > 400 {
        return false;
    }
    if lower.starts_with("abcdefghijklmnopqrstuvwxyz")
        || lower.contains("runtime error")
        || lower.contains("this program cannot be run")
        || lower.contains("schemas.microsoft.com")
        || lower.contains("xmlns")
    {
        return false;
    }
    // Import / module names (KERNEL32.dll etc.).
    if lower.ends_with(".dll")
        || lower.ends_with(".exe")
        || lower.ends_with(".sys")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd")
        || lower.ends_with(".ps1")
        || lower.ends_with(".vbs")
    {
        return true;
    }
    // Ransomware / crypto / persistence / C2 keywords.
    const KEYWORDS: &[&str] = &[
        "http://",
        "https://",
        "ftp://",
        ".onion",
        "discord.com",
        "telegram",
        "webhook",
        "electrora",
        "keylog",
        "screenshot",
        "webcam",
        "password",
        "wallet",
        "bitcoin",
        "btc",
        "ransom",
        "encrypt",
        "decrypt",
        "cmd.exe",
        "powershell",
        "wscript",
        "cscript",
        "appdata",
        "\\temp",
        "/temp",
        "hkey_",
        "software\\",
        "currentversion\\run",
        "mozill",
        "chrome",
        "login data",
        "user-agent",
        "api/",
        "createfile",
        "writefile",
        "virtualalloc",
        "loadlibrary",
        "getprocaddress",
        "internetopen",
        "httpsend",
        "wsasocket",
        "connect(",
        "smb",
        "ipc$",
        "admin$",
        "mssecsvc",
        "tasksche",
        "taskdl",
        "taskse",
        ".wnry",
        ".wry",
        "wanna",
        "wcry",
        "tor",
        "onion",
        "mutex",
        "service",
    ];
    if KEYWORDS.iter().any(|k| lower.contains(k)) {
        return true;
    }
    looks_like_ipv4(s) || looks_like_domain(s) || looks_like_killswitch_domain(s)
}

/// Long mostly-alpha domains (WannaCry kill-switch style).
fn looks_like_killswitch_domain(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower.len() < 20 || lower.len() > 80 || lower.contains(' ') {
        return false;
    }
    let host = lower.split('/').next().unwrap_or(&lower);
    let Some((name, tld)) = host.rsplit_once('.') else {
        return false;
    };
    matches!(tld, "com" | "net" | "org" | "info" | "biz" | "xyz" | "top")
        && name.len() >= 16
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && name.bytes().filter(|b| b.is_ascii_alphabetic()).count() * 100 / name.len() >= 80
}

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<_> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn looks_like_domain(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    (lower.contains(".com")
        || lower.contains(".net")
        || lower.contains(".org")
        || lower.contains(".io")
        || lower.contains(".ru")
        || lower.contains(".xyz")
        || lower.contains(".onion")
        || lower.contains(".info")
        || lower.contains(".biz")
        || lower.contains(".top"))
        && !lower.contains(' ')
        && lower.chars().filter(|c| *c == '.').count() >= 1
        && s.len() < 100
        && !lower.contains("schemas.microsoft.com")
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    let mut start = None;
    let flush = |s: usize, end: usize, out: &mut Vec<ExtractedString>| {
        if end - s >= min_len {
            if let Ok(v) = std::str::from_utf8(&data[s..end]) {
                out.push(ExtractedString {
                    offset: s as u64,
                    encoding: "ascii".into(),
                    value: v.to_string(),
                    xrefs: Vec::new(),
                });
            }
        }
    };
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..=0x7e).contains(&b);
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            flush(s, i, &mut out);
        }
    }
    // Flush a run that reaches the end of the buffer.
    if let Some(s) = start.take() {
        flush(s, data.len(), &mut out);
    }
    out
}

fn extract_utf16le_strings(data: &[u8], min_chars: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let mut j = i;
        let mut chars = Vec::new();
        while j + 1 < data.len() {
            let lo = data[j];
            let hi = data[j + 1];
            if hi == 0 && (0x20..=0x7e).contains(&lo) {
                chars.push(lo as char);
                j += 2;
            } else {
                break;
            }
        }
        if chars.len() >= min_chars {
            out.push(ExtractedString {
                offset: i as u64,
                encoding: "utf16le".into(),
                value: chars.iter().collect(),
                xrefs: Vec::new(),
            });
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Demangle-ish filter without heavy demangler crates.
/// Returns mangled-looking symbols for triage; full demangle is optional later.
pub fn demangle_symbols(symbols: &[String]) -> Vec<String> {
    symbols
        .iter()
        .filter(|s| {
            !s.is_empty()
                && (s.starts_with("_Z")
                    || s.starts_with("__Z")
                    || s.starts_with("_R")
                    || s.starts_with("?"))
        })
        .take(100)
        .cloned()
        .collect()
}
