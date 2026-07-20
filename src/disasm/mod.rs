//! High-speed static disassembler (iced-x86) + string extraction / back-trace.

use anyhow::{bail, Context, Result};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use serde::Serialize;

use crate::triage::{parse_binary, BinaryFormat, ParsedBinary};

#[derive(Debug, Clone, Serialize)]
pub struct DisasmLine {
    pub address: u64,
    pub bytes: String,
    pub text: String,
    pub anti_debug: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: String,
    pub value: String,
    /// Code offsets that contain an immediate / displacement referencing this string RVA/offset.
    pub xrefs: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisasmReport {
    pub path: String,
    pub architecture: String,
    pub start_address: u64,
    pub instructions: Vec<DisasmLine>,
    pub strings: Vec<ExtractedString>,
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

    // PE: entry is often an RVA; try image-base–relative if sections use VAs with high base
    if binary.format == BinaryFormat::Pe {
        for sec in &binary.sections {
            let start = sec.virtual_address;
            // If caller passed RVA (small) but sections store RVA already (goblin does),
            // the loop above should have hit. Fallback: treat as file offset.
            let _ = start;
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

    for _ in 0..count {
        if !decoder.can_decode() {
            break;
        }
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }

        let mut text = String::new();
        formatter.format(&instr, &mut text);

        let start_idx = (instr.ip() - ip) as usize + file_off;
        let end_idx = start_idx + instr.len();
        let raw = data.get(start_idx..end_idx.min(data.len())).unwrap_or(&[]);
        let bytes = hex::encode(raw);

        let anti = is_anti_debug(&text);
        instructions.push(DisasmLine {
            address: instr.ip(),
            bytes,
            text,
            anti_debug: anti,
        });
    }

    let strings = if with_strings {
        extract_strings_with_xrefs(data, &instructions)
    } else {
        Vec::new()
    };

    Ok(DisasmReport {
        path: path.to_string(),
        architecture: binary.architecture,
        start_address: start,
        instructions,
        strings,
    })
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

    strings.truncate(200);
    strings
}

/// Extract ASCII + UTF-16LE strings without disassembly.
pub fn extract_strings_only(data: &[u8]) -> Vec<ExtractedString> {
    let mut strings = extract_ascii_strings(data, 5);
    strings.extend(extract_utf16le_strings(data, 5));
    strings.truncate(2000);
    strings
}

/// Keep IOC-ish / analyst-interesting strings only.
pub fn interesting_strings(all: &[ExtractedString]) -> Vec<ExtractedString> {
    all.iter()
        .filter(|s| is_interesting(&s.value))
        .cloned()
        .take(80)
        .collect()
}

fn is_interesting(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if s.len() < 6 || s.len() > 240 {
        return false;
    }
    // Skip noisy PE/CRT junk
    if lower.starts_with("abcdefghijklmnopqrstuvwxyz")
        || lower.contains("runtime error")
        || lower.contains("this program cannot be run")
    {
        return false;
    }
    lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("ftp://")
        || lower.contains(".onion")
        || lower.contains("discord.com")
        || lower.contains("telegram")
        || lower.contains("webhook")
        || lower.contains("electrora")
        || lower.contains("keylog")
        || lower.contains("screenshot")
        || lower.contains("webcam")
        || lower.contains("password")
        || lower.contains("wallet")
        || lower.contains("cmd.exe")
        || lower.contains("powershell")
        || lower.contains("appdata")
        || lower.contains("\\temp")
        || lower.contains("/temp")
        || lower.contains(".exe")
        || lower.contains(".dll")
        || lower.contains("hkey_")
        || lower.contains("software\\")
        || lower.contains("mozill")
        || lower.contains("chrome")
        || lower.contains("login data")
        || lower.contains("user-agent")
        || lower.contains("api/")
        || looks_like_ipv4(s)
        || looks_like_domain(s)
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
        || lower.contains(".xyz"))
        && !lower.contains(' ')
        && lower.chars().filter(|c| *c == '.').count() >= 1
        && s.len() < 80
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..=0x7e).contains(&b);
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                if let Ok(v) = std::str::from_utf8(&data[s..i]) {
                    out.push(ExtractedString {
                        offset: s as u64,
                        encoding: "ascii".into(),
                        value: v.to_string(),
                        xrefs: Vec::new(),
                    });
                }
            }
        }
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

/// Demangle Rust (v0), C++, and Swift-ish symbols via symbolic-demangle.
pub fn demangle_symbols(symbols: &[String]) -> Vec<String> {
    use symbolic_common::Name;
    use symbolic_demangle::{Demangle, DemangleOptions};

    let opts = DemangleOptions::name_only();
    symbols
        .iter()
        .filter_map(|s| {
            if s.is_empty() {
                return None;
            }
            let name = Name::from(s.as_str());
            let demangled = name.try_demangle(opts);
            if demangled != s.as_str() {
                Some(format!("{s}  =>  {demangled}"))
            } else if s.starts_with("_Z") || s.starts_with("__Z") || s.starts_with("_R") {
                Some(s.clone())
            } else {
                None
            }
        })
        .take(100)
        .collect()
}
