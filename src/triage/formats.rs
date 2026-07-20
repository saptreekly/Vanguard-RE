//! Formal binary format detection and header extraction via goblin.

use std::path::Path;

use anyhow::{bail, Context, Result};
use goblin::Object;
use serde::Serialize;

use super::entropy::{entropy_heatmap, section_entropy, SectionEntropy};
use super::report::SectionInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    /// MS-DOS COM (no MZ header) — common for classic viruses
    DosCom,
    /// Unrecognized blob — hashes / strings / YARA only
    Raw,
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pe => write!(f, "PE"),
            Self::Elf => write!(f, "ELF"),
            Self::MachO => write!(f, "Mach-O"),
            Self::DosCom => write!(f, "DOS-COM"),
            Self::Raw => write!(f, "RAW"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Structured view of a parsed binary after formal header walk.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedBinary {
    pub format: BinaryFormat,
    pub architecture: String,
    pub entry_point: u64,
    pub is_64bit: bool,
    pub is_lib: bool,
    pub compile_timestamp: Option<u32>,
    pub has_signature: bool,
    /// Byte offset into the original file where this image begins (0 for thin; fat arch offset for Mach-O).
    pub image_file_offset: u64,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<String>,
    pub symbols: Vec<String>,
    pub section_entropies: Vec<SectionEntropy>,
    pub entropy_maps: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportEntry {
    pub library: String,
    pub function: String,
}

pub fn detect_format(data: &[u8]) -> BinaryFormat {
    match Object::parse(data) {
        Ok(Object::PE(_)) => BinaryFormat::Pe,
        Ok(Object::Elf(_)) => BinaryFormat::Elf,
        Ok(Object::Mach(_)) | Ok(Object::Archive(_)) => BinaryFormat::MachO,
        _ => {
            // goblin Archive is Mach-O fat/archive; treat unknown magic carefully
            if data.len() >= 4 {
                let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                // MH_MAGIC / MH_CIGAM / 64-bit variants / FAT
                if matches!(
                    magic,
                    0xfeedface | 0xcefaedfe | 0xfeedfacf | 0xcffaedfe | 0xcafebabe | 0xbebafeca
                ) {
                    return BinaryFormat::MachO;
                }
            }
            BinaryFormat::Unknown
        }
    }
}

pub fn parse_binary(data: &[u8], with_entropy_map: bool) -> Result<ParsedBinary> {
    parse_binary_named(data, with_entropy_map, None)
}

/// Like [`parse_binary`], but uses `name_hint` (e.g. `.com`) when goblin cannot classify.
pub fn parse_binary_named(
    data: &[u8],
    with_entropy_map: bool,
    name_hint: Option<&str>,
) -> Result<ParsedBinary> {
    match Object::parse(data) {
        Ok(Object::PE(pe)) => parse_pe(data, pe, with_entropy_map),
        Ok(Object::Elf(elf)) => parse_elf(data, elf, with_entropy_map),
        Ok(Object::Mach(mach)) => parse_mach(data, mach, with_entropy_map),
        Ok(Object::Archive(_)) => {
            // Prefer a usable raw fallback over hard-failing the whole investigation.
            Ok(parse_raw_blob(data, with_entropy_map, BinaryFormat::Raw, "archive"))
        }
        Ok(Object::Unknown(_)) | Ok(_) | Err(_) => {
            Ok(classify_and_parse_raw(data, with_entropy_map, name_hint))
        }
    }
}

fn classify_and_parse_raw(data: &[u8], with_map: bool, name_hint: Option<&str>) -> ParsedBinary {
    let (format, arch) = classify_raw(data, name_hint);
    parse_raw_blob(data, with_map, format, arch)
}

fn classify_raw(data: &[u8], name_hint: Option<&str>) -> (BinaryFormat, &'static str) {
    // MZ without valid PE — still not a classic COM.
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        return (BinaryFormat::Raw, "dos-mz");
    }

    let looks_com_name = name_hint.is_some_and(|n| {
        Path::new(n)
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("com"))
    });

    // Classic DOS COM: no MZ, ≤ 64KiB, executable-looking start (or .com name).
    if !data.is_empty() && data.len() <= 65535 && (looks_com_name || looks_like_com_prologue(data)) {
        return (BinaryFormat::DosCom, "x86-16");
    }

    (BinaryFormat::Raw, "unknown")
}

/// Common 16-bit real-mode / COM entry opcodes (JMP/CALL/INT/MOV/PUSH/…).
fn looks_like_com_prologue(data: &[u8]) -> bool {
    matches!(
        data[0],
        0xE9 | 0xEB | 0xE8 | // jmp / call
        0x90 | // nop
        0xFA | 0xFB | 0xFC | 0xFD | // cli/sti/cld/std
        0x50..=0x57 | // push r16
        0x58..=0x5F | // pop r16
        0xB0..=0xBF | // mov r8/r16, imm
        0xCD | // int
        0x33 | 0x31 | 0x29 | 0x01 | 0x03 | // xor/sub/add
        0x8B | 0x8A | 0x89 | 0x88 | // mov
        0xAC | 0xAD | 0xAE | 0xAF | // lods/scas
        0xF3 | 0xF2 | 0xF0 // rep / lock prefixes
    )
}

fn parse_raw_blob(
    data: &[u8],
    with_map: bool,
    format: BinaryFormat,
    arch: &str,
) -> ParsedBinary {
    let ent = section_entropy("blob", data);
    let mut entropy_maps = Vec::new();
    if with_map {
        entropy_maps.push(("blob".into(), entropy_heatmap(data, 64)));
    }
    ParsedBinary {
        format,
        architecture: arch.into(),
        entry_point: 0,
        is_64bit: false,
        is_lib: false,
        compile_timestamp: None,
        has_signature: false,
        image_file_offset: 0,
        sections: vec![SectionInfo {
            name: "blob".into(),
            virtual_address: 0,
            virtual_size: data.len() as u64,
            raw_size: data.len() as u64,
            file_offset: 0,
            characteristics: "raw".into(),
        }],
        imports: Vec::new(),
        exports: Vec::new(),
        symbols: Vec::new(),
        section_entropies: vec![ent],
        entropy_maps,
    }
}

fn parse_pe(data: &[u8], pe: goblin::pe::PE<'_>, with_map: bool) -> Result<ParsedBinary> {
    let mut sections = Vec::new();
    let mut section_entropies = Vec::new();
    let mut entropy_maps = Vec::new();

    for sec in &pe.sections {
        let name = String::from_utf8_lossy(&sec.name)
            .trim_end_matches('\0')
            .to_string();
        let start = sec.pointer_to_raw_data as usize;
        let size = sec.size_of_raw_data as usize;
        let slice = data.get(start..start.saturating_add(size)).unwrap_or(&[]);

        let ent = section_entropy(&name, slice);
        if with_map {
            entropy_maps.push((name.clone(), entropy_heatmap(slice, 64)));
        }
        section_entropies.push(ent);

        sections.push(SectionInfo {
            name,
            virtual_address: u64::from(sec.virtual_address),
            virtual_size: u64::from(sec.virtual_size),
            raw_size: u64::from(sec.size_of_raw_data),
            file_offset: u64::from(sec.pointer_to_raw_data),
            characteristics: format!("{:#010x}", sec.characteristics),
        });
    }

    let mut imports = Vec::new();
    for import in &pe.imports {
        imports.push(ImportEntry {
            library: import.dll.to_string(),
            function: import.name.to_string(),
        });
    }

    let exports: Vec<String> = pe.exports.iter().filter_map(|e| e.name.map(|n| n.to_string())).collect();

    let compile_timestamp = pe.header.coff_header.time_date_stamp.pipe_nonzero();

    let has_signature = pe.header.optional_header.as_ref().is_some_and(|oh| {
        oh.data_directories
            .get_certificate_table()
            .map(|d| d.size > 0)
            .unwrap_or(false)
    });

    Ok(ParsedBinary {
        format: BinaryFormat::Pe,
        architecture: if pe.is_64 {
            "x86_64".into()
        } else {
            "x86".into()
        },
        entry_point: pe.entry as u64,
        is_64bit: pe.is_64,
        is_lib: pe.is_lib,
        compile_timestamp,
        has_signature,
        image_file_offset: 0,
        sections,
        imports,
        exports,
        symbols: Vec::new(),
        section_entropies,
        entropy_maps,
    })
}

trait PipeNonZero {
    fn pipe_nonzero(self) -> Option<u32>;
}
impl PipeNonZero for u32 {
    fn pipe_nonzero(self) -> Option<u32> {
        if self == 0 { None } else { Some(self) }
    }
}

fn parse_elf(data: &[u8], elf: goblin::elf::Elf<'_>, with_map: bool) -> Result<ParsedBinary> {
    let mut sections = Vec::new();
    let mut section_entropies = Vec::new();
    let mut entropy_maps = Vec::new();

    for sec in &elf.section_headers {
        let name = elf
            .shdr_strtab
            .get_at(sec.sh_name)
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let start = sec.sh_offset as usize;
        let size = sec.sh_size as usize;
        let slice = data.get(start..start.saturating_add(size)).unwrap_or(&[]);

        let ent = section_entropy(&name, slice);
        if with_map {
            entropy_maps.push((name.clone(), entropy_heatmap(slice, 64)));
        }
        section_entropies.push(ent);

        sections.push(SectionInfo {
            name,
            virtual_address: sec.sh_addr,
            virtual_size: sec.sh_size,
            raw_size: sec.sh_size,
            file_offset: sec.sh_offset,
            characteristics: format!("{:#x}", sec.sh_flags),
        });
    }

    let mut imports = Vec::new();
    for lib in &elf.libraries {
        // ELF dynamic imports are symbol-level; record library with placeholder
        imports.push(ImportEntry {
            library: (*lib).to_string(),
            function: "*".into(),
        });
    }
    for sym in elf.dynsyms.iter() {
        if sym.is_import() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                let lib = elf
                    .libraries
                    .first()
                    .copied()
                    .unwrap_or("UNKNOWN")
                    .to_string();
                imports.push(ImportEntry {
                    library: lib,
                    function: name.to_string(),
                });
            }
        }
    }

    let exports: Vec<String> = elf
        .dynsyms
        .iter()
        .filter(|s| s.st_bind() == goblin::elf::sym::STB_GLOBAL && !s.is_import())
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name).map(|n| n.to_string()))
        .collect();

    let symbols: Vec<String> = elf
        .syms
        .iter()
        .filter_map(|s| elf.strtab.get_at(s.st_name).map(|n| n.to_string()))
        .filter(|n| !n.is_empty())
        .take(500)
        .collect();

    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_386 => "x86",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_ARM => "arm",
        goblin::elf::header::EM_MIPS => "mips",
        _ => "unknown",
    };

    Ok(ParsedBinary {
        format: BinaryFormat::Elf,
        architecture: arch.into(),
        entry_point: elf.entry,
        is_64bit: elf.is_64,
        is_lib: elf.header.e_type == goblin::elf::header::ET_DYN,
        compile_timestamp: None,
        has_signature: false,
        image_file_offset: 0,
        sections,
        imports,
        exports,
        symbols,
        section_entropies,
        entropy_maps,
    })
}

fn parse_mach(
    data: &[u8],
    mach: goblin::mach::Mach<'_>,
    with_map: bool,
) -> Result<ParsedBinary> {
    use goblin::mach::constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
    use goblin::mach::{Mach, SingleArch};

    let (macho, slice, image_file_offset) = match mach {
        Mach::Binary(m) => (m, data, 0u64),
        Mach::Fat(multi) => {
            let prefer = [
                #[cfg(target_arch = "aarch64")]
                CPU_TYPE_ARM64,
                #[cfg(target_arch = "x86_64")]
                CPU_TYPE_X86_64,
                CPU_TYPE_ARM64,
                CPU_TYPE_X86_64,
            ];

            let arches = multi.arches().context("read Mach-O fat architecture table")?;
            let mut index = arches.iter().position(|a| prefer.contains(&a.cputype));
            if index.is_none() {
                index = (0..multi.narches).find(|&i| matches!(multi.get(i), Ok(SingleArch::MachO(_))));
            }
            let i = index.ok_or_else(|| {
                anyhow::anyhow!("Mach-O fat binary has no usable architecture slice")
            })?;
            let thin = arches[i].slice(data);
            let off = u64::from(arches[i].offset);
            match multi.get(i)? {
                SingleArch::MachO(m) => (m, thin, off),
                SingleArch::Archive(_) => {
                    bail!("Mach-O fat entry {i} is an archive, not a binary")
                }
            }
        }
    };

    parse_macho(slice, macho, with_map, image_file_offset)
}

fn parse_macho(
    data: &[u8],
    macho: goblin::mach::MachO<'_>,
    with_map: bool,
    image_file_offset: u64,
) -> Result<ParsedBinary> {
    let mut sections = Vec::new();
    let mut section_entropies = Vec::new();
    let mut entropy_maps = Vec::new();

    let segments = macho.segments.sections().flatten();
    for section_result in segments {
        let (section, _data_opt) = section_result?;
        let name = section.name().unwrap_or("").to_string();
        let start = section.offset as usize;
        let size = section.size as usize;
        let slice = data.get(start..start.saturating_add(size)).unwrap_or(&[]);

        let ent = section_entropy(&name, slice);
        if with_map {
            entropy_maps.push((name.clone(), entropy_heatmap(slice, 64)));
        }
        section_entropies.push(ent);

        sections.push(SectionInfo {
            name,
            virtual_address: section.addr,
            virtual_size: section.size,
            raw_size: section.size,
            file_offset: u64::from(section.offset),
            characteristics: format!("{:#x}", section.flags),
        });
    }

    let mut imports = Vec::new();
    if let Ok(imports_map) = macho.imports() {
        for imp in imports_map.iter() {
            imports.push(ImportEntry {
                library: imp.dylib.to_string(),
                function: imp.name.to_string(),
            });
        }
    }

    let exports: Vec<String> = macho
        .exports()
        .ok()
        .map(|exps| exps.iter().map(|e| e.name.to_string()).collect())
        .unwrap_or_default();

    let symbols: Vec<String> = macho
        .symbols
        .as_ref()
        .map(|syms| {
            syms.iter()
                .filter_map(|s| s.ok())
                .map(|(name, _)| name.to_string())
                .take(500)
                .collect()
        })
        .unwrap_or_default();

    let is_64bit = macho.is_64;
    let arch = match macho.header.cputype {
        goblin::mach::constants::cputype::CPU_TYPE_X86_64 => "x86_64",
        goblin::mach::constants::cputype::CPU_TYPE_X86 => "x86",
        goblin::mach::constants::cputype::CPU_TYPE_ARM64 => "aarch64",
        goblin::mach::constants::cputype::CPU_TYPE_ARM => "arm",
        _ => "unknown",
    };

    Ok(ParsedBinary {
        format: BinaryFormat::MachO,
        architecture: arch.into(),
        entry_point: macho.entry,
        is_64bit,
        is_lib: false,
        compile_timestamp: None,
        has_signature: false,
        image_file_offset,
        sections,
        imports,
        exports,
        symbols,
        section_entropies,
        entropy_maps,
    })
}

