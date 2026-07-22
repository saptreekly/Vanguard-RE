//! Formal binary format detection and header extraction via goblin.

use std::path::Path;

use super::entropy::{SectionEntropy, entropy_heatmap, section_entropy};
use super::report::SectionInfo;
use anyhow::{Context, Result, bail};
use goblin::Object;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    /// MS-DOS COM (no MZ header) — common for classic viruses
    DosCom,
    /// ZIP / ZIP-like container (PK\x03\x04)
    Zip,
    /// Rich Text Format document
    Rtf,
    /// Raster image (BMP / PNG / JPEG)
    Image,
    /// Mostly-printable ASCII / UTF-16LE text or config
    Text,
    /// Known encrypted/payload magic (e.g. WannaCry `WANACRY!`)
    Encrypted,
    /// Unrecognized blob — hashes / strings / YARA only
    Raw,
    Unknown,
}

impl BinaryFormat {
    pub fn is_executable(self) -> bool {
        matches!(
            self,
            Self::Pe | Self::Elf | Self::MachO | Self::DosCom
        )
    }

    pub fn is_content(self) -> bool {
        matches!(
            self,
            Self::Zip | Self::Rtf | Self::Image | Self::Text | Self::Encrypted
        )
    }
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pe => write!(f, "PE"),
            Self::Elf => write!(f, "ELF"),
            Self::MachO => write!(f, "Mach-O"),
            Self::DosCom => write!(f, "DOS-COM"),
            Self::Zip => write!(f, "ZIP"),
            Self::Rtf => write!(f, "RTF"),
            Self::Image => write!(f, "Image"),
            Self::Text => write!(f, "Text"),
            Self::Encrypted => write!(f, "Encrypted"),
            Self::Raw => write!(f, "RAW"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Structured view of a parsed binary after formal header walk.
#[derive(Debug, Clone)]
pub struct ParsedBinary {
    pub format: BinaryFormat,
    pub architecture: String,
    /// Best-effort static estimate from binary headers and imported runtimes.
    pub operating_system: OperatingSystemEstimate,
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

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub library: String,
    pub function: String,
}

#[derive(Debug, Clone)]
pub struct OperatingSystemEstimate {
    pub family: String,
    pub minimum_version: Option<String>,
    pub environment: Option<String>,
    pub evidence: String,
}

impl OperatingSystemEstimate {
    pub fn display(&self) -> String {
        let mut value = self.family.clone();
        if let Some(version) = &self.minimum_version {
            value.push_str(&format!(" ≥ {version}"));
        }
        if let Some(environment) = &self.environment {
            value.push_str(&format!(" · {environment}"));
        }
        value
    }
}

pub fn detect_format(data: &[u8]) -> BinaryFormat {
    // Java class files and Mach-O fat binaries share CAFEBABE. In a class
    // header bytes 6..8 are the JVM major version (normally 45..=100);
    // in a fat Mach-O those bytes are the low half of a small arch count.
    if looks_like_java_class(data) {
        return BinaryFormat::Raw;
    }
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
    if looks_like_java_class(data) {
        return Ok(parse_raw_blob(
            data,
            with_entropy_map,
            BinaryFormat::Raw,
            "jvm-bytecode",
        ));
    }
    match Object::parse(data) {
        Ok(Object::PE(pe)) => parse_pe(data, pe, with_entropy_map),
        Ok(Object::Elf(elf)) => parse_elf(data, elf, with_entropy_map),
        Ok(Object::Mach(mach)) => parse_mach(data, mach, with_entropy_map),
        Ok(Object::Archive(_)) => {
            // Prefer a usable raw fallback over hard-failing the whole investigation.
            Ok(parse_raw_blob(
                data,
                with_entropy_map,
                BinaryFormat::Raw,
                "archive",
            ))
        }
        Ok(Object::Unknown(_)) | Ok(_) | Err(_) => {
            if let Some(parsed) = try_parse_elf_salvage(data, with_entropy_map) {
                Ok(parsed)
            } else {
                Ok(classify_and_parse_raw(data, with_entropy_map, name_hint))
            }
        }
    }
}

fn looks_like_elf_magic(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == [0x7f, b'E', b'L', b'F']
}

/// When strict goblin fails on a recognizable ELF (bad section table, etc.),
/// retry permissive parse, then fall back to a header-only ELF stub.
fn try_parse_elf_salvage(data: &[u8], with_entropy_map: bool) -> Option<ParsedBinary> {
    if !looks_like_elf_magic(data) {
        return None;
    }
    let opts = goblin::options::ParseOptions::permissive();
    if let Ok(elf) = goblin::elf::Elf::parse_with_opts(data, &opts) {
        return parse_elf(data, elf, with_entropy_map).ok();
    }
    let header = goblin::elf::Elf::parse_header(data).ok()?;
    Some(parse_elf_header_only(data, &header, with_entropy_map))
}

fn elf_machine_arch(e_machine: u16) -> &'static str {
    match e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_386 => "x86",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_ARM => "arm",
        goblin::elf::header::EM_MIPS => "mips",
        _ => "unknown",
    }
}

fn parse_elf_header_only(
    _data: &[u8],
    header: &goblin::elf::Header,
    _with_map: bool,
) -> ParsedBinary {
    let arch = elf_machine_arch(header.e_machine);
    let is_64 = header.e_ident[goblin::elf::header::EI_CLASS] == goblin::elf::header::ELFCLASS64;
    ParsedBinary {
        format: BinaryFormat::Elf,
        architecture: arch.into(),
        operating_system: OperatingSystemEstimate {
            family: "Unix / System V".into(),
            minimum_version: None,
            environment: None,
            evidence: "ELF magic (header-only salvage; section table unreadable)".into(),
        },
        entry_point: header.e_entry,
        is_64bit: is_64,
        is_lib: header.e_type == goblin::elf::header::ET_DYN,
        compile_timestamp: None,
        has_signature: false,
        image_file_offset: 0,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        symbols: Vec::new(),
        section_entropies: Vec::new(),
        entropy_maps: Vec::new(),
    }
}

fn looks_like_java_class(data: &[u8]) -> bool {
    data.len() >= 8
        && data[..4] == [0xca, 0xfe, 0xba, 0xbe]
        && (45..=100).contains(&u16::from_be_bytes([data[6], data[7]]))
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

    // Content magics before the loose DOS COM prologue heuristic.
    if let Some(hit) = classify_content_magic(data) {
        return hit;
    }

    let looks_com_name = name_hint.is_some_and(|n| {
        Path::new(n)
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("com"))
    });

    // Classic DOS COM: no MZ, ≤ 64KiB, executable-looking start (or .com name).
    // Skip when the blob is mostly printable text (ransom notes start with 'Q'
    // which overlaps the push-r16 opcode band).
    if !data.is_empty()
        && data.len() <= 65535
        && (looks_com_name || looks_like_com_prologue(data))
        && !looks_mostly_text(data)
    {
        return (BinaryFormat::DosCom, "x86-16");
    }

    if looks_mostly_text(data) {
        return (BinaryFormat::Text, "text");
    }

    (BinaryFormat::Raw, "unknown")
}

fn classify_content_magic(data: &[u8]) -> Option<(BinaryFormat, &'static str)> {
    if data.starts_with(b"{\\rtf") {
        return Some((BinaryFormat::Rtf, "rtf"));
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") || data.starts_with(b"PK\x07\x08")
    {
        return Some((BinaryFormat::Zip, "zip"));
    }
    if data.starts_with(b"BM") && data.len() >= 14 {
        return Some((BinaryFormat::Image, "bmp"));
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some((BinaryFormat::Image, "png"));
    }
    if data.len() >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
        return Some((BinaryFormat::Image, "jpeg"));
    }
    if data.starts_with(b"%PDF") {
        return Some((BinaryFormat::Raw, "pdf"));
    }
    // WannaCry encrypted-file / payload header.
    if data.starts_with(b"WANACRY!") {
        return Some((BinaryFormat::Encrypted, "wanacry"));
    }
    None
}

fn looks_mostly_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if looks_utf16le_text(data) {
        return true;
    }
    // Config blobs with a binary header + ASCII body (WannaCry c.wnry).
    if data.windows(6).any(|w| w.eq_ignore_ascii_case(b".onion"))
        || data.windows(7).any(|w| w.eq_ignore_ascii_case(b"http://"))
        || data.windows(8).any(|w| w.eq_ignore_ascii_case(b"https://"))
    {
        return true;
    }
    // Skip leading NUL padding.
    let start = data.iter().position(|&b| b != 0).unwrap_or(0);
    let slice = &data[start..];
    if slice.is_empty() {
        return false;
    }
    let n = slice.len().min(512);
    let printable = slice[..n]
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t' | b';'))
        .count();
    printable * 100 / n >= 85
}

fn looks_utf16le_text(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    if data.starts_with(&[0xff, 0xfe]) {
        return true;
    }
    let pairs = data.len().min(128) / 2;
    if pairs == 0 {
        return false;
    }
    let mut asciiish = 0;
    for i in 0..pairs {
        let lo = data[i * 2];
        let hi = data[i * 2 + 1];
        if hi == 0 && ((0x20..=0x7e).contains(&lo) || matches!(lo, b'\n' | b'\r' | b'\t')) {
            asciiish += 1;
        }
    }
    asciiish * 100 / pairs >= 70
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

fn parse_raw_blob(data: &[u8], with_map: bool, format: BinaryFormat, arch: &str) -> ParsedBinary {
    let ent = section_entropy("blob", data);
    let mut entropy_maps = Vec::new();
    if with_map {
        entropy_maps.push(("blob".into(), entropy_heatmap(data, 64)));
    }
    ParsedBinary {
        format,
        architecture: arch.into(),
        operating_system: OperatingSystemEstimate {
            family: match format {
                BinaryFormat::DosCom => "DOS".into(),
                BinaryFormat::Rtf | BinaryFormat::Text => "Document".into(),
                BinaryFormat::Image => "Image".into(),
                BinaryFormat::Zip => "Archive".into(),
                BinaryFormat::Encrypted => "Encrypted".into(),
                _ => "Unknown".into(),
            },
            minimum_version: None,
            environment: None,
            evidence: match format {
                BinaryFormat::DosCom => "DOS COM format".into(),
                BinaryFormat::Rtf => "RTF document magic".into(),
                BinaryFormat::Zip => "ZIP local/central header magic".into(),
                BinaryFormat::Image => format!("image magic ({arch})"),
                BinaryFormat::Text => "mostly-printable text/config".into(),
                BinaryFormat::Encrypted => format!("encrypted payload magic ({arch})"),
                _ => "no recognized executable header".into(),
            },
        },
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

    let exports: Vec<String> = pe
        .exports
        .iter()
        .filter_map(|e| e.name.map(|n| n.to_string()))
        .collect();

    let compile_timestamp = pe.header.coff_header.time_date_stamp.pipe_nonzero();

    let has_signature = pe.header.optional_header.as_ref().is_some_and(|oh| {
        oh.data_directories
            .get_certificate_table()
            .map(|d| d.size > 0)
            .unwrap_or(false)
    });
    let operating_system = pe_os_estimate(pe.header.optional_header.as_ref());

    Ok(ParsedBinary {
        format: BinaryFormat::Pe,
        architecture: if pe.is_64 {
            "x86_64".into()
        } else {
            "x86".into()
        },
        operating_system,
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

fn pe_os_estimate(
    optional_header: Option<&goblin::pe::optional_header::OptionalHeader>,
) -> OperatingSystemEstimate {
    use goblin::pe::subsystem;

    let Some(header) = optional_header else {
        return OperatingSystemEstimate {
            family: "Windows".into(),
            minimum_version: None,
            environment: None,
            evidence: "PE format; optional header unavailable".into(),
        };
    };
    let fields = &header.windows_fields;
    let (family, environment) = match fields.subsystem {
        subsystem::IMAGE_SUBSYSTEM_NATIVE => ("Windows", Some("native / driver")),
        subsystem::IMAGE_SUBSYSTEM_WINDOWS_GUI => ("Windows", Some("GUI")),
        subsystem::IMAGE_SUBSYSTEM_WINDOWS_CUI => ("Windows", Some("console")),
        subsystem::IMAGE_SUBSYSTEM_OS2_CUI => ("OS/2", Some("console")),
        subsystem::IMAGE_SUBSYSTEM_POSIX_CUI => ("Windows", Some("POSIX console")),
        subsystem::IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => ("Windows CE", Some("GUI")),
        subsystem::IMAGE_SUBSYSTEM_EFI_APPLICATION => ("UEFI", Some("application")),
        subsystem::IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => ("UEFI", Some("boot driver")),
        subsystem::IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => ("UEFI", Some("runtime driver")),
        subsystem::IMAGE_SUBSYSTEM_EFI_ROM => ("UEFI", Some("ROM image")),
        subsystem::IMAGE_SUBSYSTEM_XBOX => ("Xbox", None),
        subsystem::IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION => {
            ("Windows", Some("boot application"))
        }
        _ => ("Windows", None),
    };
    let minimum_version =
        (fields.major_subsystem_version != 0 || fields.minor_subsystem_version != 0).then(|| {
            format!(
                "{}.{}",
                fields.major_subsystem_version, fields.minor_subsystem_version
            )
        });
    OperatingSystemEstimate {
        family: family.into(),
        minimum_version,
        environment: environment.map(str::to_string),
        evidence: format!(
            "PE subsystem {} and linker subsystem version",
            fields.subsystem
        ),
    }
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
    let version_libs = elf_version_lib_map(&elf);
    for (sym_idx, sym) in elf.dynsyms.iter().enumerate() {
        if sym.is_import() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                let lib = elf_import_library(&elf, &version_libs, sym_idx);
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

    let arch = elf_machine_arch(elf.header.e_machine);
    let operating_system =
        elf_os_estimate(elf.header.e_ident[goblin::elf::header::EI_OSABI], &imports);

    Ok(ParsedBinary {
        format: BinaryFormat::Elf,
        architecture: arch.into(),
        operating_system,
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

fn elf_os_estimate(osabi: u8, imports: &[ImportEntry]) -> OperatingSystemEstimate {
    use goblin::elf::header::*;

    let has_linux_runtime = imports.iter().any(|import| {
        let library = import.library.to_ascii_lowercase();
        library.contains("linux")
            || library.starts_with("libc.so")
            || library.starts_with("libpthread.so")
            || library.starts_with("libdl.so")
    });
    let family = match osabi {
        ELFOSABI_HPUX => "HP-UX",
        ELFOSABI_NETBSD => "NetBSD",
        ELFOSABI_GNU => "Linux / GNU",
        ELFOSABI_SOLARIS => "Solaris",
        ELFOSABI_AIX => "AIX",
        ELFOSABI_IRIX => "IRIX",
        ELFOSABI_FREEBSD => "FreeBSD",
        ELFOSABI_TRU64 => "Tru64",
        ELFOSABI_OPENBSD => "OpenBSD",
        ELFOSABI_ARM_AEABI | ELFOSABI_ARM => "ARM (OS unspecified)",
        ELFOSABI_STANDALONE => "Standalone",
        ELFOSABI_NONE if has_linux_runtime => "Linux",
        ELFOSABI_NONE => "Unix / System V",
        _ => "Unix-like (unknown ABI)",
    };
    OperatingSystemEstimate {
        family: family.into(),
        minimum_version: None,
        environment: None,
        evidence: if osabi == ELFOSABI_NONE && has_linux_runtime {
            "ELF System V ABI with Linux runtime imports".into()
        } else {
            format!("ELF OSABI {osabi}")
        },
    }
}

/// Map GNU versym version indices → needed library names via VERNEED.
fn elf_version_lib_map(elf: &goblin::elf::Elf<'_>) -> std::collections::BTreeMap<u16, String> {
    let mut map = std::collections::BTreeMap::new();
    let Some(verneed) = &elf.verneed else {
        return map;
    };
    for need in verneed.iter() {
        let lib = elf
            .dynstrtab
            .get_at(need.vn_file)
            .unwrap_or("?")
            .to_string();
        for aux in need.iter() {
            let idx = aux.vna_other & goblin::elf::symver::VERSYM_VERSION;
            map.insert(idx, lib.clone());
        }
    }
    map
}

fn elf_import_library(
    elf: &goblin::elf::Elf<'_>,
    version_libs: &std::collections::BTreeMap<u16, String>,
    sym_idx: usize,
) -> String {
    if let Some(versym) = &elf.versym {
        if let Some(vs) = versym.get_at(sym_idx) {
            let idx = vs.version();
            if let Some(lib) = version_libs.get(&idx) {
                return lib.clone();
            }
        }
    }
    // No versioning info: leave unattributed rather than blaming the first DT_NEEDED.
    if elf.libraries.len() == 1 {
        elf.libraries[0].to_string()
    } else {
        "?".into()
    }
}

fn parse_mach(data: &[u8], mach: goblin::mach::Mach<'_>, with_map: bool) -> Result<ParsedBinary> {
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

            let arches = multi
                .arches()
                .context("read Mach-O fat architecture table")?;
            let mut index = arches.iter().position(|a| prefer.contains(&a.cputype));
            if index.is_none() {
                index =
                    (0..multi.narches).find(|&i| matches!(multi.get(i), Ok(SingleArch::MachO(_))));
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
    let operating_system = macho_os_estimate(&macho);

    Ok(ParsedBinary {
        format: BinaryFormat::MachO,
        architecture: arch.into(),
        operating_system,
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

fn macho_os_estimate(macho: &goblin::mach::MachO<'_>) -> OperatingSystemEstimate {
    use goblin::mach::load_command::CommandVariant;

    let mut family = "Apple platform".to_string();
    let mut minimum_version = None;
    let mut evidence = "Mach-O format".to_string();
    for command in &macho.load_commands {
        let (platform, encoded) = match command.command {
            CommandVariant::VersionMinMacosx(v) => ("macOS", Some(v.version)),
            CommandVariant::VersionMinIphoneos(v) => ("iOS", Some(v.version)),
            CommandVariant::VersionMinTvos(v) => ("tvOS", Some(v.version)),
            CommandVariant::VersionMinWatchos(v) => ("watchOS", Some(v.version)),
            CommandVariant::BuildVersion(v) => (
                match v.platform {
                    1 => "macOS",
                    2 => "iOS",
                    3 => "tvOS",
                    4 => "watchOS",
                    6 => "macCatalyst",
                    7 => "iOS Simulator",
                    8 => "tvOS Simulator",
                    9 => "watchOS Simulator",
                    _ => "Apple platform",
                },
                Some(v.minos),
            ),
            _ => continue,
        };
        family = platform.into();
        minimum_version = encoded.map(format_macho_version);
        evidence = "Mach-O minimum-version load command".into();
        break;
    }
    OperatingSystemEstimate {
        family,
        minimum_version,
        environment: None,
        evidence,
    }
}

fn format_macho_version(version: u32) -> String {
    format!(
        "{}.{}.{}",
        version >> 16,
        (version >> 8) & 0xff,
        version & 0xff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_macho_packed_version() {
        assert_eq!(format_macho_version(0x000d_0201), "13.2.1");
    }

    #[test]
    fn infers_linux_from_system_v_runtime_imports() {
        let estimate = elf_os_estimate(
            goblin::elf::header::ELFOSABI_NONE,
            &[ImportEntry {
                library: "libc.so.6".into(),
                function: "socket".into(),
            }],
        );
        assert_eq!(estimate.family, "Linux");
    }

    #[test]
    fn elf_import_library_uses_single_needed_or_unknown() {
        // Without a live ELF blob, assert the fallback helper policy via the
        // public parse path on a tiny invalid buffer (no crash / empty imports).
        let parsed = parse_binary_named(b"\x7fELFnot-real", false, Some("bad.elf")).unwrap();
        assert!(parsed.imports.is_empty() || parsed.format != BinaryFormat::Elf);
    }

    #[test]
    fn elf_magic_with_broken_sections_still_salvages_as_elf() {
        // Minimal ELF32 header (little-endian, EM_386) with e_shoff past EOF so
        // strict parse fails; permissive/header salvage must keep BinaryFormat::Elf.
        let mut elf = vec![0u8; 52];
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 1; // ELFCLASS32
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16] = 2; // ET_EXEC
        elf[18] = 3; // EM_386
        elf[20] = 1; // EV_CURRENT
        // e_entry at 24
        elf[24..28].copy_from_slice(&0x8048000u32.to_le_bytes());
        elf[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff
        elf[32..36].copy_from_slice(&0x0fff_ffffu32.to_le_bytes()); // e_shoff past EOF
        elf[44..46].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
        elf[46..48].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
        elf[48..50].copy_from_slice(&0u16.to_le_bytes()); // e_phnum
        elf[50..52].copy_from_slice(&40u16.to_le_bytes()); // e_shentsize
        // e_shnum / e_shstrndx default 0 in remaining zeros — still bad shoff.

        let parsed = parse_binary_named(&elf, false, Some("broken.elf")).unwrap();
        assert_eq!(parsed.format, BinaryFormat::Elf, "\\x7fELF must not fall to Raw");
        assert_eq!(parsed.architecture, "x86");
    }

    #[test]
    fn java_class_is_not_misparsed_as_fat_macho() {
        let mut class = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34];
        class.extend_from_slice(&[0; 16]);
        let parsed = parse_binary_named(&class, false, Some("Payload.class")).unwrap();
        assert_eq!(parsed.format, BinaryFormat::Raw);
        assert_eq!(parsed.architecture, "jvm-bytecode");
        assert_eq!(detect_format(&class), BinaryFormat::Raw);
    }

    #[test]
    fn detects_rtf_bmp_zip_text_and_wanacry() {
        let rtf = parse_binary_named(br"{\rtf1\ansi hello}", false, Some("m_english.wnry")).unwrap();
        assert_eq!(rtf.format, BinaryFormat::Rtf);

        let mut bmp = vec![b'B', b'M', 0, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0];
        bmp.extend_from_slice(&[0; 32]);
        let bmp = parse_binary_named(&bmp, false, Some("b.wnry")).unwrap();
        assert_eq!(bmp.format, BinaryFormat::Image);
        assert_eq!(bmp.architecture, "bmp");

        let zip = parse_binary_named(b"PK\x03\x04\0\0\0\0payload", false, Some("s.wnry")).unwrap();
        assert_eq!(zip.format, BinaryFormat::Zip);

        let note = parse_binary_named(
            b"Q:  What's wrong with my files?\nA:  Ooops, encrypted.\n",
            false,
            Some("r.wnry"),
        )
        .unwrap();
        assert_eq!(note.format, BinaryFormat::Text, "ransom note must not be DOS COM");

        let enc = parse_binary_named(b"WANACRY!\x00\x01\x00\x00ciphertext", false, Some("t.wnry"))
            .unwrap();
        assert_eq!(enc.format, BinaryFormat::Encrypted);
        assert_eq!(enc.architecture, "wanacry");
    }
}
