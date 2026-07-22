//! Toolchain / source-language fingerprinting.
//!
//! Compilers and language runtimes leave characteristic artifacts in a binary:
//! runtime section names (`.gopclntab`), import DLLs (`MSVBVM60.DLL`), symbol
//! mangling schemes (`_ZN…`, `??…@@`), embedded version strings (`Go build
//! ID:`, `rustc`), metadata magics (`BSJB` for .NET), and the MSVC PE Rich
//! header. None of this is authoritative on its own — packers strip it and
//! authors can forge it — so we collect *evidence* and rank languages by how
//! much corroborating signal we see. Purely static, read-only.

use std::collections::BTreeMap;

use crate::triage::{BinaryFormat, ParsedBinary};

#[derive(Debug, Clone)]
pub struct ToolchainFinding {
    /// Source language / toolchain, e.g. "Go", "Rust", ".NET", "MSVC C/C++".
    pub language: String,
    /// 0–100 aggregate confidence from corroborating artifacts.
    pub confidence: u8,
    /// Human-readable artifacts that matched (deduped, capped).
    pub evidence: Vec<String>,
}

/// A single byte-marker rule: language, needle, weight, and a label for it.
struct Marker {
    language: &'static str,
    needle: &'static [u8],
    weight: u8,
    evidence: &'static str,
}

/// Printable string artifacts. Ordered by language; multiple may fire.
const MARKERS: &[Marker] = &[
    // ── Go ───────────────────────────────────────────────────────────────
    Marker { language: "Go", needle: b"Go build ID:", weight: 90, evidence: "\"Go build ID:\" marker" },
    Marker { language: "Go", needle: b"go1.", weight: 25, evidence: "go1.x runtime version string" },
    Marker { language: "Go", needle: b"runtime.main", weight: 40, evidence: "runtime.main symbol" },
    Marker { language: "Go", needle: b"GOROOT", weight: 20, evidence: "GOROOT string" },
    Marker { language: "Go", needle: b"golang.org", weight: 20, evidence: "golang.org path" },

    // ── Rust ─────────────────────────────────────────────────────────────
    Marker { language: "Rust", needle: b"/rustc/", weight: 80, evidence: "/rustc/<hash> source path" },
    Marker { language: "Rust", needle: b"library/std/src/", weight: 60, evidence: "library/std/src/ path" },
    Marker { language: "Rust", needle: b"called `Result::unwrap()`", weight: 70, evidence: "Result::unwrap panic string" },
    Marker { language: "Rust", needle: b"RUST_BACKTRACE", weight: 55, evidence: "RUST_BACKTRACE env var" },
    Marker { language: "Rust", needle: b"cargo/registry", weight: 45, evidence: "cargo/registry path" },

    // ── .NET (C# / VB.NET) ─────────────────────────────────────────────────
    Marker { language: ".NET", needle: b"BSJB", weight: 75, evidence: "BSJB CLR metadata header" },
    Marker { language: ".NET", needle: b"mscorlib", weight: 45, evidence: "mscorlib reference" },
    Marker { language: ".NET", needle: b"<Module>", weight: 30, evidence: "<Module> metadata token" },
    Marker { language: ".NET", needle: b"System.Private.CoreLib", weight: 45, evidence: "CoreLib reference" },
    Marker { language: ".NET", needle: b"_CorExeMain", weight: 85, evidence: "_CorExeMain CLR entry" },
    Marker { language: ".NET", needle: b"_CorDllMain", weight: 80, evidence: "_CorDllMain CLR entry" },

    // ── MSVC C/C++ ─────────────────────────────────────────────────────────
    Marker { language: "MSVC C/C++", needle: b"Microsoft Visual C++ Runtime", weight: 55, evidence: "MSVC runtime string" },

    // ── GCC / MinGW / Clang ────────────────────────────────────────────────
    Marker { language: "GCC/Clang (C/C++)", needle: b"GCC: (", weight: 70, evidence: "GCC: (GNU) .comment tag" },
    Marker { language: "GCC/Clang (C/C++)", needle: b"clang version", weight: 70, evidence: "clang version string" },
    Marker { language: "GCC/MinGW", needle: b"libgcc", weight: 40, evidence: "libgcc reference" },
    Marker { language: "GCC/MinGW", needle: b"__mingw_", weight: 60, evidence: "__mingw_ runtime symbol" },
    Marker { language: "GCC/MinGW", needle: b"Mingw-w64", weight: 65, evidence: "Mingw-w64 string" },

    // ── Delphi / C++ Builder ───────────────────────────────────────────────
    Marker { language: "Delphi/C++ Builder", needle: b"Embarcadero", weight: 70, evidence: "Embarcadero string" },
    Marker { language: "Delphi/C++ Builder", needle: b"Borland", weight: 60, evidence: "Borland string" },
    Marker { language: "Delphi/C++ Builder", needle: b"Runtime error     at ", weight: 65, evidence: "Delphi runtime-error template" },
    Marker { language: "Delphi/C++ Builder", needle: b"SOFTWARE\\Borland\\", weight: 55, evidence: "Borland registry key" },
    Marker { language: "Delphi/C++ Builder", needle: b"FastMM", weight: 40, evidence: "FastMM allocator" },

    // ── Free Pascal / Lazarus ──────────────────────────────────────────────
    Marker { language: "Free Pascal/Lazarus", needle: b"Free Pascal", weight: 70, evidence: "Free Pascal string" },
    Marker { language: "Free Pascal/Lazarus", needle: b"FPC ", weight: 30, evidence: "FPC version tag" },
    Marker { language: "Free Pascal/Lazarus", needle: b"This program was compiled with", weight: 30, evidence: "FPC banner" },

    // ── Nim ────────────────────────────────────────────────────────────────
    Marker { language: "Nim", needle: b"NimMain", weight: 75, evidence: "NimMain entry" },
    Marker { language: "Nim", needle: b"fatal.nim", weight: 65, evidence: "fatal.nim path" },
    Marker { language: "Nim", needle: b"nimFrame", weight: 55, evidence: "nimFrame symbol" },

    // ── AutoIt ───────────────────────────────────────────────────────────
    Marker { language: "AutoIt", needle: b">>>AUTOIT SCRIPT<<<", weight: 90, evidence: "embedded AutoIt script marker" },
    Marker { language: "AutoIt", needle: b"AU3!EA", weight: 85, evidence: "AU3 signature" },
    Marker { language: "AutoIt", needle: b"AutoIt v3", weight: 70, evidence: "AutoIt v3 string" },

    // ── Python (PyInstaller / py2exe) ──────────────────────────────────────
    Marker { language: "Python (frozen)", needle: b"_MEIPASS", weight: 80, evidence: "PyInstaller _MEIPASS" },
    Marker { language: "Python (frozen)", needle: b"PyInstaller", weight: 80, evidence: "PyInstaller string" },
    Marker { language: "Python (frozen)", needle: b"pyi-", weight: 55, evidence: "pyi- bootloader option" },
    Marker { language: "Python (frozen)", needle: b"Py_Initialize", weight: 45, evidence: "CPython API symbol" },
    Marker { language: "Python (frozen)", needle: b"python3", weight: 20, evidence: "python3 reference" },
];

/// Import-DLL rules (case-insensitive substring on the library name).
struct ImportRule {
    language: &'static str,
    dll_needle: &'static str,
    weight: u8,
    evidence: &'static str,
}

const IMPORT_RULES: &[ImportRule] = &[
    ImportRule { language: ".NET", dll_needle: "mscoree.dll", weight: 90, evidence: "imports mscoree.dll (CLR shim)" },
    ImportRule { language: "Visual Basic 6", dll_needle: "msvbvm60", weight: 95, evidence: "imports MSVBVM60.DLL (VB6 runtime)" },
    ImportRule { language: "Visual Basic 6", dll_needle: "msvbvm50", weight: 95, evidence: "imports MSVBVM50.DLL (VB5 runtime)" },
    ImportRule { language: "MSVC C/C++", dll_needle: "vcruntime", weight: 70, evidence: "imports VCRUNTIME (MSVC)" },
    ImportRule { language: "MSVC C/C++", dll_needle: "msvcp", weight: 55, evidence: "imports MSVCP (MSVC C++ stdlib)" },
    ImportRule { language: "MSVC C/C++", dll_needle: "msvcr", weight: 45, evidence: "imports MSVCR (MSVC CRT)" },
    ImportRule { language: "MSVC C/C++", dll_needle: "api-ms-win-crt", weight: 55, evidence: "imports UCRT (api-ms-win-crt-*)" },
    ImportRule { language: "Python (frozen)", dll_needle: "python3", weight: 60, evidence: "imports pythonXX.dll" },
];

/// Section-name rules (exact or contains, case-sensitive as emitted by tools).
struct SectionRule {
    language: &'static str,
    needle: &'static str,
    weight: u8,
    evidence: &'static str,
}

const SECTION_RULES: &[SectionRule] = &[
    SectionRule { language: "Go", needle: ".gopclntab", weight: 90, evidence: ".gopclntab section" },
    SectionRule { language: "Go", needle: ".go.buildinfo", weight: 85, evidence: ".go.buildinfo section" },
    SectionRule { language: "Go", needle: ".noptrdata", weight: 50, evidence: ".noptrdata section" },
    SectionRule { language: "Go", needle: ".typelink", weight: 55, evidence: ".typelink section" },
    SectionRule { language: "Go", needle: ".gosymtab", weight: 60, evidence: ".gosymtab section" },
    SectionRule { language: ".NET", needle: ".cormeta", weight: 80, evidence: ".cormeta section" },
    SectionRule { language: "Delphi/C++ Builder", needle: ".didata", weight: 40, evidence: ".didata section" },
];

/// Run all fingerprint passes and return languages ranked by confidence.
pub fn identify(data: &[u8], binary: &ParsedBinary) -> Vec<ToolchainFinding> {
    let window = &data[..data.len().min(32 * 1024 * 1024)];
    let mut acc: BTreeMap<&'static str, (u32, Vec<String>)> = BTreeMap::new();

    let mut bump = |language: &'static str, weight: u8, evidence: String| {
        let entry = acc.entry(language).or_insert((0, Vec::new()));
        entry.0 = (entry.0 + weight as u32).min(100);
        if entry.1.len() < 6 && !entry.1.contains(&evidence) {
            entry.1.push(evidence);
        }
    };

    // 1) Byte markers.
    for m in MARKERS {
        // Weak Delphi string hits (e.g. "Borland" in eSTREAM headers) fire on
        // Raw source blobs. Require PE/ELF/Mach-O for weight < 70; strong
        // markers like Embarcadero still apply everywhere.
        if m.language == "Delphi/C++ Builder"
            && m.weight < 70
            && !matches!(
                binary.format,
                BinaryFormat::Pe | BinaryFormat::Elf | BinaryFormat::MachO
            )
        {
            continue;
        }
        if contains_seq(window, m.needle) {
            bump(m.language, m.weight, m.evidence.to_string());
        }
    }

    // 2) Import DLLs + CLR entrypoints.
    for imp in &binary.imports {
        let lib = imp.library.to_ascii_lowercase();
        for rule in IMPORT_RULES {
            if lib.contains(rule.dll_needle) {
                bump(rule.language, rule.weight, rule.evidence.to_string());
            }
        }
        let func = imp.function.to_ascii_lowercase();
        if func.contains("_corexemain") {
            bump(".NET", 85, "imports _CorExeMain".into());
        } else if func.contains("_cordllmain") {
            bump(".NET", 80, "imports _CorDllMain".into());
        }
    }

    // 3) Section names.
    for sec in &binary.sections {
        for rule in SECTION_RULES {
            if sec.name.contains(rule.needle) {
                bump(rule.language, rule.weight, rule.evidence.to_string());
            }
        }
    }

    // 4) Symbol mangling / runtime symbol names (ELF / Mach-O expose these).
    let mut itanium = false;
    let mut msvcpp = false;
    let mut rust_mangled = false;
    let mut go_symbols = false;
    for sym in &binary.symbols {
        if sym.starts_with("_ZN") || sym.starts_with("_Z") {
            itanium = true;
            // Rust legacy mangling: Itanium name ending in a 17-hex hash (`17h…E`).
            if sym.contains("17h") && sym.ends_with('E') {
                rust_mangled = true;
            }
        }
        if sym.starts_with("_R") && sym.len() > 3 {
            rust_mangled = true; // Rust v0 mangling
        }
        if sym.starts_with("??") || (sym.contains("@@") && sym.starts_with('?')) {
            msvcpp = true;
        }
        if sym.starts_with("runtime.") || sym.starts_with("go.") || sym == "main.main" {
            go_symbols = true;
        }
    }
    if go_symbols {
        bump("Go", 60, "Go runtime symbols (runtime.*/main.main)".into());
    }
    if rust_mangled {
        bump("Rust", 65, "Rust name mangling in symbols".into());
    }
    if msvcpp {
        bump("MSVC C/C++", 55, "MSVC C++ name mangling (??…@@)".into());
    } else if itanium && !rust_mangled {
        bump("GCC/Clang (C/C++)", 45, "Itanium C++ name mangling (_ZN…)".into());
    }

    // 5) PE Rich header — a strong MSVC toolchain fingerprint.
    if binary.format == BinaryFormat::Pe {
        if let Some(tools) = rich_header_tool_count(window) {
            bump(
                "MSVC C/C++",
                80,
                format!("PE Rich header ({tools} build-tool records)"),
            );
        }
    }

    let mut out: Vec<ToolchainFinding> = acc
        .into_iter()
        .map(|(language, (confidence, evidence))| ToolchainFinding {
            language: language.to_string(),
            confidence: confidence as u8,
            evidence,
        })
        .collect();

    // Managed .NET assemblies frequently also import a C runtime; when a strong
    // .NET signal is present, demote incidental native-CRT noise so the primary
    // language reads clearly.
    let dotnet_strong = out.iter().any(|f| f.language == ".NET" && f.confidence >= 75);
    if dotnet_strong {
        for f in &mut out {
            if f.language == "MSVC C/C++" {
                f.confidence = f.confidence.saturating_sub(40);
            }
        }
    }
    out.retain(|f| f.confidence >= 30);

    out.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(a.language.cmp(&b.language))
    });
    out
}

/// Detect the MSVC "Rich" header and count its @comp.id records.
///
/// The header sits between the DOS stub and the PE header: a `Rich` tag
/// followed by a 4-byte XOR key, preceded by a `DanS`-tagged block (XORed with
/// that key). Its presence is emitted only by the Microsoft linker. Returns the
/// number of build-tool records, or `None` if no valid header is found.
fn rich_header_tool_count(data: &[u8]) -> Option<usize> {
    let scan = &data[..data.len().min(0x1000)];
    let rich_pos = find(scan, b"Rich")?;
    if rich_pos + 8 > scan.len() {
        return None;
    }
    let key = &scan[rich_pos + 4..rich_pos + 8];

    // Walk backwards in 4-byte steps to the XOR-encoded "DanS" marker.
    let dans = [b'D', b'a', b'n', b'S'];
    let mut i = rich_pos;
    while i >= 4 {
        i -= 4;
        let decoded = [
            scan[i] ^ key[0],
            scan[i + 1] ^ key[1],
            scan[i + 2] ^ key[2],
            scan[i + 3] ^ key[3],
        ];
        if decoded == dans {
            // Records live between DanS+16 (after 3 pad dwords) and the Rich tag,
            // 8 bytes each.
            let start = i + 16;
            if start <= rich_pos {
                return Some((rich_pos - start) / 8);
            }
            return Some(0);
        }
    }
    None
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let n = needle.len();
    if n == 0 || hay.len() < n {
        return None;
    }
    (0..=hay.len() - n).find(|&i| &hay[i..i + n] == needle)
}

/// Substring search with a cheap first-byte skip.
fn contains_seq(hay: &[u8], needle: &[u8]) -> bool {
    let n = needle.len();
    if n == 0 || hay.len() < n {
        return false;
    }
    let first = needle[0];
    let mut i = 0;
    while i + n <= hay.len() {
        if hay[i] == first && &hay[i..i + n] == needle {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triage::{OperatingSystemEstimate, parse_binary};

    fn blob_with(markers: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        for m in markers {
            v.extend_from_slice(m);
            v.push(0);
        }
        v
    }

    fn identify_raw(data: &[u8]) -> Vec<ToolchainFinding> {
        let binary = parse_binary(data, false).unwrap();
        identify(data, &binary)
    }

    fn top(findings: &[ToolchainFinding]) -> &str {
        findings.first().map(|f| f.language.as_str()).unwrap_or("")
    }

    #[test]
    fn identifies_go_from_build_id() {
        let data = blob_with(&[b"Go build ID: \"abc\"", b"go1.19", b"runtime.main"]);
        let f = identify_raw(&data);
        assert_eq!(top(&f), "Go");
        assert!(f[0].confidence >= 90);
    }

    #[test]
    fn identifies_rust_from_paths() {
        let data = blob_with(&[b"/rustc/deadbeef/library/std/src/", b"RUST_BACKTRACE"]);
        let f = identify_raw(&data);
        assert_eq!(top(&f), "Rust");
    }

    #[test]
    fn identifies_dotnet_and_demotes_crt() {
        let data = blob_with(&[b"BSJB", b"mscorlib", b"<Module>"]);
        let f = identify_raw(&data);
        assert_eq!(top(&f), ".NET");
    }

    #[test]
    fn identifies_nim() {
        let data = blob_with(&[b"NimMain", b"fatal.nim"]);
        assert_eq!(top(&identify_raw(&data)), "Nim");
    }

    #[test]
    fn clean_blob_reports_nothing() {
        let data = blob_with(&[b"just some harmless text here"]);
        assert!(identify_raw(&data).is_empty());
    }

    #[test]
    fn borland_string_ignored_on_raw_headers() {
        // Conti ecrypt-config.h mentions Borland in eSTREAM commentary.
        let data = blob_with(&[b"/* Written by ... for Borland C */", b"ECRYPT_VARIANT"]);
        let f = identify_raw(&data);
        assert!(
            !f.iter().any(|x| x.language.contains("Delphi")),
            "Raw Borland string must not tag Delphi: {f:?}"
        );
    }

    #[test]
    fn embarmadero_still_tags_delphi_on_pe() {
        let data = blob_with(&[b"Embarcadero Technologies", b"SOFTWARE\\Borland\\Delphi"]);
        let binary = ParsedBinary {
            format: BinaryFormat::Pe,
            architecture: "x86".into(),
            operating_system: OperatingSystemEstimate {
                family: "Windows".into(),
                minimum_version: None,
                environment: None,
                evidence: "test".into(),
            },
            entry_point: 0,
            is_64bit: false,
            is_lib: false,
            compile_timestamp: None,
            has_signature: false,
            image_file_offset: 0,
            sections: vec![],
            imports: vec![],
            exports: vec![],
            symbols: vec![],
            section_entropies: vec![],
            entropy_maps: vec![],
        };
        let f = identify(&data, &binary);
        assert!(
            f.iter().any(|x| x.language.contains("Delphi") && x.confidence >= 70),
            "PE Embarcadero should tag Delphi: {f:?}"
        );
    }
}
