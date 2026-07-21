//! Triage report aggregation.

use crate::heuristics::ThreatScore;
use crate::signatures::HashBundle;
use crate::triage::formats::ParsedBinary;

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    /// File offset of section contents (within the analyzed image slice).
    pub file_offset: u64,
    pub characteristics: String,
}

#[derive(Debug, Clone)]
pub struct TriageReport {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub binary: ParsedBinary,
    pub hashes: HashBundle,
    pub threat: ThreatScore,
    pub demangled_symbols: Vec<String>,
    pub packer_hints: Vec<String>,
}

/// Detect common packer/compiler fingerprints from section names & entropy.
pub fn detect_packer_hints(binary: &ParsedBinary) -> Vec<String> {
    let mut hints = Vec::new();
    let names: Vec<&str> = binary.sections.iter().map(|s| s.name.as_str()).collect();

    if names.iter().any(|n| n.contains("UPX")) {
        hints.push("UPX packer sections detected".into());
    }
    if names.iter().any(|n| n.contains("vmp") || n.contains("VMP")) {
        hints.push("VMProtect-like section names".into());
    }
    if names.iter().any(|n| *n == ".ndata" || n.contains("Themida")) {
        hints.push("Themida/WinLicense indicators".into());
    }

    let high = binary
        .section_entropies
        .iter()
        .filter(|e| e.high_entropy)
        .count();
    if high >= 1 {
        hints.push(format!(
            "{high} high-entropy section(s) (packed/compressed/encrypted payload likely)"
        ));
    }

    // Entry point in non-standard section
    if let Some(ep_sec) = binary.sections.iter().find(|s| {
        let start = s.virtual_address;
        let end = start.saturating_add(s.virtual_size);
        binary.entry_point >= start && binary.entry_point < end
    }) {
        let n = ep_sec.name.to_lowercase();
        if !matches!(n.as_str(), ".text" | "__text" | "text") && !n.contains("text") {
            hints.push(format!(
                "entry point in atypical section '{}'",
                ep_sec.name
            ));
        }
    }

    hints
}
