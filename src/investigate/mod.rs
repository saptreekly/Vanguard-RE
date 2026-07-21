//! Automated investigation pipeline — default `vanguard <path>` behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::containment::{EmbeddedArchive, QuarantinedSample};
use crate::crypto::{CryptoFinding, scan as scan_crypto};
use crate::disasm::{DisasmReport, ExtractedString, disassemble, interesting_strings};
use crate::heuristics::{CapabilityTag, ThreatScore, capability_summary, score_imports};
use crate::iocs::{IocKind, NetworkIoc, scan_data as scan_iocs};
use crate::secrets::{SecretCandidate, scan as scan_secrets};
use crate::signatures::{YaraMatch, build_hash_bundle, scan_yara};
use crate::toolchain::ToolchainFinding;
use crate::triage::{
    BinaryFormat, ImportEntry, TriageReport, detect_packer_hints, parse_binary_named,
};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct ImpHashCluster {
    pub imphash: String,
    pub members: Vec<String>,
    pub max_score: u8,
    /// VirusTotal intelligence pivot (open in browser; no API key required).
    pub virustotal_search: String,
}

#[derive(Debug, Clone)]
pub struct DeepDive {
    pub path: String,
    pub sha256: String,
    pub score: u8,
    pub reason: String,
    pub capabilities: Vec<CapabilityTag>,
    pub yara: Vec<YaraMatch>,
    pub interesting_strings: Vec<ExtractedString>,
    /// Hardcoded network indicators (C2 candidates) ranked by confidence.
    pub network_iocs: Vec<NetworkIoc>,
    /// Detected crypto schemes (constant fingerprints + crypto API imports).
    pub crypto: Vec<CryptoFinding>,
    /// ZIP archives carved from this sample's own bytes (encrypted payload
    /// bundles such as WannaCry's `.wnry` set), listed even when undecryptable.
    pub embedded_archives: Vec<EmbeddedArchive>,
    /// Heuristic password / credential candidates (shape-based, not proof).
    pub secrets: Vec<SecretCandidate>,
    /// Pre-grouped imports for the Imports tab (library → functions).
    pub grouped_imports: Vec<(String, Vec<String>)>,
    pub disasm: Option<DisasmReport>,
}

#[derive(Debug, Clone)]
pub struct InvestigationReport {
    pub source: String,
    pub sample_count: usize,
    pub triage: Vec<TriageReport>,
    pub ranking: Vec<(String, u8, String)>,
    pub imphash_clusters: Vec<ImpHashCluster>,
    pub yara_by_sample: Vec<(String, Vec<YaraMatch>)>,
    pub deep_dives: Vec<DeepDive>,
}

#[derive(Debug, Clone, Copy)]
pub struct InvestigateOptions<'a> {
    pub deep: usize,
    pub disasm_count: usize,
    pub yara_rules: Option<&'a Path>,
    pub min_deep_score: u8,
}

impl Default for InvestigateOptions<'_> {
    fn default() -> Self {
        Self {
            deep: 3,
            disasm_count: 512,
            yara_rules: None,
            min_deep_score: 70,
        }
    }
}

pub fn triage_sample(sample: &QuarantinedSample, entropy_map: bool) -> Result<TriageReport> {
    let binary = parse_binary_named(&sample.data, entropy_map, Some(sample.label.as_str()))?;
    let hashes = build_hash_bundle(&sample.data, &binary.imports);
    let mut threat = score_imports(&binary.imports);
    let demangled_symbols = crate::disasm::demangle_symbols(&binary.symbols);
    let mut packer_hints = detect_packer_hints(&binary);
    let toolchain = crate::toolchain::identify(&sample.data, &binary);

    // DOS COM: no IAT — still surface a useful verdict. Raw blobs no longer
    // get an automatic 35 (that flooded rankings with language packs / source).
    if binary.format == BinaryFormat::DosCom && threat.score < 20 {
        threat.score = threat.score.max(35);
        threat.label = "DOS COM / classic virus candidate (limited static analysis)".into();
        packer_hints.push(
            "Not PE/ELF/Mach-O — header triage limited; deep-dive still extracts strings/YARA"
                .into(),
        );
    }

    apply_managed_score_floor(&sample.data, &toolchain, &mut threat);
    apply_content_class_demotion(&sample.label, binary.format, &mut threat);

    Ok(TriageReport {
        path: sample.label.clone(),
        sha256: hashes.sha256.clone(),
        size: sample.data.len() as u64,
        binary,
        hashes,
        threat,
        demangled_symbols,
        packer_hints,
        toolchain,
    })
}

/// Managed PE IAT is usually just `_CorExeMain` — without a floor, AgentTesla
/// scores 0 while a `.cpp` source blob ranks at 35. Bump .NET samples based on
/// CLR confidence and stealer-shaped strings.
fn apply_managed_score_floor(
    data: &[u8],
    toolchain: &[ToolchainFinding],
    threat: &mut ThreatScore,
) {
    let Some(dotnet) = toolchain
        .iter()
        .find(|t| t.language == ".NET" && t.confidence >= 70)
    else {
        return;
    };

    let text = String::from_utf8_lossy(&data[..data.len().min(2 * 1024 * 1024)]).to_ascii_lowercase();
    let stealer_markers = [
        "login data",
        "web data",
        "user data",
        "cookies",
        "mozill",
        "chrome",
        "wallet.dat",
        "smtp",
        "telegram",
        "discord.com/api",
        "password",
        "keylog",
        "screenshot",
        "clipboard",
    ];
    let stealer_hits = stealer_markers.iter().filter(|m| text.contains(*m)).count();

    let floor = if stealer_hits >= 4 {
        75
    } else if stealer_hits >= 2 {
        60
    } else if stealer_hits >= 1 {
        50
    } else {
        // Still outrank demoted noise so managed malware is not invisible.
        40
    };

    if threat.score < floor {
        threat.score = floor;
        threat.label = format!(
            "{} — .NET managed (conf {})",
            if floor >= 70 {
                "high risk"
            } else if floor >= 40 {
                "likely malicious tooling"
            } else {
                "suspicious"
            },
            dotnet.confidence
        );
        if stealer_hits > 0 {
            threat.label.push_str(&format!(" / stealer-strings×{stealer_hits}"));
        }
    }
}

/// Demote source trees, build logs, and ransomware language packs so they
/// cannot outrank real PE/ELF payloads in ranking.
fn apply_content_class_demotion(path: &str, format: BinaryFormat, threat: &mut ThreatScore) {
    let class = classify_content(path, format);
    let (cap, label) = match class {
        ContentClass::LanguagePack => (5, "language/resource pack — demoted"),
        ContentClass::SourceBuild => (5, "source/build artifact — demoted"),
        ContentClass::LowInterestRaw => (10, "non-executable blob — demoted"),
        ContentClass::Interesting => return,
    };
    if threat.score > cap {
        threat.score = cap;
        threat.label = label.into();
    } else if threat.score > 0 {
        // Keep a tiny score but rewrite the misleading "suspicious" raw label.
        threat.label = label.into();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentClass {
    Interesting,
    LanguagePack,
    SourceBuild,
    LowInterestRaw,
}

fn classify_content(path: &str, format: BinaryFormat) -> ContentClass {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let file = Path::new(&lower)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(lower.as_str());
    let ext = Path::new(&lower)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    // WannaCry-style message packs: msg/m_english.wnry (not u/c/t.wnry payloads).
    if lower.contains("/msg/")
        || lower.contains("/lang/")
        || lower.contains("/locales/")
        || file.starts_with("m_") && matches!(ext, "wnry" | "dll" | "mui")
        || matches!(ext, "mui" | "nls")
    {
        return ContentClass::LanguagePack;
    }

    if matches!(
        ext,
        "c" | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hpp"
            | "hxx"
            | "cs"
            | "java"
            | "py"
            | "go"
            | "rs"
            | "sln"
            | "vcxproj"
            | "vcproj"
            | "pdb"
            | "idb"
            | "ilk"
            | "obj"
            | "o"
            | "a"
            | "lib"
            | "tlog"
            | "log"
            | "md"
            | "txt"
            | "rtf"
            | "xml"
            | "json"
            | "yml"
            | "yaml"
            | "toml"
            | "cmake"
            | "makefile"
    ) || file == "makefile"
        || file.ends_with(".tlog")
    {
        return ContentClass::SourceBuild;
    }

    // Generic raw/text leftovers that are not DOS COM / PE / ELF / Mach-O.
    if matches!(format, BinaryFormat::Raw | BinaryFormat::Unknown)
        && !matches!(ext, "exe" | "dll" | "sys" | "scr" | "com" | "elf" | "so" | "bin" | "wnry")
    {
        return ContentClass::LowInterestRaw;
    }

    ContentClass::Interesting
}

/// Full automated investigation over in-memory quarantined samples.
pub fn investigate(
    source: &str,
    samples: &[QuarantinedSample],
    opts: InvestigateOptions<'_>,
) -> Result<InvestigationReport> {
    // Entropy heatmaps are unused in the TUI today — skip the O(sections)
    // work on every sample (including ZIP children).
    let mut triage = Vec::with_capacity(samples.len());
    for s in samples {
        match triage_sample(s, false) {
            Ok(r) => triage.push(r),
            Err(e) => eprintln!("skip {}: {e:#}", s.label),
        }
    }

    triage.sort_by(|a, b| {
        b.threat
            .score
            .cmp(&a.threat.score)
            .then(a.path.cmp(&b.path))
    });

    let ranking: Vec<_> = triage
        .iter()
        .map(|r| (r.path.clone(), r.threat.score, r.threat.label.clone()))
        .collect();

    let imphash_clusters = cluster_imphash(&triage);

    let data_by_label: BTreeMap<&str, &[u8]> = samples
        .iter()
        .map(|s| (s.label.as_str(), s.data.as_slice()))
        .collect();
    let embedded_by_label: BTreeMap<&str, &[EmbeddedArchive]> = samples
        .iter()
        .map(|s| (s.label.as_str(), s.embedded_archives.as_slice()))
        .collect();

    // One YARA pass per sample — reused for ranking signals and deep-dives.
    let mut yara_hits: BTreeMap<String, Vec<YaraMatch>> = BTreeMap::new();
    for r in &triage {
        if let Some(data) = data_by_label.get(r.path.as_str()) {
            let hits = scan_yara(data, opts.yara_rules);
            if !hits.is_empty() {
                yara_hits.insert(r.path.clone(), hits);
            }
        }
    }
    let yara_by_sample: Vec<(String, Vec<YaraMatch>)> = yara_hits
        .iter()
        .map(|(path, hits)| (path.clone(), hits.clone()))
        .collect();

    // Deep-dive: top `deep` by score, plus any remaining with score >= min_deep_score.
    let mut deep_targets: Vec<&TriageReport> = triage.iter().take(opts.deep).collect();
    for r in triage.iter().skip(opts.deep) {
        if r.threat.score >= opts.min_deep_score {
            deep_targets.push(r);
        }
    }

    let mut deep_dives = Vec::new();
    for r in deep_targets {
        let Some(data) = data_by_label.get(r.path.as_str()) else {
            continue;
        };
        let yara = yara_hits.get(&r.path).cloned().unwrap_or_default();
        // Skip the disasm-internal string pass — investigate already extracts
        // strings from the full sample below (with_strings: false).
        let disasm = disassemble(&r.path, data, None, opts.disasm_count, false).ok();
        let strings = {
            let all = crate::disasm::extract_strings_ranked(data, 8_000);
            interesting_strings(&all).into_iter().take(120).collect()
        };

        let reason = {
            let caps = capability_summary(&r.threat.capabilities);
            let behaviors = r
                .threat
                .behaviors
                .iter()
                .map(|b| b.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            if !behaviors.is_empty() {
                format!("{behaviors}  |  caps: {caps}")
            } else if caps != "(none)" {
                format!("{}  |  caps: {caps}", r.threat.label)
            } else {
                r.threat.label.clone()
            }
        };

        let mut network_iocs = scan_iocs(data);
        // Merge indicators recovered from this sample's own decrypted embedded
        // members (e.g. WannaCry's `c.wnry` Tor C2 list, unlocked once the
        // inner ZIP password was cracked). Only hostname-class indicators are
        // pulled up: bare IPs buried inside a bundled Tor binary are that
        // component's infrastructure, not this sample's C2, and would mislead.
        let child_prefix = format!("{}::", r.path);
        for child in samples
            .iter()
            .filter(|s| s.label.starts_with(&child_prefix))
        {
            for ioc in scan_iocs(&child.data) {
                let hostname_class = matches!(
                    ioc.kind,
                    IocKind::Onion
                        | IocKind::Url
                        | IocKind::Domain
                        | IocKind::Email
                        | IocKind::Bitcoin
                );
                if hostname_class && !network_iocs.iter().any(|e| e.value == ioc.value) {
                    network_iocs.push(ioc);
                }
            }
        }
        network_iocs.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then(b.count.cmp(&a.count))
                .then(a.value.cmp(&b.value))
        });
        network_iocs.truncate(40);

        let crypto = scan_crypto(data, &r.binary.imports);
        let embedded_archives = embedded_by_label
            .get(r.path.as_str())
            .map(|a| a.to_vec())
            .unwrap_or_default();
        let secrets = scan_secrets(data);
        let grouped_imports = group_imports(&r.binary.imports);

        deep_dives.push(DeepDive {
            path: r.path.clone(),
            sha256: r.sha256.clone(),
            score: r.threat.score,
            reason,
            capabilities: r.threat.capabilities.clone(),
            yara,
            interesting_strings: strings,
            network_iocs,
            crypto,
            embedded_archives,
            secrets,
            grouped_imports,
            disasm,
        });
    }

    Ok(InvestigationReport {
        source: source.to_string(),
        sample_count: triage.len(),
        triage,
        ranking,
        imphash_clusters,
        yara_by_sample,
        deep_dives,
    })
}

fn group_imports(imports: &[ImportEntry]) -> Vec<(String, Vec<String>)> {
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for import in imports {
        map.entry(import.library.clone())
            .or_default()
            .insert(import.function.clone());
    }
    map.into_iter()
        .map(|(library, functions)| (library, functions.into_iter().collect()))
        .collect()
}

fn cluster_imphash(triage: &[TriageReport]) -> Vec<ImpHashCluster> {
    let mut map: BTreeMap<String, Vec<&TriageReport>> = BTreeMap::new();
    for r in triage {
        if let Some(h) = &r.hashes.imphash {
            map.entry(h.clone()).or_default().push(r);
        }
    }
    let mut clusters: Vec<_> = map
        .into_iter()
        .map(|(imphash, members)| {
            let max_score = members.iter().map(|m| m.threat.score).max().unwrap_or(0);
            let names: Vec<String> = members.iter().map(|m| short_name(&m.path)).collect();
            ImpHashCluster {
                virustotal_search: format!(
                    "https://www.virustotal.com/gui/search/imphash%3A{imphash}"
                ),
                imphash,
                members: names,
                max_score,
            }
        })
        .collect();
    clusters.sort_by(|a, b| {
        b.members
            .len()
            .cmp(&a.members.len())
            .then(b.max_score.cmp(&a.max_score))
    });
    clusters
}

pub fn short_name(path: &str) -> String {
    path.rsplit("::").next().unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::ThreatScore;

    fn blank_threat(score: u8) -> ThreatScore {
        ThreatScore {
            score,
            label: "suspicious".into(),
            behaviors: vec![],
            suspicious_apis: vec![],
            capabilities: vec![],
        }
    }

    #[test]
    fn demotes_wannacry_language_packs() {
        assert_eq!(
            classify_content("msg/m_english.wnry", BinaryFormat::Raw),
            ContentClass::LanguagePack
        );
        assert_eq!(
            classify_content("u.wnry", BinaryFormat::Raw),
            ContentClass::Interesting
        );
        let mut threat = blank_threat(35);
        apply_content_class_demotion("msg/m_chinese (simplified).wnry", BinaryFormat::Raw, &mut threat);
        assert_eq!(threat.score, 5);
    }

    #[test]
    fn demotes_source_and_tlog() {
        assert_eq!(
            classify_content("locker/main.cpp", BinaryFormat::Raw),
            ContentClass::SourceBuild
        );
        assert_eq!(
            classify_content("BuildLog.tlog", BinaryFormat::Raw),
            ContentClass::SourceBuild
        );
        let mut threat = blank_threat(35);
        apply_content_class_demotion("src/bot.c", BinaryFormat::Raw, &mut threat);
        assert_eq!(threat.score, 5);
    }

    #[test]
    fn managed_floor_lifts_dotnet_stealers() {
        let toolchain = vec![ToolchainFinding {
            language: ".NET".into(),
            confidence: 100,
            evidence: vec!["BSJB".into()],
        }];
        let data = b"Chrome Login Data cookies Web Data password keylog";
        let mut threat = blank_threat(0);
        apply_managed_score_floor(data, &toolchain, &mut threat);
        assert!(threat.score >= 60, "stealer .NET floor too low: {}", threat.score);
        assert!(threat.label.contains(".NET"));
    }
}
