//! Automated investigation pipeline — default `vanguard <path>` behavior.

use std::collections::BTreeMap;
use std::path::Path;

use crate::containment::{EmbeddedArchive, QuarantinedSample};
use crate::crypto::{CryptoFinding, scan as scan_crypto};
use crate::disasm::{DisasmReport, ExtractedString, disassemble, interesting_strings};
use crate::heuristics::{CapabilityTag, capability_summary, score_imports};
use crate::iocs::{IocKind, NetworkIoc, scan_data as scan_iocs};
use crate::secrets::{SecretCandidate, scan as scan_secrets};
use crate::signatures::{YaraMatch, build_hash_bundle, scan_yara};
use crate::triage::{TriageReport, detect_packer_hints, parse_binary_named};
use crate::util::sha256_hex;
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

    // Raw / DOS COM: no IAT — still surface a useful verdict.
    if matches!(
        binary.format,
        crate::triage::BinaryFormat::DosCom | crate::triage::BinaryFormat::Raw
    ) && threat.score < 20
    {
        threat.score = threat.score.max(35);
        threat.label = match binary.format {
            crate::triage::BinaryFormat::DosCom => {
                "DOS COM / classic virus candidate (limited static analysis)".into()
            }
            _ => "unrecognized binary — hashes, entropy, YARA, strings only".into(),
        };
        packer_hints.push(
            "Not PE/ELF/Mach-O — header triage limited; deep-dive still extracts strings/YARA"
                .into(),
        );
    }

    Ok(TriageReport {
        path: sample.label.clone(),
        sha256: sha256_hex(&sample.data),
        size: sample.data.len() as u64,
        binary,
        hashes,
        threat,
        demangled_symbols,
        packer_hints,
        toolchain,
    })
}

/// Full automated investigation over in-memory quarantined samples.
pub fn investigate(
    source: &str,
    samples: &[QuarantinedSample],
    opts: InvestigateOptions<'_>,
) -> Result<InvestigationReport> {
    let mut triage = Vec::with_capacity(samples.len());
    for s in samples {
        match triage_sample(s, true) {
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

    let mut yara_by_sample = Vec::new();
    let data_by_label: BTreeMap<&str, &[u8]> = samples
        .iter()
        .map(|s| (s.label.as_str(), s.data.as_slice()))
        .collect();
    let embedded_by_label: BTreeMap<&str, &[EmbeddedArchive]> = samples
        .iter()
        .map(|s| (s.label.as_str(), s.embedded_archives.as_slice()))
        .collect();

    for r in &triage {
        if let Some(data) = data_by_label.get(r.path.as_str()) {
            let hits = scan_yara(data, opts.yara_rules);
            if !hits.is_empty() {
                yara_by_sample.push((r.path.clone(), hits));
            }
        }
    }

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
        let yara = scan_yara(data, opts.yara_rules);
        let disasm = disassemble(&r.path, data, None, opts.disasm_count, true).ok();
        // Always extract from the full sample — do not reuse the disasm window's
        // truncated string list (packed samples bury C2 domains under noise).
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
