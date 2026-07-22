use std::path::Path;

use vanguard_re::containment::{EmbeddedArchive, QuarantinedSample};
use vanguard_re::investigate::{short_name, InvestigationReport};
use vanguard_re::triage::BinaryFormat;

/// Options controlling how much detail the CLI dumps.
#[derive(Debug, Clone, Copy)]
pub struct PrintOptions {
    /// When true, print every member and every triage block (including demoted / score-0).
    pub full: bool,
}

impl Default for PrintOptions {
    fn default() -> Self {
        Self { full: false }
    }
}

const MEMBER_PREVIEW: usize = 12;
const RANKING_ZERO_COLLAPSE: usize = 8;
const TRIAGE_MIN_SCORE: u8 = 20;

/// Print the full investigation report to stdout (summary → ranking → clusters → triage → deep dives).
pub fn print_report(
    path: &Path,
    samples: &[QuarantinedSample],
    report: &InvestigationReport,
    opts: PrintOptions,
) {
    print_header(path, samples, opts);
    print_ranking(report, opts);
    print_imphash_clusters(report);
    print_triage(report, opts);
    print_deep_dives(report);
}

fn print_header(path: &Path, samples: &[QuarantinedSample], opts: PrintOptions) {
    println!("== VANGUARD-RE ==");
    println!("source  : {}", path.display());
    println!("members : {}", samples.len());

    if samples.is_empty() {
        return;
    }

    if opts.full || samples.len() <= MEMBER_PREVIEW {
        for s in samples {
            println!(
                "  - {:<40} {:>10}",
                truncate(&short_name(&s.label), 40),
                human_bytes(s.data.len() as u64)
            );
        }
        return;
    }

    // Compact preview: largest / first few by path order already collected,
    // plus a remainder line.
    let mut indexed: Vec<(usize, &QuarantinedSample)> = samples.iter().enumerate().collect();
    indexed.sort_by(|a, b| b.1.data.len().cmp(&a.1.data.len()));
    let preview: Vec<_> = indexed.into_iter().take(MEMBER_PREVIEW).collect();
    println!("  (top {MEMBER_PREVIEW} by size; use --full to list all)");
    for (_, s) in &preview {
        println!(
            "  - {:<40} {:>10}",
            truncate(&short_name(&s.label), 40),
            human_bytes(s.data.len() as u64)
        );
    }
    let rest = samples.len().saturating_sub(preview.len());
    if rest > 0 {
        let rest_bytes: u64 = samples
            .iter()
            .map(|s| s.data.len() as u64)
            .sum::<u64>()
            .saturating_sub(
                preview
                    .iter()
                    .map(|(_, s)| s.data.len() as u64)
                    .sum::<u64>(),
            );
        println!(
            "  … and {rest} more ({})",
            human_bytes(rest_bytes)
        );
    }
}

fn print_ranking(report: &InvestigationReport, opts: PrintOptions) {
    println!("\n== RANKING ({} samples) ==", report.sample_count);
    if report.ranking.is_empty() {
        println!("  (empty)");
        return;
    }

    let nonzero: Vec<(usize, &(String, u8, String))> = report
        .ranking
        .iter()
        .enumerate()
        .filter(|(_, (_, score, _))| *score > 0)
        .collect();
    let zero_count = report.ranking.len().saturating_sub(nonzero.len());

    println!("  {:>4}  {:>5}  {:<28}  {}", "#", "score", "name", "label");
    println!("  {}", "-".repeat(72));

    if opts.full {
        for (i, (name, score, label)) in report.ranking.iter().enumerate() {
            println!(
                "  [{i:>2}]  {score:>5}  {:<28}  {}",
                truncate(&short_name(name), 28),
                label
            );
        }
        return;
    }

    if nonzero.is_empty() {
        for (i, (name, score, label)) in report.ranking.iter().take(RANKING_ZERO_COLLAPSE).enumerate()
        {
            println!(
                "  [{i:>2}]  {score:>5}  {:<28}  {}",
                truncate(&short_name(name), 28),
                label
            );
        }
        if report.ranking.len() > RANKING_ZERO_COLLAPSE {
            println!(
                "  … {} more (use --full to list)",
                report.ranking.len() - RANKING_ZERO_COLLAPSE
            );
        }
        return;
    }

    for (i, (name, score, label)) in &nonzero {
        println!(
            "  [{i:>2}]  {score:>5}  {:<28}  {}",
            truncate(&short_name(name), 28),
            label
        );
    }
    if zero_count > 0 {
        println!("  … {zero_count} more at score 0 (use --full to list)");
    }
}

fn print_imphash_clusters(report: &InvestigationReport) {
    if report.imphash_clusters.is_empty() {
        return;
    }
    println!("\n== IMPHASH CLUSTERS ==");
    for c in &report.imphash_clusters {
        let members: Vec<_> = c.members.iter().map(|m| short_name(m)).collect();
        println!(
            "  {}  max_score={:<3}  members={}",
            c.imphash,
            c.max_score,
            members.join(", ")
        );
        println!("      VT: {}", c.virustotal_search);
    }
}

fn print_triage(report: &InvestigationReport, opts: PrintOptions) {
    let selected: Vec<_> = report
        .triage
        .iter()
        .filter(|t| {
            opts.full
                || t.threat.score >= TRIAGE_MIN_SCORE
                || matches!(
                    t.binary.format,
                    BinaryFormat::Pe | BinaryFormat::Elf | BinaryFormat::MachO
                )
        })
        .collect();

    let skipped = report.triage.len().saturating_sub(selected.len());
    println!(
        "\n== TRIAGE ({} of {} samples) ==",
        selected.len(),
        report.triage.len()
    );
    if skipped > 0 && !opts.full {
        println!("  (skipped {skipped} low-interest; use --full for all)");
    }

    for t in selected {
        println!("\n-- {} --", short_name(&t.path));
        println!("  path     : {}", t.path);
        println!("  sha256   : {}", t.sha256);
        println!("  size     : {}", human_bytes(t.size));
        println!(
            "  format   : {}  arch={}  entry=0x{:x}  lib={}",
            t.binary.format, t.binary.architecture, t.binary.entry_point, t.binary.is_lib
        );
        println!("  os guess : {}", t.binary.operating_system.display());
        if let Some(ts) = t.binary.compile_timestamp {
            println!("  compiled : 0x{ts:08x} ({ts})");
        }
        println!("  signed   : {}", t.binary.has_signature);
        print!("  hashes   : md5={}", t.hashes.md5);
        match &t.hashes.imphash {
            Some(h) => println!("  imphash={h}"),
            None => println!("  imphash=-"),
        }
        println!("  threat   : score={}  {}", t.threat.score, t.threat.label);

        if !t.toolchain.is_empty() {
            println!("  toolchain:");
            for tc in &t.toolchain {
                println!(
                    "    {} (conf {}) — {}",
                    tc.language,
                    tc.confidence,
                    tc.evidence.join("; ")
                );
            }
        }
        if !t.packer_hints.is_empty() {
            println!("  packer:");
            for h in &t.packer_hints {
                println!("    - {h}");
            }
        }
        if !t.binary.sections.is_empty() {
            println!("  sections:");
            for s in &t.binary.sections {
                let ent = t
                    .binary
                    .section_entropies
                    .iter()
                    .find(|e| e.name == s.name)
                    .map(|e| e.entropy)
                    .unwrap_or(0.0);
                println!(
                    "    {:<12} vaddr=0x{:<8x} vsize=0x{:<8x} raw=0x{:<8x} entropy={:.2}",
                    s.name, s.virtual_address, s.virtual_size, s.raw_size, ent
                );
            }
        }
        if !t.threat.behaviors.is_empty() {
            println!("  behaviors:");
            for b in &t.threat.behaviors {
                println!(
                    "    [{:>2}] {} — {}  ({})",
                    b.severity,
                    b.name,
                    b.description,
                    b.matched_apis.join(", ")
                );
            }
        }
        if !t.threat.capabilities.is_empty() {
            println!("  capabilities:");
            for c in &t.threat.capabilities {
                println!(
                    "    {} (conf {}) — {}  [{}]",
                    c.label,
                    c.confidence,
                    c.id,
                    c.evidence.join(", ")
                );
            }
        }
        if !t.threat.suspicious_apis.is_empty() {
            println!(
                "  suspicious apis: {}",
                t.threat.suspicious_apis.join(", ")
            );
        }
    }
}

fn print_deep_dives(report: &InvestigationReport) {
    if report.deep_dives.is_empty() {
        return;
    }
    println!("\n== DEEP DIVES ({}) ==", report.deep_dives.len());

    for d in &report.deep_dives {
        println!("\n## {}", short_name(&d.path));
        println!("  path   : {}", d.path);
        println!("  sha256 : {}", d.sha256);
        println!("  score  : {}  {}", d.score, d.reason);

        if !d.yara.is_empty() {
            println!("\n  -- YARA --");
            for y in &d.yara {
                let tags = if y.tags.is_empty() {
                    String::new()
                } else {
                    format!("  tags={}", y.tags.join(","))
                };
                match &y.namespace {
                    Some(ns) => println!("    {} (ns={ns}){tags}", y.rule),
                    None => println!("    {}{tags}", y.rule),
                }
            }
        }

        if !d.network_iocs.is_empty() {
            println!("\n  -- NETWORK IOCs --");
            println!("    {:>6}  {:>4}  {:>5}  {}", "kind", "conf", "count", "value");
            for ioc in &d.network_iocs {
                let priv_mark = if ioc.private { " priv" } else { "" };
                println!(
                    "    {:>6}  {:>4}  {:>5}  {}{priv_mark}",
                    ioc.kind.label(),
                    ioc.confidence,
                    ioc.count,
                    ioc.value
                );
            }
        }

        if !d.crypto.is_empty() {
            println!("\n  -- CRYPTO --");
            for c in &d.crypto {
                println!(
                    "    {} [{}] conf={} — {}",
                    c.name,
                    c.category.label(),
                    c.confidence,
                    c.evidence
                );
            }
        }

        if !d.secrets.is_empty() {
            println!("\n  -- SECRETS / CREDENTIAL CANDIDATES --");
            for s in &d.secrets {
                println!("    [{}] score={}  {}", s.kind.label(), s.score, s.value);
            }
        }

        if !d.embedded_archives.is_empty() {
            println!("\n  -- EMBEDDED ARCHIVES --");
            for a in &d.embedded_archives {
                print_embedded_archive(a);
            }
        }

        if !d.grouped_imports.is_empty() {
            println!("\n  -- IMPORTS (by library) --");
            for (lib, fns) in &d.grouped_imports {
                println!("    {lib} ({} fns)", fns.len());
                println!("      {}", fns.join(", "));
            }
        }

        if !d.interesting_strings.is_empty() {
            println!(
                "\n  -- INTERESTING STRINGS ({}) --",
                d.interesting_strings.len()
            );
            for s in &d.interesting_strings {
                println!(
                    "    @0x{:<8x} [{:<7}] {}",
                    s.offset,
                    s.encoding,
                    truncate(&s.value, 120)
                );
            }
        }

        if let Some(dis) = &d.disasm {
            println!(
                "\n  -- DISASM — arch={} start=0x{:x} insns={} functions={} --",
                dis.architecture,
                dis.start_address,
                dis.instructions.len(),
                dis.functions.len()
            );
            if !dis.insights.is_empty() {
                println!("    code insights:");
                for ins in &dis.insights {
                    println!(
                        "      [{:>2}] {} — {} hit(s)",
                        ins.severity,
                        ins.label,
                        ins.hits.len()
                    );
                }
            }
            let mut fns: Vec<_> = dis.functions.iter().collect();
            fns.sort_by(|a, b| b.interest.cmp(&a.interest));
            println!("    top functions by interest:");
            for f in fns.iter().take(12) {
                println!(
                    "      {:<28} start=0x{:<8x} interest={:>3} cluster='{}' callees={} callers={}",
                    truncate(&f.name, 28),
                    f.start,
                    f.interest,
                    f.cluster_label,
                    f.callees.len(),
                    f.callers.len()
                );
            }
        }
    }
}

fn print_embedded_archive(a: &EmbeddedArchive) {
    let enc = a.encrypted_count();
    println!(
        "    {}  offset={}  span={}  members={}  extracted={}  encrypted={}",
        a.label,
        a.offset,
        human_bytes(a.span as u64),
        a.member_count(),
        a.extracted,
        enc
    );
    if let Some(pw) = &a.recovered_password {
        println!("      recovered_password: {pw}");
    }
    let show = a.members.len().min(16);
    for m in a.members.iter().take(show) {
        let flag = if m.encrypted { "enc" } else { "   " };
        println!(
            "      [{flag}] {:<36} {:>10}",
            truncate(&m.name, 36),
            human_bytes(m.size)
        );
    }
    if a.members.len() > show {
        println!("      … and {} more members", a.members.len() - show);
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn truncate(s: &str, max: usize) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { '.' } else { c })
        .collect();
    if clean.chars().count() > max {
        let cut: String = clean.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_formats_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.00 KB");
        assert_eq!(human_bytes(3_514_368), "3.35 MB");
    }

    #[test]
    fn truncate_respects_char_count() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
    }
}
