use std::path::Path;

use vanguard_re::containment::QuarantinedSample;
use vanguard_re::investigate::InvestigationReport;

/// Print the full investigation report to stdout (ranking → clusters → triage → deep dives).
pub fn print_report(
    path: &Path,
    samples: &[QuarantinedSample],
    report: &InvestigationReport,
) {
    println!("== VANGUARD-RE ==");
    println!("source         : {}", path.display());
    println!("members        : {}", samples.len());
    for s in samples {
        println!("  - {:<48} {} bytes", s.label, s.data.len());
    }

    println!("\n== RANKING ({} samples) ==", report.sample_count);
    for (i, (name, score, label)) in report.ranking.iter().enumerate() {
        println!("  [{i}] score={score:>3}  {name}\n        {label}");
    }

    println!("\n== IMPHASH CLUSTERS ==");
    for c in &report.imphash_clusters {
        println!(
            "  imphash={}  max_score={}  members={:?}",
            c.imphash, c.max_score, c.members
        );
        println!("      VT: {}", c.virustotal_search);
    }

    for t in &report.triage {
        println!("\n================ TRIAGE: {} ================", t.path);
        println!("sha256   : {}", t.sha256);
        println!("size     : {} bytes", t.size);
        println!(
            "format   : {:?}  arch={}  entry=0x{:x}  lib={}",
            t.binary.format, t.binary.architecture, t.binary.entry_point, t.binary.is_lib
        );
        println!("os guess : {}", t.binary.operating_system.display());
        if let Some(ts) = t.binary.compile_timestamp {
            println!("compiled : 0x{ts:08x} ({ts})");
        }
        println!("signed   : {}", t.binary.has_signature);
        println!(
            "hashes   : md5={} imphash={:?}",
            t.hashes.md5, t.hashes.imphash
        );
        println!("threat   : score={} {}", t.threat.score, t.threat.label);
        if !t.toolchain.is_empty() {
            println!("toolchain:");
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
            println!("packer   :");
            for h in &t.packer_hints {
                println!("    - {h}");
            }
        }
        if !t.binary.sections.is_empty() {
            println!("sections :");
            for s in &t.binary.sections {
                let ent = t
                    .binary
                    .section_entropies
                    .iter()
                    .find(|e| e.name == s.name)
                    .map(|e| e.entropy)
                    .unwrap_or(0.0);
                println!(
                    "    {:<12} vaddr=0x{:<8x} vsize=0x{:<8x} raw=0x{:<8x} entropy={:.2} [{}]",
                    s.name, s.virtual_address, s.virtual_size, s.raw_size, ent, s.characteristics
                );
            }
        }
        if !t.threat.behaviors.is_empty() {
            println!("behaviors:");
            for b in &t.threat.behaviors {
                println!(
                    "    [{}] {} — {}  apis={:?}",
                    b.severity, b.name, b.description, b.matched_apis
                );
            }
        }
        if !t.threat.capabilities.is_empty() {
            println!("capabilities:");
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
            println!("suspicious apis: {}", t.threat.suspicious_apis.join(", "));
        }
    }

    for d in &report.deep_dives {
        println!("\n################ DEEP DIVE: {} ################", d.path);
        println!("sha256 : {}", d.sha256);
        println!("score  : {}  {}", d.score, d.reason);

        if !d.yara.is_empty() {
            println!("\n-- YARA --");
            for y in &d.yara {
                println!("  {} (ns={:?}) tags={:?}", y.rule, y.namespace, y.tags);
            }
        }

        if !d.network_iocs.is_empty() {
            println!("\n-- NETWORK IOCs --");
            for ioc in &d.network_iocs {
                println!(
                    "  [{}] conf={} count={} priv={} {}",
                    ioc.kind.label(),
                    ioc.confidence,
                    ioc.count,
                    ioc.private,
                    ioc.value
                );
            }
        }

        if !d.crypto.is_empty() {
            println!("\n-- CRYPTO --");
            for c in &d.crypto {
                println!(
                    "  {} [{}] conf={} — {}",
                    c.name,
                    c.category.label(),
                    c.confidence,
                    c.evidence
                );
            }
        }

        if !d.secrets.is_empty() {
            println!("\n-- SECRETS / CREDENTIAL CANDIDATES --");
            for s in &d.secrets {
                println!("  [{}] score={} {}", s.kind.label(), s.score, s.value);
            }
        }

        if !d.embedded_archives.is_empty() {
            println!("\n-- EMBEDDED ARCHIVES --");
            for a in &d.embedded_archives {
                println!("  archive @ offset {:?}", a);
            }
        }

        if !d.grouped_imports.is_empty() {
            println!("\n-- IMPORTS (by library) --");
            for (lib, fns) in &d.grouped_imports {
                println!("  {lib} ({} fns): {}", fns.len(), fns.join(", "));
            }
        }

        if !d.interesting_strings.is_empty() {
            println!(
                "\n-- INTERESTING STRINGS ({}) --",
                d.interesting_strings.len()
            );
            for s in &d.interesting_strings {
                println!(
                    "  @0x{:<8x} [{}] {}",
                    s.offset,
                    s.encoding,
                    truncate(&s.value, 160)
                );
            }
        }

        if let Some(dis) = &d.disasm {
            println!(
                "\n-- DISASM: arch={} start=0x{:x} insns={} functions={} --",
                dis.architecture,
                dis.start_address,
                dis.instructions.len(),
                dis.functions.len()
            );
            if !dis.insights.is_empty() {
                println!("  code insights:");
                for ins in &dis.insights {
                    println!(
                        "    [{}] {} — {} hit(s)",
                        ins.severity,
                        ins.label,
                        ins.hits.len()
                    );
                }
            }
            let mut fns: Vec<_> = dis.functions.iter().collect();
            fns.sort_by(|a, b| b.interest.cmp(&a.interest));
            println!("  top functions by interest:");
            for f in fns.iter().take(12) {
                println!(
                    "    {:<28} start=0x{:<8x} interest={:>3} cluster='{}' callees={} callers={}",
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

fn truncate(s: &str, max: usize) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { '.' } else { c })
        .collect();
    if clean.chars().count() > max {
        let cut: String = clean.chars().take(max).collect();
        format!("{cut}…")
    } else {
        clean
    }
}
