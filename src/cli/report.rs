use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use vanguard_re::containment::{EmbeddedArchive, QuarantinedSample};
use vanguard_re::iocs::IocKind;
use vanguard_re::investigate::{short_name, DeepDive, InvestigationReport, NetworkFindings};
use vanguard_re::triage::TriageReport;

use super::style::{ColorChoice, Style};

/// Options controlling how much detail the CLI dumps.
#[derive(Debug, Clone, Copy)]
pub struct PrintOptions {
    /// When true, print every member and every triage block (including demoted / score-0).
    pub full: bool,
    /// ANSI color preference for the report.
    pub color: ColorChoice,
}

impl Default for PrintOptions {
    fn default() -> Self {
        Self {
            full: false,
            color: ColorChoice::Auto,
        }
    }
}

const RANKING_SHOW: usize = 12;
const STRING_CAP: usize = 40;
const EMBEDDED_MEMBER_CAP: usize = 12;
const IMPORT_WRAP: usize = 72;
const RULE: &str = "────────────────────────────────────────────────────────────";

/// Print the investigation report: summary → ranking → ImpHash → C2 → samples.
pub fn print_report(
    path: &Path,
    samples: &[QuarantinedSample],
    report: &InvestigationReport,
    opts: PrintOptions,
) {
    let sty = Style::from_preference(opts.color);
    print_banner(path, samples, report, sty);
    print_ranking(report, opts, sty);
    print_imphash_clusters(report, sty);
    print_c2_section(report, sty);
    print_samples(report, opts, sty);
}

fn print_section_title(sty: Style, title: &str) {
    println!("\n{}", sty.section(title));
    println!("{}", sty.rule(RULE));
}

fn print_banner(
    path: &Path,
    samples: &[QuarantinedSample],
    report: &InvestigationReport,
    sty: Style,
) {
    let total_bytes: u64 = samples.iter().map(|s| s.data.len() as u64).sum();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for t in &report.triage {
        *counts.entry(t.binary.format.to_string()).or_default() += 1;
    }
    let mix = if counts.is_empty() {
        "none".into()
    } else {
        counts
            .iter()
            .map(|(k, n)| format!("{k}={n}"))
            .collect::<Vec<_>>()
            .join(" ")
    };

    println!("{}", sty.brand("VANGUARD-RE"));
    println!("{}", sty.rule(RULE));
    println!("{}", sty.field("source", &path.display().to_string()));
    println!(
        "{}",
        sty.field(
            "members",
            &format!("{}  ·  {}  ·  {}", samples.len(), human_bytes(total_bytes), mix)
        )
    );
    if let Some((name, score, label)) = report.ranking.first() {
        println!(
            "{}",
            sty.field(
                "top hit",
                &format!(
                    "{}  {}  {}",
                    sty.emph(&display_name(name)),
                    sty.badge(*score),
                    sty.label(label, *score)
                )
            )
        );
    }
    println!(
        "{}",
        sty.field(
            "deep",
            &format!(
                "{} sample(s)  ·  clusters {}",
                report.deep_dives.len(),
                report.imphash_clusters.len()
            )
        )
    );
}

fn print_ranking(report: &InvestigationReport, opts: PrintOptions, sty: Style) {
    print_section_title(sty, "RANKING");
    if report.ranking.is_empty() {
        println!("  {}", sty.dim("(empty)"));
        return;
    }

    let nonzero: Vec<(usize, &(String, u8, String))> = report
        .ranking
        .iter()
        .enumerate()
        .filter(|(_, (_, score, _))| *score > 0)
        .collect();
    let zero = report.ranking.len() - nonzero.len();

    let rows: Vec<(usize, &(String, u8, String))> = if opts.full {
        report.ranking.iter().enumerate().collect()
    } else {
        nonzero.iter().copied().take(RANKING_SHOW).collect()
    };

    println!(
        "  {}  {}  {}  {}",
        sty.dim(&format!("{:>3}", "#")),
        sty.dim(&format!("{:>5}", "score")),
        sty.dim(&format!("{:<22}", "name")),
        sty.dim("label")
    );
    for (i, (name, score, label)) in &rows {
        println!(
            "  {i:>3}  {}  {:<22}  {}",
            sty.score_text(*score, &format!("{score:>5}")),
            truncate(&display_name(name), 22),
            sty.label(label, *score)
        );
    }
    if !opts.full {
        let mut notes = Vec::new();
        if nonzero.len() > rows.len() {
            notes.push(format!("{} more scored", nonzero.len() - rows.len()));
        }
        if zero > 0 {
            notes.push(format!("{zero} at score 0"));
        }
        if !notes.is_empty() {
            println!(
                "  {} {}  (use --full)",
                sty.dim("…"),
                sty.dim(&notes.join(" · "))
            );
        }
    }
}

fn print_imphash_clusters(report: &InvestigationReport, sty: Style) {
    let clusters: Vec<_> = report
        .imphash_clusters
        .iter()
        .filter(|c| c.members.len() > 1 || c.max_score >= 40)
        .collect();
    if clusters.is_empty() {
        return;
    }
    print_section_title(sty, "IMPHASH");
    for c in clusters {
        let members: Vec<_> = c.members.iter().map(|m| display_name(m)).collect();
        println!(
            "  {}  max={}  {}",
            sty.hash(&c.imphash),
            sty.score_text(c.max_score, &format!("{:<3}", c.max_score)),
            members.join(", ")
        );
    }
}

fn print_c2_section(report: &InvestigationReport, sty: Style) {
    if report.network_findings.is_empty() {
        return;
    }
    print_section_title(sty, "C2");
    println!(
        "  {}",
        sty.dim("Hardcoded hosts/IPs from sample strings — nothing resolved or contacted")
    );
    for n in &report.network_findings {
        let top = n
            .iocs
            .iter()
            .take(3)
            .map(|i| i.value.as_str())
            .collect::<Vec<_>>()
            .join("  ·  ");
        let extra = n.iocs.len().saturating_sub(3);
        let dns = if n.dns_apis.is_empty() {
            String::new()
        } else {
            format!("  dns={}", n.dns_apis.join(","))
        };
        let more = if extra > 0 {
            format!("  (+{extra})")
        } else {
            String::new()
        };
        println!(
            "  {}  {}{}{}",
            sty.emph(&truncate(&display_name(&n.path), 28)),
            if top.is_empty() {
                sty.dim("DNS APIs only").to_string()
            } else {
                top
            },
            more,
            sty.dim(&dns)
        );
    }
}

fn print_samples(report: &InvestigationReport, opts: PrintOptions, sty: Style) {
    let deep_by_sha: std::collections::HashMap<&str, &DeepDive> = report
        .deep_dives
        .iter()
        .map(|d| (d.sha256.as_str(), d))
        .collect();
    let net_by_sha: std::collections::HashMap<&str, &NetworkFindings> = report
        .network_findings
        .iter()
        .map(|n| (n.sha256.as_str(), n))
        .collect();

    let mut ordered: Vec<&TriageReport> = report
        .triage
        .iter()
        .filter(|t| should_print_sample(t, opts))
        .collect();
    ordered.sort_by(|a, b| {
        b.threat
            .score
            .cmp(&a.threat.score)
            .then(a.path.cmp(&b.path))
            .then(a.sha256.cmp(&b.sha256))
    });

    let skipped = report.triage.len().saturating_sub(ordered.len());
    println!("\n{}  ({})", sty.section("SAMPLES"), ordered.len());
    if skipped > 0 && !opts.full {
        println!(
            "  {}",
            sty.dim(&format!(
                "skipped {skipped} low-interest  ·  use --full for all"
            ))
        );
    }

    for t in ordered {
        let deep = deep_by_sha.get(t.sha256.as_str()).copied();
        let net = net_by_sha.get(t.sha256.as_str()).copied();
        print_sample_block(t, deep, net, opts, sty);
    }
}

fn should_print_sample(t: &TriageReport, opts: PrintOptions) -> bool {
    opts.full || t.threat.score >= 20 || t.binary.format.is_executable()
}

fn print_sample_block(
    t: &TriageReport,
    deep: Option<&DeepDive>,
    net: Option<&NetworkFindings>,
    opts: PrintOptions,
    sty: Style,
) {
    let name = display_name(&t.path);
    println!();
    println!(
        "{} {}  {}  {}",
        sty.rule("──"),
        sty.emph(&truncate(&name, 40)),
        sty.badge(t.threat.score),
        sty.label(&t.threat.label, t.threat.score)
    );

    println!("{}", sty.field("member", &member_path(&t.path)));
    println!("{}", sty.field("sha256", &sty.hash(&t.sha256)));
    println!(
        "             {}",
        sty.url(&format!(
            "https://www.virustotal.com/gui/file/{}",
            t.sha256
        ))
    );
    println!("{}", sty.field("md5", &sty.hash(&t.hashes.md5)));
    if let Some(h) = &t.hashes.imphash {
        println!("{}", sty.field("imphash", &sty.hash(h)));
    }

    let mut identity = vec![
        t.binary.format.to_string(),
        t.binary.architecture.clone(),
        human_bytes(t.size),
    ];
    if t.binary.is_lib {
        identity.push("library".into());
    }
    if t.binary.has_signature {
        identity.push("signed".into());
    } else {
        identity.push("unsigned".into());
    }
    identity.push(t.binary.operating_system.display());
    println!("{}", sty.field("identity", &identity.join(" · ")));
    println!(
        "{}",
        sty.field(
            "entry",
            &sty.hash(&format!("0x{:x}", t.binary.entry_point))
        )
    );
    if let Some(ts) = t.binary.compile_timestamp {
        println!("{}", sty.field("compiled", &format_compile_time(ts)));
    }

    if let Some(tc) = t.toolchain.first() {
        println!(
            "{}",
            sty.field(
                "toolchain",
                &format!(
                    "{} (conf {}) — {}",
                    tc.language,
                    tc.confidence,
                    tc.evidence
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            )
        );
    }
    if !t.packer_hints.is_empty() {
        println!(
            "{}",
            sty.field("packer", &sty.packed(&t.packer_hints.join("; ")))
        );
    }

    if !t.binary.sections.is_empty() {
        println!();
        println!("  {}", sty.key("sections"));
        for s in &t.binary.sections {
            let ent = t
                .binary
                .section_entropies
                .iter()
                .find(|e| e.name == s.name)
                .map(|e| e.entropy)
                .unwrap_or(0.0);
            let ent_text = format!("{ent:.2}");
            let flag = if ent >= 7.0 {
                format!("  {}", sty.packed("packed?"))
            } else {
                String::new()
            };
            println!(
                "    {:<10}  {:<10}  {}{flag}",
                s.name,
                human_bytes(s.raw_size),
                sty.entropy(ent, &ent_text)
            );
        }
    }

    if !t.threat.capabilities.is_empty() {
        println!();
        println!("  {}", sty.key("caps"));
        for c in &t.threat.capabilities {
            // Pad before coloring so ANSI codes do not break the column.
            println!(
                "    {}  {}  {}",
                sty.confidence_text(c.confidence, &format!("{:>3}", c.confidence)),
                sty.cap_id(&format!("{:<14}", c.id)),
                sty.dim(&c.evidence.join(", "))
            );
        }
    }
    if !t.threat.behaviors.is_empty() {
        println!();
        println!("  {}", sty.key("behaviors"));
        for b in &t.threat.behaviors {
            println!(
                "    {}  {}  {}",
                sty.confidence_text(b.severity, &format!("{:>3}", b.severity)),
                sty.cap_id(&format!("{:<22}", b.name)),
                sty.dim(&format!("({})", b.matched_apis.join(", ")))
            );
        }
    }
    if !t.threat.suspicious_apis.is_empty() && opts.full {
        println!();
        println!(
            "{}",
            sty.field(
                "suspicious",
                &sty.dim(&t.threat.suspicious_apis.join(", "))
            )
        );
    }

    // Network / C2: prefer deep-dive (includes embedded-child merge), else triage scan.
    let network = deep
        .map(|d| d.network_iocs.as_slice())
        .filter(|v| !v.is_empty())
        .or_else(|| net.map(|n| n.iocs.as_slice()));
    let dns_apis = net.map(|n| n.dns_apis.as_slice()).unwrap_or(&[]);
    if network.is_some() || !dns_apis.is_empty() {
        println!();
        println!("  {}", sty.key("network"));
        if !dns_apis.is_empty() {
            println!("    {}  {}", sty.dim("dns"), sty.dim(&dns_apis.join(", ")));
        }
        if let Some(iocs) = network {
            for ioc in iocs {
                let priv_mark = if ioc.private {
                    format!("  {}", sty.dim("private"))
                } else {
                    String::new()
                };
                let kind = match ioc.kind {
                    IocKind::Ipv6 | IocKind::Ipv6Port => sty.hash(ioc.kind.label()),
                    IocKind::Ipv4 | IocKind::Ipv4Port => sty.hash(ioc.kind.label()),
                    IocKind::Domain | IocKind::Url | IocKind::Onion => sty.cap_id(ioc.kind.label()),
                    other => other.label().to_string(),
                };
                println!(
                    "    {:<8}  conf={}  {}{priv_mark}",
                    kind,
                    sty.confidence_text(ioc.confidence, &format!("{:<3}", ioc.confidence)),
                    ioc.value
                );
            }
        }
    }

    let Some(d) = deep else {
        return;
    };

    if !d.crypto.is_empty() {
        println!();
        println!("  {}", sty.key("crypto"));
        for c in &d.crypto {
            println!(
                "    {}  {} [{}] — {}",
                sty.confidence_text(c.confidence, &format!("{:>3}", c.confidence)),
                sty.cap_id(&c.name),
                c.category.label(),
                sty.dim(&c.evidence)
            );
        }
    }

    if !d.xor_recoveries.is_empty() {
        println!();
        println!("  {}", sty.key("xor"));
        for x in &d.xor_recoveries {
            let peers = if x.peers.is_empty() {
                String::new()
            } else {
                format!("  peers={}", x.peers.join(","))
            };
            println!(
                "    {}  conf={}  {}  span={}{peers}",
                x.scheme(),
                x.confidence,
                sty.hash(&format!("@0x{:x}", x.offset)),
                human_bytes(x.length as u64),
            );
            println!("      {} {}", sty.key("key"), x.key_display());
            if !x.preview.is_empty() {
                println!("      {} \"{}\"", sty.key("plain"), x.preview);
            }
            if !x.evidence.is_empty() {
                println!("      {} {}", sty.key("note"), sty.dim(&x.evidence));
            }
        }
    }

    if !d.secrets.is_empty() {
        let secrets: Vec<_> = d.secrets.iter().filter(|s| s.score >= 75).take(8).collect();
        if !secrets.is_empty() {
            println!();
            println!("  {}", sty.key("secrets"));
            for s in secrets {
                println!(
                    "    {}  [{}]  {}",
                    sty.confidence_text(s.score, &format!("{:>3}", s.score)),
                    s.kind.label(),
                    s.value
                );
            }
        }
    }

    if !d.yara.is_empty() {
        println!();
        println!("  {}", sty.key("yara"));
        for y in &d.yara {
            println!("    {}", y.rule);
        }
    }

    if !d.embedded_archives.is_empty() {
        println!();
        println!("  {}", sty.key("embedded"));
        for a in &d.embedded_archives {
            print_embedded_archive(a, opts, sty);
        }
    }

    if !d.grouped_imports.is_empty() {
        println!();
        print_imports(&d.grouped_imports, opts, sty);
    }

    if !d.interesting_strings.is_empty() {
        println!();
        print_strings(&d.interesting_strings, opts, sty);
    }

    if let Some(dis) = &d.disasm {
        println!();
        println!(
            "{}",
            sty.field(
                "disasm",
                &format!(
                    "{}  start={}  {} insn  {} fn",
                    dis.architecture,
                    sty.hash(&format!("0x{:x}", dis.start_address)),
                    dis.instructions.len(),
                    dis.functions.len()
                )
            )
        );
        if !dis.insights.is_empty() {
            for ins in &dis.insights {
                println!(
                    "    {}  {}  {}  ({} hits)",
                    sty.dim("insight"),
                    sty.confidence_text(ins.severity, &format!("{:>2}", ins.severity)),
                    ins.label,
                    ins.hits.len()
                );
            }
        }
        let mut fns: Vec<_> = dis.functions.iter().collect();
        fns.sort_by(|a, b| b.interest.cmp(&a.interest));
        let show = if opts.full { 12 } else { 6 };
        for f in fns.iter().take(show) {
            if f.interest == 0 && !opts.full {
                continue;
            }
            println!(
                "    fn  interest={}  {}  {:<24}  {}",
                sty.confidence_text(f.interest, &format!("{:>3}", f.interest)),
                sty.hash(&format!("0x{:<8x}", f.start)),
                truncate(&f.name, 24),
                sty.dim(&f.cluster_label)
            );
        }
    }
}

fn print_imports(grouped: &[(String, Vec<String>)], opts: PrintOptions, sty: Style) {
    println!("  {}", sty.key("imports"));
    for (lib, fns) in grouped {
        let lower = lib.to_ascii_lowercase();
        let is_crt = lower.contains("msvcr")
            || lower.contains("msvcp")
            || lower.contains("ucrt")
            || lower.contains("vcruntime")
            || lower == "libgcc_s_dw2-1.dll";
        if is_crt && !opts.full {
            println!(
                "    {}  {}",
                sty.lib(lib),
                sty.dim(&format!("({} crt helpers — hidden, use --full)", fns.len()))
            );
            continue;
        }
        let interesting: Vec<&String> = fns
            .iter()
            .filter(|f| opts.full || !is_mangled(f))
            .collect();
        if interesting.is_empty() {
            println!(
                "    {}  {}",
                sty.lib(lib),
                sty.dim(&format!("({} fns)", fns.len()))
            );
            continue;
        }
        println!(
            "    {}  {}",
            sty.lib(lib),
            sty.dim(&format!("({})", interesting.len()))
        );
        let joined = interesting
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        for chunk in wrap_line(&joined, IMPORT_WRAP) {
            println!("      {}", sty.dim(&chunk));
        }
    }
}

fn print_strings(
    strings: &[vanguard_re::disasm::ExtractedString],
    opts: PrintOptions,
    sty: Style,
) {
    let filtered: Vec<_> = strings
        .iter()
        .filter(|s| opts.full || is_interesting_string(&s.value))
        .collect();
    let cap = if opts.full {
        filtered.len()
    } else {
        STRING_CAP.min(filtered.len())
    };
    println!(
        "  {}  {}",
        sty.key("strings"),
        sty.dim(&format!("showing {cap} of {}", strings.len()))
    );
    for s in filtered.iter().take(cap) {
        println!(
            "    {}  {}",
            sty.dim(&format!("@0x{:<8x}", s.offset)),
            truncate(&s.value, 90)
        );
    }
    if filtered.len() > cap {
        println!("    {} {} more", sty.dim("…"), filtered.len() - cap);
    }
}

fn print_embedded_archive(a: &EmbeddedArchive, opts: PrintOptions, sty: Style) {
    println!(
        "    {}  @{}  span={}  members={}  extracted={}  encrypted={}",
        a.label,
        a.offset,
        human_bytes(a.span as u64),
        a.member_count(),
        a.extracted,
        a.encrypted_count()
    );
    if let Some(pw) = &a.recovered_password {
        println!("      {} {}", sty.key("password"), pw);
    }

    let (priority, rest): (Vec<_>, Vec<_>) = a
        .members
        .iter()
        .partition(|m| {
            let n = m.name.to_ascii_lowercase();
            !n.contains("/msg/") && !n.contains("m_") && !n.ends_with(".wnry")
                || n.ends_with("u.wnry")
                || n.ends_with(".exe")
                || n.ends_with(".dll")
                || n == "c.wnry"
                || n == "b.wnry"
                || n == "s.wnry"
                || n == "t.wnry"
                || n == "r.wnry"
        });

    // Default: payloads/helpers only. --full lists everything.
    let list: Vec<_> = if opts.full {
        a.members.iter().collect()
    } else if !priority.is_empty() {
        priority
    } else {
        rest.into_iter().take(EMBEDDED_MEMBER_CAP).collect()
    };
    for m in &list {
        let flag = if m.encrypted { "enc" } else { "   " };
        println!(
            "      [{flag}]  {:<34}  {:>9}",
            truncate(&m.name, 34),
            human_bytes(m.size)
        );
    }
    let shown = list.len();
    let remaining = a.members.len().saturating_sub(shown);
    if remaining > 0 {
        let msg_n = a
            .members
            .iter()
            .filter(|m| {
                let n = m.name.to_ascii_lowercase();
                n.contains("/msg/") || n.contains("m_") && n.contains(".wnry")
            })
            .count();
        if msg_n > 0 && !opts.full {
            println!(
                "      {} {}",
                sty.dim("…"),
                sty.dim(&format!("{remaining} more ({msg_n} language packs)"))
            );
        } else {
            println!("      {} {} more", sty.dim("…"), remaining);
        }
    }
}

/// Prefer nested member path over absolute host path for display.
fn member_path(path: &str) -> String {
    if let Some(idx) = path.find(".zip::") {
        // Keep from the archive member onward when possible.
        let after = &path[idx + 5..]; // starts with "::..."
        let trimmed = after.trim_start_matches(':');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some((_, rest)) = path.split_once("::") {
        return rest.to_string();
    }
    path.to_string()
}

/// Short label for tables: basename, with hash-like names compacted.
fn display_name(path: &str) -> String {
    let name = short_name(path);
    compact_hash_name(&name)
}

fn compact_hash_name(name: &str) -> String {
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 && i < name.len() - 1 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let hexish = stem.len() >= 32 && stem.chars().all(|c| c.is_ascii_hexdigit());
    if hexish {
        format!("{}…{}", &stem[..8], ext)
    } else if name.len() > 36 {
        truncate(name, 36)
    } else {
        name.to_string()
    }
}

fn format_compile_time(ts: u32) -> String {
    let Ok(datetime) = UNIX_EPOCH
        .checked_add(Duration::from_secs(ts as u64))
        .ok_or(())
    else {
        return format!("0x{ts:08x} ({ts})");
    };
    // Manual UTC date without chrono dependency.
    let secs = datetime
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d, hh, mm, ss) = civil_from_days(secs);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC  (0x{ts:08x})")
}

/// Days since Unix epoch → civil date (Howard Hinnant algorithm, UTC).
fn civil_from_days(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let ss = (secs % 60) as u32;
    let mins = secs / 60;
    let mm = (mins % 60) as u32;
    let hours = mins / 60;
    let hh = (hours % 24) as u32;
    let days = (hours / 24) as i64;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, hh, mm, ss)
}

fn is_mangled(s: &str) -> bool {
    s.starts_with('?') || s.starts_with("_Z") || s.contains("@@")
}

fn is_interesting_string(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if is_mangled(s) {
        return false;
    }
    if lower.ends_with(".dll") || lower.ends_with(".so") || lower.ends_with(".dylib") {
        return false;
    }
    // WannaCry language-pack path dumps dominate otherwise.
    if lower.contains("msg/m_")
        || lower.contains("/m_")
        || (lower.starts_with("m_") && lower.contains(".wnry"))
    {
        return false;
    }
    if lower.starts_with("microsoft visual") || lower.contains("runtime error") {
        return false;
    }
    true
}

fn wrap_line(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for part in s.split(", ") {
        let next = if cur.is_empty() {
            part.to_string()
        } else {
            format!("{cur}, {part}")
        };
        if next.chars().count() > width && !cur.is_empty() {
            out.push(cur);
            cur = part.to_string();
        } else {
            cur = next;
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
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

    #[test]
    fn compact_hash_names() {
        let long = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe";
        assert_eq!(compact_hash_name(long), "ed01ebfb….exe");
        assert_eq!(compact_hash_name("u.wnry"), "u.wnry");
    }

    #[test]
    fn member_path_strips_host_prefix() {
        let p = "/Users/x/Malware/Ransomware.WannaCry.zip::ed01.exe::embedded-1.zip::u.wnry";
        assert_eq!(member_path(p), "ed01.exe::embedded-1.zip::u.wnry");
    }

    #[test]
    fn compile_time_formats_utc() {
        // 2010-11-20-ish WannaCry dropper stamp 0x4ce78f41
        let s = format_compile_time(0x4ce78f41);
        assert!(s.contains("UTC"), "{s}");
        assert!(s.contains("0x4ce78f41"), "{s}");
    }
}
