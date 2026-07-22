use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use vanguard_re::containment::{EmbeddedArchive, QuarantinedSample};
use vanguard_re::investigate::{short_name, DeepDive, InvestigationReport};
use vanguard_re::triage::TriageReport;

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

const RANKING_SHOW: usize = 12;
const STRING_CAP: usize = 40;
const EMBEDDED_MEMBER_CAP: usize = 12;
const RULE: &str = "────────────────────────────────────────────────────────────";

/// Print the investigation report: summary → ranking → ImpHash → per-sample blocks.
pub fn print_report(
    path: &Path,
    samples: &[QuarantinedSample],
    report: &InvestigationReport,
    opts: PrintOptions,
) {
    print_banner(path, samples, report);
    print_ranking(report, opts);
    print_imphash_clusters(report);
    print_samples(report, opts);
}

fn print_banner(path: &Path, samples: &[QuarantinedSample], report: &InvestigationReport) {
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

    println!("VANGUARD-RE");
    println!("{RULE}");
    println!("  source   {}", path.display());
    println!(
        "  members  {}  ·  {}  ·  {}",
        samples.len(),
        human_bytes(total_bytes),
        mix
    );
    if let Some((name, score, label)) = report.ranking.first() {
        println!(
            "  top hit  {}  score={}  {}",
            display_name(name),
            score,
            label
        );
    }
    println!(
        "  deep     {} sample(s)  ·  clusters {}",
        report.deep_dives.len(),
        report.imphash_clusters.len()
    );
}

fn print_ranking(report: &InvestigationReport, opts: PrintOptions) {
    println!("\nRANKING");
    println!("{RULE}");
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
    let zero = report.ranking.len() - nonzero.len();

    let rows: Vec<(usize, &(String, u8, String))> = if opts.full {
        report.ranking.iter().enumerate().collect()
    } else {
        nonzero.iter().copied().take(RANKING_SHOW).collect()
    };

    println!("  {:>3}  {:>5}  {:<22}  {}", "#", "score", "name", "label");
    for (i, (name, score, label)) in &rows {
        println!(
            "  {i:>3}  {score:>5}  {:<22}  {}",
            truncate(&display_name(name), 22),
            label
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
            println!("  … {}  (use --full)", notes.join(" · "));
        }
    }
}

fn print_imphash_clusters(report: &InvestigationReport) {
    let clusters: Vec<_> = report
        .imphash_clusters
        .iter()
        .filter(|c| c.members.len() > 1 || c.max_score >= 40)
        .collect();
    if clusters.is_empty() {
        return;
    }
    println!("\nIMPHASH");
    println!("{RULE}");
    for c in clusters {
        let members: Vec<_> = c.members.iter().map(|m| display_name(m)).collect();
        println!(
            "  {}  max={:<3}  {}",
            c.imphash,
            c.max_score,
            members.join(", ")
        );
        println!("           {}", c.virustotal_search);
    }
}

fn print_samples(report: &InvestigationReport, opts: PrintOptions) {
    let deep_by_sha: std::collections::HashMap<&str, &DeepDive> = report
        .deep_dives
        .iter()
        .map(|d| (d.sha256.as_str(), d))
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
    println!("\nSAMPLES  ({})", ordered.len());
    if skipped > 0 && !opts.full {
        println!("  skipped {skipped} low-interest  ·  use --full for all");
    }

    for t in ordered {
        let deep = deep_by_sha.get(t.sha256.as_str()).copied();
        print_sample_block(t, deep, opts);
    }
}

fn should_print_sample(t: &TriageReport, opts: PrintOptions) -> bool {
    opts.full || t.threat.score >= 20 || t.binary.format.is_executable()
}

fn print_sample_block(t: &TriageReport, deep: Option<&DeepDive>, opts: PrintOptions) {
    let name = display_name(&t.path);
    println!();
    println!("{RULE}");
    println!(
        "  {}   score {:>3}   {}",
        truncate(&name, 40),
        t.threat.score,
        t.threat.label
    );
    println!("{RULE}");

    println!("  member   {}", member_path(&t.path));
    println!("  sha256   {}", t.sha256);
    println!("  md5      {}", t.hashes.md5);
    if let Some(h) = &t.hashes.imphash {
        println!("  imphash  {h}");
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
    println!("  identity {}", identity.join(" · "));
    println!("  entry    0x{:x}", t.binary.entry_point);
    if let Some(ts) = t.binary.compile_timestamp {
        println!("  compiled {}", format_compile_time(ts));
    }

    if let Some(tc) = t.toolchain.first() {
        println!(
            "  toolchain {} (conf {}) — {}",
            tc.language,
            tc.confidence,
            tc.evidence.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
        );
    }
    if !t.packer_hints.is_empty() {
        println!("  packer   {}", t.packer_hints.join("; "));
    }

    if !t.binary.sections.is_empty() {
        println!("  sections");
        for s in &t.binary.sections {
            let ent = t
                .binary
                .section_entropies
                .iter()
                .find(|e| e.name == s.name)
                .map(|e| e.entropy)
                .unwrap_or(0.0);
            let flag = if ent >= 7.0 { "  packed?" } else { "" };
            println!(
                "    {:<10}  raw={:<10}  entropy={:.2}{flag}",
                s.name,
                human_bytes(s.raw_size),
                ent
            );
        }
    }

    if !t.threat.capabilities.is_empty() {
        println!("  caps");
        for c in &t.threat.capabilities {
            println!(
                "    {:>3}  {:<14}  {}",
                c.confidence,
                c.id,
                c.evidence.join(", ")
            );
        }
    }
    if !t.threat.behaviors.is_empty() {
        println!("  behaviors");
        for b in &t.threat.behaviors {
            println!(
                "    {:>3}  {}  ({})",
                b.severity,
                b.name,
                b.matched_apis.join(", ")
            );
        }
    }
    if !t.threat.suspicious_apis.is_empty() && opts.full {
        println!("  suspicious {}", t.threat.suspicious_apis.join(", "));
    }

    let Some(d) = deep else {
        return;
    };

    if !d.network_iocs.is_empty() {
        println!("  network");
        for ioc in &d.network_iocs {
            let priv_mark = if ioc.private { "  private" } else { "" };
            println!(
                "    {:>5}  conf={:<3}  {}{priv_mark}",
                ioc.kind.label(),
                ioc.confidence,
                ioc.value
            );
        }
    }

    if !d.crypto.is_empty() {
        println!("  crypto");
        for c in &d.crypto {
            println!(
                "    {:>3}  {} [{}] — {}",
                c.confidence,
                c.name,
                c.category.label(),
                c.evidence
            );
        }
    }

    if !d.xor_recoveries.is_empty() {
        println!("  xor");
        for x in &d.xor_recoveries {
            let peers = if x.peers.is_empty() {
                String::new()
            } else {
                format!("  peers={}", x.peers.join(","))
            };
            println!(
                "    {}  conf={}  @0x{:x}  span={}{peers}",
                x.scheme(),
                x.confidence,
                x.offset,
                human_bytes(x.length as u64),
            );
            println!("      key    {}", x.key_display());
            if !x.preview.is_empty() {
                println!("      plain  \"{}\"", x.preview);
            }
            if !x.evidence.is_empty() {
                println!("      note   {}", x.evidence);
            }
        }
    }

    if !d.secrets.is_empty() {
        println!("  secrets");
        for s in &d.secrets {
            println!("    {:>3}  [{}]  {}", s.score, s.kind.label(), s.value);
        }
    }

    if !d.yara.is_empty() {
        println!("  yara");
        for y in &d.yara {
            println!("    {}", y.rule);
        }
    }

    if !d.embedded_archives.is_empty() {
        println!("  embedded");
        for a in &d.embedded_archives {
            print_embedded_archive(a, opts);
        }
    }

    if !d.grouped_imports.is_empty() {
        print_imports(&d.grouped_imports, opts);
    }

    if !d.interesting_strings.is_empty() {
        print_strings(&d.interesting_strings, opts);
    }

    if let Some(dis) = &d.disasm {
        println!(
            "  disasm   {}  start=0x{:x}  {} insn  {} fn",
            dis.architecture,
            dis.start_address,
            dis.instructions.len(),
            dis.functions.len()
        );
        if !dis.insights.is_empty() {
            for ins in &dis.insights {
                println!(
                    "    insight  {:>2}  {}  ({} hits)",
                    ins.severity,
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
                "    fn  interest={:>3}  0x{:<8x}  {:<24}  {}",
                f.interest,
                f.start,
                truncate(&f.name, 24),
                f.cluster_label
            );
        }
    }
}

fn print_imports(grouped: &[(String, Vec<String>)], opts: PrintOptions) {
    println!("  imports");
    for (lib, fns) in grouped {
        let lower = lib.to_ascii_lowercase();
        let is_crt = lower.contains("msvcr")
            || lower.contains("msvcp")
            || lower.contains("ucrt")
            || lower.contains("vcruntime")
            || lower == "libgcc_s_dw2-1.dll";
        if is_crt && !opts.full {
            println!("    {lib}  ({} crt helpers — hidden, use --full)", fns.len());
            continue;
        }
        let interesting: Vec<&String> = fns
            .iter()
            .filter(|f| opts.full || !is_mangled(f))
            .collect();
        if interesting.is_empty() {
            println!("    {lib}  ({} fns)", fns.len());
            continue;
        }
        println!("    {lib}  ({})", interesting.len());
        // Wrap roughly.
        let joined = interesting
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        for chunk in wrap_line(&joined, 70) {
            println!("      {chunk}");
        }
    }
}

fn print_strings(
    strings: &[vanguard_re::disasm::ExtractedString],
    opts: PrintOptions,
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
    println!("  strings  showing {cap} of {}", strings.len());
    for s in filtered.iter().take(cap) {
        println!(
            "    @0x{:<8x}  {}",
            s.offset,
            truncate(&s.value, 90)
        );
    }
    if filtered.len() > cap {
        println!("    … {} more", filtered.len() - cap);
    }
}

fn print_embedded_archive(a: &EmbeddedArchive, opts: PrintOptions) {
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
        println!("      password  {pw}");
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
            println!("      … {remaining} more ({msg_n} language packs)");
        } else {
            println!("      … {remaining} more");
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
    let hexish = stem.len() >= 32
        && stem
            .chars()
            .all(|c| c.is_ascii_hexdigit());
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
    let secs = datetime.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
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
    if lower.contains("msg/m_") || lower.contains("/m_") || (lower.starts_with("m_") && lower.contains(".wnry")) {
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
