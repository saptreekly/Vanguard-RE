//! Smoke: DOS COM sample must appear in ranking (not blank results).
use std::path::PathBuf;

use vanguard_re::containment::collect_samples;
use vanguard_re::investigate::{investigate, InvestigateOptions};

#[test]
fn friday_the_13th_com_ranks() {
    let path = PathBuf::from(
        "/Users/jackweekly/Documents/Malware/Friday_the_13th.416.B/Friday_the_13th.416.B.zip",
    );
    if !path.exists() {
        eprintln!("skip: sample ZIP missing at {}", path.display());
        return;
    }

    let samples = collect_samples(&path, false, Some("infected")).expect("collect");
    assert!(!samples.is_empty(), "expected at least one member");

    let report = investigate(
        &path.display().to_string(),
        &samples,
        InvestigateOptions {
            deep: 1,
            disasm_count: 16,
            yara_rules: None,
            min_deep_score: 70,
        },
    )
    .expect("investigate");

    assert_eq!(report.sample_count, samples.len());
    assert!(
        !report.ranking.is_empty(),
        "ranking must not be empty for DOS COM"
    );
    let (name, score, label) = &report.ranking[0];
    assert!(
        name.to_lowercase().contains("friday") || name.to_lowercase().ends_with(".com"),
        "unexpected name: {name}"
    );
    assert!(*score >= 35, "score too low: {score}");
        assert!(
            label.to_lowercase().contains("com") || label.to_lowercase().contains("dos"),
            "unexpected label: {label}"
        );
        eprintln!("ok: {name} score={score} label={label}");
}
