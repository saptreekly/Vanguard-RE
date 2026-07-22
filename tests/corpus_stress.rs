//! Opt-in full-corpus stress test.
//!
//! Run with:
//! `VANGUARD_MALWARE_CORPUS=/path cargo test --test corpus_stress -- --ignored --nocapture`
//!
//! Samples are only read and statically analyzed. Extracted members stay in RAM.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use vanguard_re::containment::collect_samples;
use vanguard_re::investigate::{InvestigateOptions, investigate};

#[derive(Debug)]
struct CaseResult {
    path: PathBuf,
    samples: usize,
    elapsed: Duration,
}

fn walk_targets(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_targets(&path, out);
            continue;
        }
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(
            extension.as_str(),
            "zip" | "exe" | "apk" | "dmp" | "001" | "002"
        ) {
            out.push(path);
        }
    }
}

fn password_for(path: &Path) -> String {
    if let Some(password) = std::env::var_os("VANGUARD_MALWARE_PASSWORD_OVERRIDE") {
        return password.to_string_lossy().into_owned();
    }
    let Some(parent) = path.parent() else {
        return "infected".into();
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return "infected".into();
    };
    entries
        .flatten()
        .find_map(|entry| {
            let candidate = entry.path();
            let name = candidate.file_name()?.to_str()?.to_ascii_lowercase();
            if !name.contains(".pass") {
                return None;
            }
            let password = fs::read_to_string(candidate).ok()?;
            let password = password.trim();
            (!password.is_empty()).then(|| password.to_string())
        })
        .unwrap_or_else(|| "infected".into())
}

#[test]
#[ignore = "requires an external malware corpus"]
fn entire_external_corpus_is_handled() {
    let root = PathBuf::from(
        std::env::var_os("VANGUARD_MALWARE_CORPUS")
            .expect("set VANGUARD_MALWARE_CORPUS to the corpus directory"),
    );
    assert!(root.is_dir(), "corpus does not exist: {}", root.display());

    let mut targets = Vec::new();
    walk_targets(&root, &mut targets);
    targets.sort();
    if let Some(filter) = std::env::var_os("VANGUARD_MALWARE_FILTER") {
        let filters: Vec<String> = filter
            .to_string_lossy()
            .split(',')
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect();
        targets.retain(|path| {
            let path = path.to_string_lossy().to_ascii_lowercase();
            filters.iter().any(|filter| path.contains(filter))
        });
    }
    assert!(!targets.is_empty(), "no supported corpus targets found");

    let started = Instant::now();
    let mut passed = Vec::new();
    let mut failures = Vec::new();
    let mut total_samples = 0usize;

    for (index, path) in targets.iter().enumerate() {
        let case_started = Instant::now();
        let password = password_for(path);
        let result = collect_samples(path, false, Some(&password)).and_then(|samples| {
            let count = samples.len();
            let report = investigate(
                &path.display().to_string(),
                &samples,
                InvestigateOptions {
                    deep: 1,
                    disasm_count: 64,
                    yara_rules: None,
                    min_deep_score: 100,
                    full: false,
                },
            )?;
            if report.sample_count != count || report.ranking.len() != count {
                anyhow::bail!(
                    "incomplete report: collected={count}, reported={}, ranked={}",
                    report.sample_count,
                    report.ranking.len()
                );
            }
            Ok(count)
        });

        let elapsed = case_started.elapsed();
        match result {
            Ok(samples) => {
                total_samples += samples;
                passed.push(CaseResult {
                    path: path.clone(),
                    samples,
                    elapsed,
                });
                eprintln!(
                    "[{}/{}] ok   {:>4} samples  {:>7.2?}  {}",
                    index + 1,
                    targets.len(),
                    samples,
                    elapsed,
                    path.strip_prefix(&root).unwrap_or(path).display()
                );
            }
            Err(error) => {
                failures.push((path.clone(), format!("{error:#}")));
                eprintln!(
                    "[{}/{}] FAIL {:>7.2?}  {}: {error:#}",
                    index + 1,
                    targets.len(),
                    elapsed,
                    path.strip_prefix(&root).unwrap_or(path).display()
                );
            }
        }
    }

    passed.sort_by_key(|result| std::cmp::Reverse(result.elapsed));
    eprintln!(
        "\ncorpus summary: {} targets, {} passed, {} failed, {} extracted samples, {:.2?}",
        targets.len(),
        passed.len(),
        failures.len(),
        total_samples,
        started.elapsed()
    );
    eprintln!("slowest targets:");
    for result in passed.iter().take(10) {
        eprintln!(
            "  {:>7.2?}  {:>4} samples  {}",
            result.elapsed,
            result.samples,
            result
                .path
                .strip_prefix(&root)
                .unwrap_or(&result.path)
                .display()
        );
    }
    if !failures.is_empty() {
        eprintln!("failures:");
        for (path, error) in &failures {
            eprintln!(
                "  {}: {error}",
                path.strip_prefix(&root).unwrap_or(path).display()
            );
        }
        panic!("{} corpus targets failed", failures.len());
    }
}
