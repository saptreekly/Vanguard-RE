//! Integration: dynamic analysis must fail closed without Docker/image.
//! Static investigate must still succeed.

use std::io::{Cursor, Write};
use std::path::PathBuf;

use zip::write::SimpleFileOptions;

use vanguard_re::containment::collect_samples;
use vanguard_re::dynamic::{emulate_pe, EmulateOptions, IsolationStatus};
use vanguard_re::investigate::{investigate, InvestigateOptions};

fn tiny_zip_on_disk() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vanguard-dyn-it-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("sample.zip");

    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    // Minimal MZ stub — not a valid PE deep enough for Speakeasy, but enough for collect.
    writer
        .start_file("stub.exe", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"MZ\0\0this-is-not-a-real-pe").unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn emulate_pe_never_panics_without_isolation() {
    // Whatever the host Docker state is, this must return a structured result.
    let dive = emulate_pe(b"MZ\0\0fake", EmulateOptions { timeout_secs: 5 });
    assert!(
        matches!(
            dive.status.as_str(),
            "ok" | "skipped" | "error" | "timeout"
        ),
        "unexpected status: {}",
        dive.status
    );
}

#[test]
fn investigate_static_ok_when_dynamic_unavailable() {
    let path = tiny_zip_on_disk();
    let samples = collect_samples(&path, false, None).expect("collect");
    assert!(!samples.is_empty());

    let report = investigate(
        &path.display().to_string(),
        &samples,
        InvestigateOptions {
            deep: 2,
            disasm_count: 32,
            yara_rules: None,
            min_deep_score: 0,
            max_deep: 4,
            full: true,
        },
    )
    .expect("investigate must succeed without Docker");

    // Banner status is always present.
    let _ = report.dynamic_status.banner_line();

    // If isolation was unavailable/disabled, no sample should have attempted dynamic.
    match vanguard_re::dynamic::isolation_status() {
        IsolationStatus::Unavailable { .. } | IsolationStatus::Disabled { .. } => {
            assert!(
                report
                    .deep_dives
                    .iter()
                    .all(|d| d.dynamic.is_none()),
                "dynamic must not run when isolation is unavailable"
            );
        }
        IsolationStatus::Ready { image_id, .. } => {
            assert!(image_id.starts_with("sha256:"));
            // Image present — budgeted runs may or may not select this stub (score).
            // Just ensure no panic and statuses are structured.
            for d in &report.deep_dives {
                if let Some(dyn_r) = &d.dynamic {
                    assert!(!dyn_r.status.is_empty());
                }
            }
        }
    }

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
