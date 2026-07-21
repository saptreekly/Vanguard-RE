//! Vanguard-RE CLI — static malware triage from the command line.

mod cli;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use vanguard_re::containment::collect_samples;
use vanguard_re::investigate::{InvestigateOptions, investigate};

#[derive(Debug, Parser)]
#[command(
    name = "vanguard",
    about = "High-speed, memory-safe static malware triage",
    long_about = "Map and statically analyze a sample or passworded ZIP. \
Nothing is executed; ZIP members stay in process memory only."
)]
struct Args {
    /// Path to a sample file or ZIP archive
    path: PathBuf,

    /// Password for encrypted ZIP archives
    #[arg(short, long, default_value = "infected")]
    password: String,

    /// Number of top-scoring samples to deep-dive
    #[arg(long, default_value_t = 3)]
    deep: usize,

    /// Max instructions to decode per deep-dive disassembly
    #[arg(long, default_value_t = 4000)]
    disasm_count: usize,

    /// Minimum triage score required for a deep-dive
    #[arg(long, default_value_t = 70)]
    min_deep_score: u8,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let password = if args.password.is_empty() {
        None
    } else {
        Some(args.password.as_str())
    };

    let samples = collect_samples(&args.path, false, password)
        .with_context(|| format!("collect {}", args.path.display()))?;

    let report = investigate(
        &args.path.display().to_string(),
        &samples,
        InvestigateOptions {
            deep: args.deep,
            disasm_count: args.disasm_count,
            yara_rules: None,
            min_deep_score: args.min_deep_score,
        },
    )?;

    cli::print_report(&args.path, &samples, &report);
    Ok(())
}
