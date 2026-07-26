//! Vanguard-RE — high-speed, memory-safe static malware analysis.
//!
//! Built on three pillars:
//! - **Speed**: memmap2 zero-copy I/O + focused static pipelines
//! - **Accuracy**: formal PE/ELF/Mach-O parsing, ImpHash, entropy, signatures,
//!   network IOCs, crypto fingerprints, and automated disasm code analysis
//! - **Safety**: Rust memory safety + in-memory quarantine (never host-exec;
//!   optional Speakeasy only inside Docker `--network=none`, with ephemeral
//!   non-executable staging under `$TMPDIR`)

pub mod containment;
pub mod crypto;
pub mod disasm;
pub mod dynamic;
pub mod heuristics;
pub mod iocs;
pub mod investigate;
pub mod secrets;
pub mod signatures;
pub mod toolchain;
pub mod triage;
pub mod util;

pub use containment::{
    collect_samples, containment_policy, ContainmentReport, EmbeddedArchive, EmbeddedMember,
    QuarantinedSample, SampleWriteMode,
};
pub use investigate::{investigate, short_name, InvestigateOptions, InvestigationReport};
pub use triage::{BinaryFormat, TriageReport};
