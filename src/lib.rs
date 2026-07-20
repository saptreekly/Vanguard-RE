//! Vanguard-RE — high-speed, memory-safe static malware analysis.
//!
//! Built on three pillars:
//! - **Speed**: memmap2 + rayon for zero-copy, data-parallel scanning
//! - **Accuracy**: formal PE/ELF/Mach-O parsing, ImpHash, entropy, signatures
//! - **Safety**: Rust memory safety + in-memory quarantine (samples never executed)

pub mod containment;
pub mod disasm;
pub mod heuristics;
pub mod investigate;
pub mod signatures;
pub mod triage;
pub mod util;

pub use containment::{collect_samples, containment_policy, QuarantinedSample};
pub use investigate::{investigate, InvestigateOptions, InvestigationReport};
pub use triage::{BinaryFormat, TriageReport};
