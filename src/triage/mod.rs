//! Static triage & formal header parsing (PE / ELF / Mach-O).

pub mod entropy;
pub mod formats;
pub mod report;

pub use entropy::{entropy_heatmap, shannon_entropy, SectionEntropy};
pub use formats::{
    detect_format, parse_binary, parse_binary_named, BinaryFormat, ImportEntry, ParsedBinary,
};
pub use report::{detect_packer_hints, SectionInfo, TriageReport};
