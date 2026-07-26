//! Command-line report printer for investigation results.

mod report;
mod style;

pub use report::{print_report, PrintOptions};
pub use style::ColorChoice;
