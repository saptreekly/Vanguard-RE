//! Lightweight ANSI styling for CLI report output.
//!
//! No external color crate — escape codes are applied only when enabled
//! (TTY + no `NO_COLOR`, or `--color always`).

use std::io::{self, IsTerminal};

/// Width of the left-hand field-key column (characters).
pub const KEY_WIDTH: usize = 10;

/// User preference for ANSI color in report output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }
}

/// Active styling context for one report print.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    enabled: bool,
}

impl Style {
    pub fn from_preference(choice: ColorChoice) -> Self {
        let enabled = match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
            }
        };
        Self { enabled }
    }

    fn paint(self, codes: &str, s: &str) -> String {
        if !self.enabled || s.is_empty() {
            return s.to_string();
        }
        format!("\x1b[{codes}m{s}\x1b[0m")
    }

    pub fn dim(self, s: &str) -> String {
        self.paint("2", s)
    }

    pub fn brand(self, s: &str) -> String {
        self.paint("1;96", s) // bold bright cyan
    }

    pub fn header(self, s: &str) -> String {
        self.paint("1;97", s) // bold bright white
    }

    /// Section title with leading glyph: `▸ RANKING`.
    pub fn section(self, title: &str) -> String {
        self.header(&format!("▸ {title}"))
    }

    pub fn key(self, s: &str) -> String {
        self.dim(&format!("{s:<KEY_WIDTH$}"))
    }

    /// Dim padded key + value on one line prefix (no trailing newline).
    pub fn field(self, key: &str, value: &str) -> String {
        format!("  {} {}", self.key(key), value)
    }

    pub fn rule(self, s: &str) -> String {
        self.dim(s)
    }

    pub fn hash(self, s: &str) -> String {
        self.paint("93", s) // bright yellow
    }

    pub fn url(self, s: &str) -> String {
        self.paint("4;96", s) // underlined bright cyan
    }

    pub fn packed(self, s: &str) -> String {
        self.paint("91", s) // bright red
    }

    /// Emphasize a primary name (sample, member).
    pub fn emph(self, s: &str) -> String {
        self.paint("1;97", s) // bold bright white
    }

    /// DLL / library title.
    pub fn lib(self, s: &str) -> String {
        self.paint("1;96", s) // bold bright cyan
    }

    /// Capability / behavior id.
    pub fn cap_id(self, s: &str) -> String {
        self.paint("1;96", s)
    }

    /// Color a formatted score string (e.g. right-aligned) by band.
    pub fn score_text(self, n: u8, text: &str) -> String {
        self.paint(score_codes(n), text)
    }

    /// Bracketed score badge: `[99]`.
    pub fn badge(self, n: u8) -> String {
        self.score_text(n, &format!("[{n}]"))
    }

    /// Color a threat label; prefer the leading risk phrase, else score band.
    pub fn label(self, label: &str, score: u8) -> String {
        let codes = label_codes(label).unwrap_or_else(|| score_codes(score));
        self.paint(codes, label)
    }

    /// Tint a pre-formatted confidence string (e.g. right-aligned).
    pub fn confidence_text(self, n: u8, text: &str) -> String {
        let codes = match n {
            0..=39 => "2",   // dim
            40..=69 => "33", // yellow
            70..=89 => "93", // bright yellow
            _ => "91",       // bright red
        };
        self.paint(codes, text)
    }

    /// Entropy value; highlight packed-looking (≥ 7.0).
    pub fn entropy(self, ent: f64, text: &str) -> String {
        if ent >= 7.0 {
            self.paint("91", text)
        } else {
            text.to_string()
        }
    }
}

fn score_codes(n: u8) -> &'static str {
    match n {
        0..=19 => "2;32", // dim green
        20..=39 => "33",  // yellow
        40..=69 => "93",  // bright yellow
        70..=89 => "91",  // bright red
        _ => "1;91",      // bold bright red
    }
}

/// Match the leading risk-band phrase from `compose_label` / `risk_band`.
fn label_codes(label: &str) -> Option<&'static str> {
    let lower = label.to_ascii_lowercase();
    if lower.starts_with("critical") {
        Some("1;91")
    } else if lower.starts_with("high risk") {
        Some("91")
    } else if lower.starts_with("likely malicious") {
        Some("93")
    } else if lower.starts_with("suspicious") {
        Some("33")
    } else if lower.starts_with("benign") {
        Some("2;32")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_emits_plain_text() {
        let s = Style { enabled: false };
        assert_eq!(s.brand("VANGUARD-RE"), "VANGUARD-RE");
        assert_eq!(s.score_text(99, "99"), "99");
        assert_eq!(s.badge(99), "[99]");
        assert_eq!(s.label("critical — file_drop", 99), "critical — file_drop");
        assert_eq!(s.hash("abc"), "abc");
        assert_eq!(s.url("https://example.com"), "https://example.com");
        assert_eq!(s.dim("x"), "x");
        assert_eq!(s.emph("name"), "name");
        assert_eq!(s.lib("KERNEL32.dll"), "KERNEL32.dll");
        assert_eq!(s.field("sha256", "abc"), "  sha256     abc");
        assert_eq!(s.section("RANKING"), "▸ RANKING");
        assert_eq!(s.confidence_text(88, " 88"), " 88");
        assert!(!s.badge(99).contains('\x1b'));
    }

    #[test]
    fn enabled_wraps_with_ansi() {
        let s = Style { enabled: true };
        let branded = s.brand("VANGUARD-RE");
        assert!(branded.contains('\x1b'));
        assert!(branded.contains("VANGUARD-RE"));
        assert!(branded.ends_with("\x1b[0m"));

        let crit = s.score_text(99, "99");
        assert!(crit.contains("1;91"));
        let badge = s.badge(99);
        assert!(badge.contains("[99]"));
        assert!(badge.contains("1;91"));
        let benign = s.score_text(5, "5");
        assert!(benign.contains("2;32"));
    }

    #[test]
    fn label_codes_prefer_phrase() {
        let s = Style { enabled: true };
        assert!(s.label("critical — x", 10).contains("1;91"));
        assert!(s.label("benign / low interest", 90).contains("2;32"));
        // Unknown prefix falls back to score band.
        assert!(s.label("DOS COM / classic", 10).contains("2;32"));
    }

    #[test]
    fn color_choice_parse() {
        assert_eq!(ColorChoice::parse("auto"), Some(ColorChoice::Auto));
        assert_eq!(ColorChoice::parse("ALWAYS"), Some(ColorChoice::Always));
        assert_eq!(ColorChoice::parse("never"), Some(ColorChoice::Never));
        assert_eq!(ColorChoice::parse("maybe"), None);
    }

    #[test]
    fn key_pads_to_width() {
        let s = Style { enabled: false };
        assert_eq!(s.key("md5").chars().count(), KEY_WIDTH);
        assert_eq!(s.key("imphash").chars().count(), KEY_WIDTH);
    }
}
