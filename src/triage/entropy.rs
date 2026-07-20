//! Shannon entropy and ASCII heat-map rendering.

use serde::Serialize;

/// Per-section entropy summary.
#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropy {
    pub name: String,
    pub entropy: f64,
    pub size: u64,
    /// Packed/encrypted heuristic: entropy typically > 7.0 for high-entropy payloads.
    pub high_entropy: bool,
}

/// Shannon entropy of a byte slice in bits (0.0 ..= 8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Build a 64-column ASCII heat map from byte entropy windows.
///
/// Darker/heavier glyphs = higher local entropy (packed / encrypted regions).
pub fn entropy_heatmap(data: &[u8], width: usize) -> String {
    const RAMP: &[u8] = b" .:-=+*#%@";
    if data.is_empty() || width == 0 {
        return String::new();
    }

    let chunk = (data.len() / width).max(1);
    let mut line = String::with_capacity(width);
    for i in 0..width {
        let start = i * chunk;
        if start >= data.len() {
            line.push(' ');
            continue;
        }
        let end = (start + chunk).min(data.len());
        let e = shannon_entropy(&data[start..end]);
        let idx = ((e / 8.0) * (RAMP.len() - 1) as f64).round() as usize;
        line.push(RAMP[idx.min(RAMP.len() - 1)] as char);
    }
    line
}

/// Classify a section by entropy threshold.
pub fn section_entropy(name: impl Into<String>, data: &[u8]) -> SectionEntropy {
    let entropy = shannon_entropy(data);
    SectionEntropy {
        name: name.into(),
        entropy,
        size: data.len() as u64,
        high_entropy: entropy >= 7.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_entropy_for_uniform() {
        let data = vec![0u8; 4096];
        assert!(shannon_entropy(&data) < 0.01);
    }

    #[test]
    fn high_entropy_for_randomish() {
        let data: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!(shannon_entropy(&data) > 7.5);
    }
}
