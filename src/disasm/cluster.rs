//! Function feature vectors + Lloyd k-means for visual clustering.

use super::{DisasmLine, FlowKind, FunctionInfo};

/// Feature dimensionality for function vectors.
pub const FEATURE_DIM: usize = 10;

/// Build a normalized feature vector for a function span.
///
/// Dims: [call, jmp, jcc, ret, anti_debug, xor_ops, pushpop, mem, density_calls, log_len]
pub fn function_features(instructions: &[DisasmLine], f: &FunctionInfo) -> [f32; FEATURE_DIM] {
    let slice = &instructions[f.insn_start..=f.insn_end];
    let n = slice.len().max(1) as f32;

    let mut call = 0f32;
    let mut jmp = 0f32;
    let mut jcc = 0f32;
    let mut ret = 0f32;
    let mut anti = 0f32;
    let mut xor = 0f32;
    let mut pushpop = 0f32;
    let mut mem = 0f32;

    for line in slice {
        match line.flow {
            FlowKind::Call => call += 1.0,
            FlowKind::Jump => jmp += 1.0,
            FlowKind::CondJump => jcc += 1.0,
            FlowKind::Return => ret += 1.0,
            _ => {}
        }
        if line.anti_debug {
            anti += 1.0;
        }
        let t = line.text.to_ascii_lowercase();
        if t.starts_with("xor ") || t.contains(" xor ") {
            xor += 1.0;
        }
        if t.starts_with("push ") || t.starts_with("pop ") {
            pushpop += 1.0;
        }
        if t.contains('[') {
            mem += 1.0;
        }
    }

    [
        call / n,
        jmp / n,
        jcc / n,
        ret / n,
        (anti / n).min(1.0),
        xor / n,
        pushpop / n,
        mem / n,
        (call / 8.0).min(1.0),
        ((n.ln()) / 6.0).min(1.0),
    ]
}

fn dist(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| {
            let d = x - y;
            d * d
        })
        .sum::<f32>()
        .sqrt()
}

/// Lloyd k-means. Returns cluster id per row (0..k-1).
pub fn kmeans(rows: &[[f32; FEATURE_DIM]], k: usize, max_iters: usize) -> Vec<usize> {
    let n = rows.len();
    if n == 0 {
        return Vec::new();
    }
    let k = k.clamp(1, n);

    let mut centroids: Vec<[f32; FEATURE_DIM]> = (0..k)
        .map(|i| {
            let idx = if k == 1 {
                0
            } else {
                i * (n - 1) / (k - 1)
            };
            rows[idx]
        })
        .collect();

    let mut assign = vec![0usize; n];

    for _ in 0..max_iters {
        let mut changed = false;
        for (i, row) in rows.iter().enumerate() {
            let mut best = 0usize;
            let mut best_d = f32::MAX;
            for (c, cen) in centroids.iter().enumerate() {
                let d = dist(row, cen);
                if d < best_d {
                    best_d = d;
                    best = c;
                }
            }
            if assign[i] != best {
                assign[i] = best;
                changed = true;
            }
        }

        let mut sums = vec![[0f32; FEATURE_DIM]; k];
        let mut counts = vec![0usize; k];
        for (i, row) in rows.iter().enumerate() {
            let c = assign[i];
            counts[c] += 1;
            for d in 0..FEATURE_DIM {
                sums[c][d] += row[d];
            }
        }
        for c in 0..k {
            if counts[c] == 0 {
                centroids[c] = rows[c % n];
                continue;
            }
            for d in 0..FEATURE_DIM {
                centroids[c][d] = sums[c][d] / counts[c] as f32;
            }
        }

        if !changed {
            break;
        }
    }

    assign
}

/// Human-readable cluster label from member feature averages.
pub fn label_cluster(members: &[[f32; FEATURE_DIM]]) -> String {
    if members.is_empty() {
        return "empty".into();
    }
    let mut avg = [0f32; FEATURE_DIM];
    for m in members {
        for d in 0..FEATURE_DIM {
            avg[d] += m[d];
        }
    }
    let n = members.len() as f32;
    for v in &mut avg {
        *v /= n;
    }

    let names = [
        (0usize, "call-heavy"),
        (1, "jump-heavy"),
        (2, "branchy"),
        (3, "leaf/ret"),
        (4, "anti-debug"),
        (5, "xor/crypto-ish"),
        (6, "stack-heavy"),
        (7, "memory-ops"),
    ];
    let mut best = (0usize, 0f32);
    for &(i, _) in &names {
        if avg[i] > best.1 {
            best = (i, avg[i]);
        }
    }
    if best.1 < 0.05 {
        return "mixed".into();
    }
    names
        .iter()
        .find(|(i, _)| *i == best.0)
        .map(|(_, n)| (*n).into())
        .unwrap_or_else(|| "mixed".into())
}

/// Choose k ≈ √(n/2), clamped to [1, 6].
pub fn choose_k(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    if n <= 3 {
        return n.min(2);
    }
    let k = ((n as f32 / 2.0).sqrt().round() as usize).clamp(2, 6);
    k.min(n)
}
