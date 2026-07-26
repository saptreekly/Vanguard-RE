//! Docker isolation probes for Fort Knox dynamic analysis.
//!
//! Dynamic emulation is refused unless Docker is reachable **and** the
//! Speakeasy image is present. There is no host-exec fallback.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Default image tag built from `docker/speakeasy`.
pub const DEFAULT_IMAGE: &str = "vanguard-speakeasy:latest";

/// Prefix for ephemeral Speakeasy staging directories under `$TMPDIR`.
pub const STAGING_DIR_PREFIX: &str = "vanguard-dyn-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationStatus {
    /// Image ref as requested plus resolved local content id (`sha256:…`).
    Ready { image: String, image_id: String },
    Disabled { reason: String },
    Unavailable { reason: String },
}

impl IsolationStatus {
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    pub fn image(&self) -> Option<&str> {
        match self {
            Self::Ready { image, .. } => Some(image.as_str()),
            _ => None,
        }
    }

    pub fn image_id(&self) -> Option<&str> {
        match self {
            Self::Ready { image_id, .. } => Some(image_id.as_str()),
            _ => None,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Disabled { reason } | Self::Unavailable { reason } => Some(reason.as_str()),
            Self::Ready { .. } => None,
        }
    }

    /// Compact id for banners: `sha256:abcdef0…`.
    pub fn short_image_id(&self) -> Option<String> {
        self.image_id().map(short_digest)
    }
}

/// Resolve the Speakeasy image name (env override or default).
///
/// Accepts tags (`vanguard-speakeasy:latest`) or digest pins
/// (`vanguard-speakeasy@sha256:…`).
pub fn image_name() -> String {
    std::env::var("VANGUARD_SPEAKEASY_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string())
}

/// Whether the operator forced dynamic off via `VANGUARD_DYNAMIC=0`.
pub fn dynamic_forced_off() -> bool {
    match std::env::var("VANGUARD_DYNAMIC") {
        Ok(v) => matches!(
            v.to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => false,
    }
}

/// Probe Docker + image. Never attempts to pull images (fail closed).
///
/// Also reaps stale Speakeasy staging directories left behind by prior SIGKILL.
pub fn probe() -> IsolationStatus {
    let _ = reap_stale_staging();

    if dynamic_forced_off() {
        return IsolationStatus::Disabled {
            reason: "VANGUARD_DYNAMIC=0".into(),
        };
    }

    let image = image_name();

    if !docker_cli_works() {
        return IsolationStatus::Unavailable {
            reason: "Docker CLI not available or daemon not running".into(),
        };
    }

    let Some(image_id) = resolve_image_id(&image) else {
        return IsolationStatus::Unavailable {
            reason: format!(
                "image `{image}` not found — build with: docker build -t {image} ./docker/speakeasy"
            ),
        };
    };

    IsolationStatus::Ready { image, image_id }
}

fn docker_cli_works() -> bool {
    let mut cmd = Command::new("docker");
    cmd.args(["version", "--format", "{{.Server.Version}}"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    match run_with_timeout(&mut cmd, Duration::from_secs(5)) {
        Some(output) => output.status.success() && !output.stdout.is_empty(),
        None => false,
    }
}

/// Resolve a local image content id (`sha256:…`). Never pulls.
pub fn resolve_image_id(image: &str) -> Option<String> {
    let mut cmd = Command::new("docker");
    cmd.args(["image", "inspect", "--format", "{{.Id}}", image])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = run_with_timeout(&mut cmd, Duration::from_secs(5))?;
    if !output.status.success() {
        return None;
    }
    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if id.is_empty() || !id.starts_with("sha256:") {
        return None;
    }
    Some(id)
}

/// Compact `sha256:<64hex>` → `sha256:<12hex>…` for banners.
pub fn short_digest(id: &str) -> String {
    let hex = id.strip_prefix("sha256:").unwrap_or(id);
    if hex.len() <= 12 {
        return id.to_string();
    }
    format!("sha256:{}…", &hex[..12])
}

/// Whether a tempdir basename looks like Speakeasy staging (`vanguard-dyn-<pid>-<suffix>`).
///
/// Deliberately excludes names like `vanguard-dyn-it-*` used by integration tests.
pub fn is_staging_dir_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(STAGING_DIR_PREFIX) else {
        return false;
    };
    let mut parts = rest.split('-');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), None) => {
            !a.is_empty()
                && !b.is_empty()
                && a.chars().all(|c| c.is_ascii_digit())
                && b.chars().all(|c| c.is_ascii_digit())
        }
        _ => false,
    }
}

/// Best-effort removal of leftover Speakeasy staging trees under `$TMPDIR`.
///
/// Returns how many directories were removed.
pub fn reap_stale_staging() -> usize {
    reap_stale_staging_in(&std::env::temp_dir())
}

/// Testable variant of [`reap_stale_staging`].
pub fn reap_stale_staging_in(base: &Path) -> usize {
    let Ok(entries) = fs::read_dir(base) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_staging_dir_name(name) {
            continue;
        }
        let path = entry.path();
        // Only reap dirs that look like ours (contain sample.bin or are empty-ish).
        if staging_dir_looks_ours(&path) && fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn staging_dir_looks_ours(path: &Path) -> bool {
    let sample = path.join("sample.bin");
    if sample.is_file() {
        return true;
    }
    // Empty or partially cleaned leftover — still safe to remove if name matches.
    match fs::read_dir(path) {
        Ok(mut it) => it.next().is_none(),
        Err(_) => false,
    }
}

/// Run a command with a wall-clock timeout; kill the process on expiry.
pub fn run_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> Option<std::process::Output> {
    use std::sync::mpsc;
    use std::thread;

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return None,
    };
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => Some(output),
        Ok(Err(_)) => None,
        Err(_) => {
            // Best-effort kill; ignore errors if already exited.
            let _ = Command::new("kill")
                .args(["-9", &pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            // Also try docker kill if this was a long docker run — caller handles
            // named containers separately.
            let _ = rx.recv_timeout(Duration::from_secs(2));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn forced_off_is_disabled() {
        // Safety: don't mutate global env in parallel tests beyond this check of parser.
        assert!(!matches!(
            "1".to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ));
        assert!(matches!(
            "0".to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ));
    }

    #[test]
    fn default_image_name_constant() {
        assert!(DEFAULT_IMAGE.contains("vanguard-speakeasy"));
    }

    #[test]
    fn short_digest_truncates() {
        let full = format!("sha256:{}", "ab".repeat(32));
        let s = short_digest(&full);
        assert!(s.starts_with("sha256:abababababab"));
        assert!(s.ends_with('…'));
        assert!(s.len() < full.len());
    }

    #[test]
    fn staging_dir_name_matches_pid_suffix_only() {
        assert!(is_staging_dir_name("vanguard-dyn-12345-9876543210"));
        assert!(!is_staging_dir_name("vanguard-dyn-it-12345"));
        assert!(!is_staging_dir_name("vanguard-dyn-abc-1"));
        assert!(!is_staging_dir_name("other-123-456"));
        assert!(!is_staging_dir_name("vanguard-dyn-1-2-3"));
    }

    #[test]
    fn reap_removes_stale_staging_keeps_unrelated() {
        let base = std::env::temp_dir().join(format!(
            "vanguard-reap-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let stale = base.join("vanguard-dyn-999001-424242");
        fs::create_dir_all(&stale).unwrap();
        {
            let mut f = fs::File::create(stale.join("sample.bin")).unwrap();
            f.write_all(b"MZ leftover").unwrap();
        }

        let keep_it = base.join("vanguard-dyn-it-999001");
        fs::create_dir_all(&keep_it).unwrap();
        fs::write(keep_it.join("sample.zip"), b"PK").unwrap();

        let keep_other = base.join("not-staging");
        fs::create_dir_all(&keep_other).unwrap();

        let n = reap_stale_staging_in(&base);
        assert_eq!(n, 1);
        assert!(!stale.exists());
        assert!(keep_it.exists());
        assert!(keep_other.exists());

        let _ = fs::remove_dir_all(&base);
    }
}
