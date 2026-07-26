//! Speakeasy runner: stage sample → Docker `--network=none` → JSON stdout.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::isolate::{self, IsolationStatus, STAGING_DIR_PREFIX};
use super::map::map_speakeasy_json;
use super::{DynamicDive, DynamicEvents, EmulateOptions};

/// Chunk size for best-effort overwrite of staged sample bytes.
const WIPE_CHUNK: usize = 64 * 1024;

/// RAII staging directory: overwrite sample bytes then remove tree on drop.
struct StagingDir {
    dir: PathBuf,
    sample: PathBuf,
}

impl StagingDir {
    fn create(bytes: &[u8]) -> Result<Self, String> {
        let base = std::env::temp_dir();
        let dir = base.join(format!(
            "{}{}-{}",
            STAGING_DIR_PREFIX,
            std::process::id(),
            random_suffix()
        ));
        fs::create_dir(&dir).map_err(|e| format!("create staging dir: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dir)
                .map_err(|e| format!("stat staging dir: {e}"))?
                .permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&dir, perms).map_err(|e| format!("chmod staging dir: {e}"))?;
        }

        let sample = dir.join("sample.bin");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&sample)
                .map_err(|e| format!("create sample staging file: {e}"))?;
            f.write_all(bytes)
                .map_err(|e| format!("write sample staging file: {e}"))?;
            f.sync_all().ok();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&sample)
                .map_err(|e| format!("stat sample file: {e}"))?
                .permissions();
            // Read-only for owner — never executable.
            perms.set_mode(0o400);
            fs::set_permissions(&sample, perms)
                .map_err(|e| format!("chmod sample file: {e}"))?;
        }

        // Refuse to continue if somehow executable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&sample)
                .map_err(|e| format!("re-stat sample: {e}"))?
                .permissions()
                .mode();
            if mode & 0o111 != 0 {
                return Err("staging sample unexpectedly has execute bits".into());
            }
        }

        Ok(Self { dir, sample })
    }

    #[cfg(test)]
    fn sample_path(&self) -> &Path {
        &self.sample
    }

    #[cfg(test)]
    fn dir_path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        wipe_and_remove_sample(&self.sample);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Overwrite the full file length with zeros, then unlink (best-effort).
pub(crate) fn wipe_and_remove_sample(path: &Path) {
    if !path.exists() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(path, perms);
        }
    }
    if let Ok(meta) = fs::metadata(path) {
        let len = meta.len() as usize;
        if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
            let _ = wipe_writer(&mut f, len);
            let _ = f.sync_all();
        }
    }
    let _ = fs::remove_file(path);
}

/// Zero-fill `len` bytes via a reusable chunk (avoids allocating a huge Vec).
pub(crate) fn wipe_writer(w: &mut impl Write, len: usize) -> std::io::Result<()> {
    let chunk = vec![0u8; WIPE_CHUNK.min(len.max(1))];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(chunk.len());
        w.write_all(&chunk[..n])?;
        remaining -= n;
    }
    Ok(())
}

fn random_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    t ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Guest timeout slightly under host so entrypoint can exit before CLI kill.
pub(crate) fn guest_timeout_secs(host_timeout_secs: u64) -> u64 {
    host_timeout_secs.saturating_sub(5).max(5)
}

/// Build Fort Knox `docker run` argv (without the leading `docker` binary).
///
/// Unit-tested so flag regressions are caught without needing a daemon.
pub fn fort_knox_run_args(
    container_name: &str,
    staging_dir: &str,
    image: &str,
    host_timeout_secs: u64,
) -> Vec<String> {
    let guest_timeout = guest_timeout_secs(host_timeout_secs).to_string();
    vec![
        "run".into(),
        "--name".into(),
        container_name.into(),
        "--rm".into(),
        "--network=none".into(),
        "--cap-drop=ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--read-only".into(),
        // Private IPC namespace (Docker accepts private|host|shareable|container:…).
        // UTS is already private by default — Docker has no `--uts=private` (only `--uts=host`).
        "--ipc=private".into(),
        "--tmpfs".into(),
        "/tmp:rw,nosuid,nodev,size=64m".into(),
        "--memory=1g".into(),
        "--memory-swap=1g".into(),
        "--cpus=1".into(),
        "--pids-limit=256".into(),
        "--ulimit".into(),
        "nproc=256:256".into(),
        "--user".into(),
        "65534:65534".into(),
        "-e".into(),
        format!("VANGUARD_EMU_TIMEOUT={guest_timeout}"),
        "-e".into(),
        "VANGUARD_SAMPLE=/work/sample.bin".into(),
        // Whole staging dir is read-only: sample.bin mode 0400, no host drops.
        "-v".into(),
        format!("{staging_dir}:/work:ro"),
        "-w".into(),
        "/tmp".into(),
        image.into(),
    ]
}

/// Emulate a PE under Speakeasy inside Docker with Fort Knox flags.
pub fn emulate_pe(bytes: &[u8], opts: EmulateOptions, status: &IsolationStatus) -> DynamicDive {
    let started = Instant::now();
    let IsolationStatus::Ready { image, .. } = status else {
        return DynamicDive::skipped(
            status
                .reason()
                .unwrap_or("isolation unavailable")
                .to_string(),
        );
    };

    if bytes.len() < 2 || &bytes[..2] != b"MZ" {
        return DynamicDive {
            backend: "speakeasy".into(),
            elapsed_ms: started.elapsed().as_millis() as u64,
            status: "skipped".into(),
            summary: "not a PE (missing MZ)".into(),
            events: DynamicEvents::default(),
            capabilities: Vec::new(),
            behaviors: Vec::new(),
            network_iocs: Vec::new(),
        };
    }

    let staging = match StagingDir::create(bytes) {
        Ok(s) => s,
        Err(e) => {
            return DynamicDive {
                backend: "speakeasy".into(),
                elapsed_ms: started.elapsed().as_millis() as u64,
                status: "error".into(),
                summary: e,
                events: DynamicEvents::default(),
                capabilities: Vec::new(),
                behaviors: Vec::new(),
                network_iocs: Vec::new(),
            };
        }
    };

    let name = format!(
        "{}{}-{}",
        STAGING_DIR_PREFIX,
        std::process::id(),
        random_suffix()
    );

    let args = fort_knox_run_args(
        &name,
        &staging.dir.display().to_string(),
        image,
        opts.timeout_secs,
    );

    let mut cmd = Command::new("docker");
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let timeout = Duration::from_secs(opts.timeout_secs.max(5));
    let output = isolate::run_with_timeout(&mut cmd, timeout);

    // Ensure container is gone even if --rm raced with kill.
    let _ = Command::new("docker")
        .args(["rm", "-f", &name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let elapsed_ms = started.elapsed().as_millis() as u64;

    let Some(output) = output else {
        return DynamicDive {
            backend: "speakeasy".into(),
            elapsed_ms,
            status: "timeout".into(),
            summary: format!("emulation exceeded {}s — container killed", opts.timeout_secs),
            events: DynamicEvents::default(),
            capabilities: Vec::new(),
            behaviors: Vec::new(),
            network_iocs: Vec::new(),
        };
    };

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let err = err.trim();
        let snippet: String = err.chars().take(240).collect();
        return DynamicDive {
            backend: "speakeasy".into(),
            elapsed_ms,
            status: "error".into(),
            summary: if snippet.is_empty() {
                format!("docker/speakeasy exited {}", output.status)
            } else {
                format!("docker/speakeasy failed: {snippet}")
            },
            events: DynamicEvents::default(),
            capabilities: Vec::new(),
            behaviors: Vec::new(),
            network_iocs: Vec::new(),
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = extract_json(&stdout);
    match map_speakeasy_json(json) {
        Ok((events, capabilities, behaviors, network_iocs)) => DynamicDive {
            backend: "speakeasy".into(),
            elapsed_ms,
            status: "ok".into(),
            summary: format!(
                "{} apis · {} procs · {} files · {} net",
                events.apis.len(),
                events.process_creates.len(),
                events.file_writes.len(),
                events.network.len()
            ),
            events,
            capabilities,
            behaviors,
            network_iocs,
        },
        Err(e) => DynamicDive {
            backend: "speakeasy".into(),
            elapsed_ms,
            status: "error".into(),
            summary: e,
            events: DynamicEvents::default(),
            capabilities: Vec::new(),
            behaviors: Vec::new(),
            network_iocs: Vec::new(),
        },
    }
}

/// Speakeasy may print logs before JSON — take the outermost `{...}` blob.
fn extract_json(stdout: &str) -> &str {
    let start = stdout.find('{');
    let end = stdout.rfind('}');
    match (start, end) {
        (Some(s), Some(e)) if e > s => &stdout[s..=e],
        _ => stdout.trim(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn staging_is_non_executable_and_cleaned() {
        let bytes = b"MZ\0\0fake-pe-bytes-for-staging-test";
        let path = {
            let staging = StagingDir::create(bytes).expect("stage");
            let p = staging.sample_path().to_path_buf();
            assert!(p.exists());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&p).unwrap().permissions().mode();
                assert_eq!(mode & 0o111, 0, "must not be executable: {mode:o}");
                assert_eq!(mode & 0o400, 0o400, "owner-read expected");
            }
            p
        }; // drop cleans up
        assert!(!path.exists(), "staging file must be removed on drop");
    }

    #[test]
    fn wipe_covers_full_length_not_8mib_cap() {
        // Larger than the old 8 MiB wipe cap — must zero the entire buffer.
        let len = 8 * 1024 * 1024 + 4096;
        let mut buf = vec![0xA5u8; len];
        {
            let mut cursor = Cursor::new(&mut buf);
            wipe_writer(&mut cursor, len).unwrap();
        }
        assert!(buf.iter().all(|&b| b == 0), "full-length wipe required");
    }

    #[test]
    fn staging_drop_removes_large_sample() {
        let len = 8 * 1024 * 1024 + 1024;
        let mut bytes = vec![0x5Au8; len];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        let (sample, dir) = {
            let staging = StagingDir::create(&bytes).expect("stage large");
            (
                staging.sample_path().to_path_buf(),
                staging.dir_path().to_path_buf(),
            )
        };
        assert!(!sample.exists());
        assert!(!dir.exists());
    }

    #[test]
    fn extract_json_strips_prefix_logs() {
        let s = "info: starting\n{\"a\":1}\n";
        assert_eq!(extract_json(s), "{\"a\":1}");
    }

    #[test]
    fn fort_knox_args_include_isolation_flags() {
        let args = fort_knox_run_args(
            "vanguard-dyn-1-2",
            "/tmp/vanguard-dyn-1-2",
            "vanguard-speakeasy:latest",
            45,
        );
        let joined = args.join(" ");
        assert!(joined.contains("--network=none"));
        assert!(joined.contains("--cap-drop=ALL"));
        assert!(joined.contains("no-new-privileges"));
        assert!(joined.contains("--read-only"));
        assert!(joined.contains("--ipc=private"));
        assert!(!joined.contains("--uts=")); // private UTS is Docker default; `--uts=private` is invalid
        assert!(joined.contains("nproc=256:256"));
        assert!(joined.contains("VANGUARD_EMU_TIMEOUT=40"));
        assert!(joined.contains("VANGUARD_SAMPLE=/work/sample.bin"));
        assert!(joined.contains("/tmp/vanguard-dyn-1-2:/work:ro"));
        assert!(args.last().is_some_and(|s| s == "vanguard-speakeasy:latest"));
        // Must not pull / must not enable network aliases.
        assert!(!joined.contains("--network=bridge"));
        assert!(!joined.contains("pull"));
    }

    #[test]
    fn guest_timeout_floors_at_five() {
        assert_eq!(guest_timeout_secs(45), 40);
        assert_eq!(guest_timeout_secs(8), 5);
        assert_eq!(guest_timeout_secs(3), 5);
    }
}
