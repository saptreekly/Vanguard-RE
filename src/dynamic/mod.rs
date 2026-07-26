//! Fort Knox dynamic analysis — Speakeasy inside Docker `--network=none` only.
//!
//! The host OS loader never executes sample bytes. If Docker isolation is
//! unavailable, dynamic analysis is skipped and static triage continues.

mod isolate;
mod map;
mod speakeasy;

pub use isolate::{
    is_staging_dir_name, probe, reap_stale_staging, short_digest, IsolationStatus, DEFAULT_IMAGE,
    STAGING_DIR_PREFIX,
};
pub use speakeasy::fort_knox_run_args;

use crate::heuristics::{BehaviorMatch, CapabilityTag};
use crate::iocs::NetworkIoc;

/// Normalized events extracted from an emulator report.
#[derive(Debug, Clone, Default)]
pub struct DynamicEvents {
    pub apis: Vec<String>,
    pub process_creates: Vec<String>,
    pub network: Vec<String>,
    pub registry_writes: Vec<String>,
    pub file_writes: Vec<String>,
    /// `LoadLibrary*` targets observed during emulation.
    pub libraries: Vec<String>,
    /// `GetProcAddress` names resolved at runtime.
    pub resolved_apis: Vec<String>,
    /// APIs that aborted an entry point (`unsupported_api` errors).
    pub unsupported_apis: Vec<String>,
    /// Other entry-point faults (e.g. `UC_ERR_READ_UNMAPPED`).
    pub emu_faults: Vec<String>,
}

/// MSVC/UCRT / threadpool init resolves — not malware dyn_resolve signal.
pub fn is_runtime_init_api(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    let leaf = l
        .rsplit(['.', '!', '/'])
        .next()
        .unwrap_or(l.as_str())
        .trim();
    if leaf.is_empty() {
        return false;
    }
    if leaf.contains("threadpool")
        || leaf.starts_with("fls")
        || leaf.starts_with("initializecriticalsection")
        || leaf.starts_with("entercriticalsection")
        || leaf.starts_with("leavecriticalsection")
        || leaf.starts_with("deletecriticalsection")
        || leaf.starts_with("initonce")
    {
        return true;
    }
    matches!(
        leaf,
        // Processor / timing / process identity (UCRT startup)
        "flushprocesswritebuffers"
            | "getcurrentprocessornumber"
            | "getcurrentprocessornumberex"
            | "getlogicalprocessorinformation"
            | "getlogicalprocessorinformationex"
            | "getsystemtimeasfiletime"
            | "getsystemtimepreciseasfiletime"
            | "queryperformancecounter"
            | "queryperformancefrequency"
            | "getcurrentthreadid"
            | "getcurrentprocessid"
            | "getcurrentthread"
            | "getcurrentprocess"
            | "isprocessorfeaturepresent"
            | "setunhandledexceptionfilter"
            | "unhandledexceptionfilter"
            | "seterrormode"
            | "getstartupinfoa"
            | "getstartupinfow"
            | "getmodulehandleexa"
            | "getmodulehandleexw"
            | "initializeslisthead"
            | "interlockedpushentryslist"
            | "interlockedpopentryslist"
            | "interlockedflushslist"
            // ntdll unwind / PE helpers used by UCRT x64
            | "rtlcapturecontext"
            | "rtllookupfunctionentry"
            | "rtlvirtualunwind"
            | "rtlinstallfunctiontablecallback"
            | "rtldelfunctiontable"
            | "rtlpctofileheader"
            | "rtlunwind"
            | "corexitprocess"
            | "exitprocess"
            | "terminateprocess"
            | "getprocessheaps"
            | "heapsetinformation"
            | "encodepointer"
            | "decodepointer"
            | "initialize_onexit_table"
            | "register_onexit_function"
            | "execute_onexit_table"
            | "initterm"
            | "_initterm"
            | "_initterm_e"
            // Vista+ kernel32 delay-loads probed by MSVC CRT / appcrt
            | "comparestringex"
            | "lcmapstringex"
            | "getlocaleinfoex"
            | "getdateformatex"
            | "gettimeformatex"
            | "getuserdefaultlocalename"
            | "isvalidlocalename"
            | "localenametolcid"
            | "lcidtolocalename"
            | "enumsystemlocalesex"
            | "createeventexw"
            | "createeventexa"
            | "createsemaphoreexw"
            | "createsemaphoreexa"
            | "createmutexexw"
            | "createmutexexa"
            | "createwaitabletimerexw"
            | "createwaitabletimerexa"
            | "createsymboliclinkw"
            | "createsymboliclinka"
            | "setdefaultdlldirectories"
            | "setfileinformationbyhandle"
            | "setfileinformationbyhandlea"
            | "setfileinformationbyhandlew"
            | "getfinalpathnamebyhandlew"
            | "getfinalpathnamebyhandlea"
            | "gettickcount64"
            | "getfileinformationbyhandleex"
            | "getfileinformationbyhandleexa"
            | "getfileinformationbyhandleexw"
            | "canceliosex"
            | "getqueuedcompletionstatusex"
            | "freelibrarywhencallbackreturns"
            | "setthreadstackguarantee"
            | "getcurrentpackageid"
            | "wergetflags"
            | "wersetflags"
            | "roinitialize"
            | "rouninitialize"
            | "windowscreatestring"
            | "windowsdeletestring"
    ) || leaf.starts_with("_initterm")
        || leaf.starts_with("__stdio")
        || leaf.starts_with("__iob")
}

impl DynamicEvents {
    /// Interesting (non-CRT) GetProcAddress targets.
    pub fn interesting_resolves(&self) -> Vec<&str> {
        self.resolved_apis
            .iter()
            .filter(|a| !is_runtime_init_api(a))
            .map(|s| s.as_str())
            .collect()
    }

    /// CRT / UCRT / threadpool init resolves.
    pub fn runtime_resolves(&self) -> Vec<&str> {
        self.resolved_apis
            .iter()
            .filter(|a| is_runtime_init_api(a))
            .map(|s| s.as_str())
            .collect()
    }

    /// Short human-readable highlights for the CLI sample block.
    pub fn highlights(&self) -> Vec<String> {
        let mut out = Vec::new();
        for f in self.file_writes.iter().filter(|f| {
            let l = f.to_ascii_lowercase();
            l.ends_with(".dll") || l.ends_with(".exe") || l.ends_with(".sys")
        }) {
            out.push(format!("drop {f}"));
            if out.len() >= 3 {
                break;
            }
        }
        if out.len() < 3 {
            for f in self.file_writes.iter().take(2) {
                let line = format!("drop {f}");
                if !out.iter().any(|e| e == &line) {
                    out.push(line);
                }
                if out.len() >= 3 {
                    break;
                }
            }
        }
        for r in self.registry_writes.iter().take(3) {
            out.push(format!("reg {r}"));
        }
        for p in self.process_creates.iter().take(2) {
            out.push(format!("spawn {p}"));
        }
        for lib in self.libraries.iter().take(3) {
            out.push(format!("load {lib}"));
        }
        for api in self.interesting_resolves().into_iter().take(4) {
            out.push(format!("resolve {api}"));
        }
        for n in self.network.iter().take(2) {
            out.push(format!("net {n}"));
        }
        out.truncate(10);
        out
    }
}

/// Result of one dynamic emulation attempt (ok / skipped / error / timeout).
#[derive(Debug, Clone)]
pub struct DynamicDive {
    pub backend: String,
    pub elapsed_ms: u64,
    pub status: String,
    pub summary: String,
    pub events: DynamicEvents,
    pub capabilities: Vec<CapabilityTag>,
    pub behaviors: Vec<BehaviorMatch>,
    pub network_iocs: Vec<NetworkIoc>,
}

impl DynamicDive {
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            backend: "speakeasy".into(),
            elapsed_ms: 0,
            status: "skipped".into(),
            summary: reason.into(),
            events: DynamicEvents::default(),
            capabilities: Vec::new(),
            behaviors: Vec::new(),
            network_iocs: Vec::new(),
        }
    }

    pub fn ok(&self) -> bool {
        self.status == "ok"
    }
}

/// Archive-level dynamic status for the banner.
#[derive(Debug, Clone)]
pub enum DynamicStatus {
    Ready { image: String, image_id: String },
    Disabled { reason: String },
    Unavailable { reason: String },
    Ran {
        ok: usize,
        failed: usize,
        skipped: usize,
        image: String,
        image_id: String,
    },
}

impl DynamicStatus {
    pub fn banner_line(&self) -> String {
        match self {
            Self::Ready { image_id, .. } => {
                format!(
                    "speakeasy ready  {}  (Docker network=none)",
                    short_digest(image_id)
                )
            }
            Self::Disabled { reason } => format!("disabled ({reason})"),
            Self::Unavailable { reason } => format!("skipped — {reason}"),
            Self::Ran {
                ok,
                failed,
                skipped,
                image_id,
                ..
            } => format!(
                "speakeasy  ok={ok}  failed={failed}  skipped={skipped}  {}  (Docker network=none)",
                short_digest(image_id)
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EmulateOptions {
    pub timeout_secs: u64,
}

impl Default for EmulateOptions {
    fn default() -> Self {
        Self { timeout_secs: 45 }
    }
}

/// Budget for dynamic runs per archive (plan: max 3).
pub const MAX_DYNAMIC_PER_ARCHIVE: usize = 3;

/// Minimum triage score to prefer for dynamic slots.
pub const MIN_DYNAMIC_SCORE: u8 = 40;

/// Probe isolation; never pulls images.
pub fn isolation_status() -> IsolationStatus {
    probe()
}

/// Emulate PE bytes under Speakeasy/Docker. Fail-closed on isolation issues.
pub fn emulate_pe(bytes: &[u8], opts: EmulateOptions) -> DynamicDive {
    let status = probe();
    speakeasy::emulate_pe(bytes, opts, &status)
}

/// Emulate using a pre-probed isolation status (avoids repeated docker inspect).
pub fn emulate_pe_with_status(
    bytes: &[u8],
    opts: EmulateOptions,
    status: &IsolationStatus,
) -> DynamicDive {
    speakeasy::emulate_pe(bytes, opts, status)
}

/// Merge dynamic tags into an existing capability list (dynamic evidence appended;
/// static confidence never lowered).
pub fn merge_capabilities(static_caps: &mut Vec<CapabilityTag>, dynamic: &[CapabilityTag]) {
    for d in dynamic {
        if let Some(existing) = static_caps.iter_mut().find(|c| c.id == d.id) {
            existing.confidence = existing.confidence.max(d.confidence);
            for e in &d.evidence {
                if !existing.evidence.iter().any(|x| x == e) {
                    existing.evidence.push(e.clone());
                }
            }
        } else {
            static_caps.push(d.clone());
        }
    }
    static_caps.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.id.cmp(&b.id)));
}

/// Merge dynamic network IOCs (already prefixed `dyn:`) into the sample list.
pub fn merge_network(static_iocs: &mut Vec<NetworkIoc>, dynamic: &[NetworkIoc]) {
    for d in dynamic {
        if !static_iocs.iter().any(|s| s.value == d.value) {
            static_iocs.push(d.clone());
        }
    }
    static_iocs.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(b.count.cmp(&a.count))
            .then(a.value.cmp(&b.value))
    });
    static_iocs.truncate(60);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::CapabilityTag;
    use crate::iocs::{IocKind, NetworkIoc};

    #[test]
    fn runtime_init_api_detects_ucrt_noise() {
        assert!(is_runtime_init_api("FlushProcessWriteBuffers"));
        assert!(is_runtime_init_api("kernel32.GetLogicalProcessorInformation"));
        assert!(is_runtime_init_api("CloseThreadpoolTimer"));
        assert!(is_runtime_init_api("RtlPcToFileHeader"));
        assert!(is_runtime_init_api("CompareStringEx"));
        assert!(is_runtime_init_api("CreateEventExW"));
        assert!(is_runtime_init_api("EnumSystemLocalesEx"));
        assert!(!is_runtime_init_api("InternetOpenA"));
        assert!(!is_runtime_init_api("CreateProcessW"));
        assert!(!is_runtime_init_api("HttpSendRequestA"));
    }

    #[test]
    fn emulate_skips_when_isolation_unavailable() {
        let status = IsolationStatus::Unavailable {
            reason: "Docker CLI not available or daemon not running".into(),
        };
        let dive = emulate_pe_with_status(b"MZ\0\0not-a-real-pe", EmulateOptions::default(), &status);
        assert_eq!(dive.status, "skipped");
        assert!(dive.summary.contains("Docker") || dive.summary.contains("isolation"));
        assert!(dive.capabilities.is_empty());
    }

    #[test]
    fn emulate_skips_when_forced_off_status() {
        let status = IsolationStatus::Disabled {
            reason: "VANGUARD_DYNAMIC=0".into(),
        };
        let dive = emulate_pe_with_status(b"MZ\0\0", EmulateOptions::default(), &status);
        assert_eq!(dive.status, "skipped");
        assert!(dive.summary.contains("VANGUARD_DYNAMIC=0"));
    }

    #[test]
    fn merge_capabilities_never_lowers_static_confidence() {
        let mut caps = vec![CapabilityTag {
            id: "exec".into(),
            label: "Process execution".into(),
            confidence: 80,
            evidence: vec!["static: CreateProcessA".into()],
        }];
        let dyn_caps = vec![CapabilityTag {
            id: "exec".into(),
            label: "Process execution".into(),
            confidence: 50,
            evidence: vec!["dynamic: CreateProcessA".into()],
        }];
        merge_capabilities(&mut caps, &dyn_caps);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].confidence, 80);
        assert!(caps[0].evidence.iter().any(|e| e.starts_with("dynamic:")));
        assert!(caps[0].evidence.iter().any(|e| e.starts_with("static:")));
    }

    #[test]
    fn merge_network_adds_dyn_prefix_iocs() {
        let mut iocs = vec![NetworkIoc {
            kind: IocKind::Domain,
            value: "static.example".into(),
            confidence: 70,
            count: 1,
            private: false,
        }];
        let dyn_iocs = vec![NetworkIoc {
            kind: IocKind::Url,
            value: "dyn:http://evil.example/gate".into(),
            confidence: 95,
            count: 1,
            private: false,
        }];
        merge_network(&mut iocs, &dyn_iocs);
        assert_eq!(iocs.len(), 2);
        assert!(iocs[0].value.starts_with("dyn:"));
    }
}
