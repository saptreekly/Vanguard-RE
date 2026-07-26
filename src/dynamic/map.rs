//! Map Speakeasy JSON reports into Vanguard capabilities / network IOCs.
//!
//! Supports Speakeasy report 1.x (`entry_points[].apis[]` + `args`) and
//! 3.x (`entry_points[].events[]` with typed `event` fields).
//! Deliberately ignores the report `strings` tables — those are static
//! artifacts, not observed API calls.

use serde_json::Value;

use crate::heuristics::{BehaviorMatch, CapabilityTag};
use crate::iocs::{IocKind, NetworkIoc};

use super::DynamicEvents;

/// Parse Speakeasy JSON into normalized events + CAPA-like tags.
pub fn map_speakeasy_json(
    json: &str,
) -> Result<(DynamicEvents, Vec<CapabilityTag>, Vec<BehaviorMatch>, Vec<NetworkIoc>), String> {
    let root: Value =
        serde_json::from_str(json).map_err(|e| format!("invalid Speakeasy JSON: {e}"))?;

    let mut apis = Vec::new();
    let mut process_creates = Vec::new();
    let mut network_raw = Vec::new();
    let mut registry_writes = Vec::new();
    let mut file_writes = Vec::new();
    let mut libraries = Vec::new();
    let mut resolved_apis = Vec::new();
    let mut unsupported_apis = Vec::new();
    let mut emu_faults = Vec::new();

    if let Some(eps) = root.get("entry_points").and_then(|v| v.as_array()) {
        for ep in eps {
            // Speakeasy 1.x: apis[{api_name, args, ret_val}]
            if let Some(arr) = ep.get("apis").and_then(|v| v.as_array()) {
                for item in arr {
                    ingest_api_record(
                        item,
                        &mut apis,
                        &mut process_creates,
                        &mut network_raw,
                        &mut registry_writes,
                        &mut file_writes,
                        &mut libraries,
                        &mut resolved_apis,
                    );
                }
            }
            // Speakeasy 3.x: unified events stream
            if let Some(arr) = ep.get("events").and_then(|v| v.as_array()) {
                for item in arr {
                    ingest_event_record(
                        item,
                        &mut apis,
                        &mut process_creates,
                        &mut network_raw,
                        &mut registry_writes,
                        &mut file_writes,
                        &mut libraries,
                        &mut resolved_apis,
                    );
                }
            }
            // Dropped file paths (metadata only — never contents).
            if let Some(arr) = ep.get("dropped_files").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(path) = string_field(item, &["path", "file_name", "file"]) {
                        file_writes.push(path);
                    }
                }
            }
            // Entry-point abort (see Speakeasy limitations.md).
            if let Some(err) = ep.get("error") {
                let etype = err.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if etype.is_empty() {
                    // ignore empty error objects Speakeasy sometimes emits
                } else if etype == "unsupported_api" {
                    if let Some(name) = string_field(err, &["api_name", "api", "name"]) {
                        unsupported_apis.push(name);
                    } else {
                        emu_faults.push(etype.to_string());
                    }
                } else {
                    // e.g. Invalid memory read (UC_ERR_READ_UNMAPPED)
                    let short = etype
                        .split('(')
                        .nth(1)
                        .and_then(|s| s.split(')').next())
                        .unwrap_or(etype);
                    emu_faults.push(short.trim().to_string());
                }
            }
        }
    }

    // Entrypoint attaches `vanguard.unsupported_apis` after the run.
    if let Some(arr) = root
        .pointer("/vanguard/unsupported_apis")
        .and_then(|v| v.as_array())
    {
        for item in arr {
            if let Some(s) = item.as_str() {
                unsupported_apis.push(s.to_string());
            }
        }
    }

    dedupe_strings(&mut apis);
    dedupe_strings(&mut process_creates);
    dedupe_strings(&mut network_raw);
    dedupe_strings(&mut registry_writes);
    dedupe_strings(&mut file_writes);
    dedupe_strings(&mut libraries);
    dedupe_strings(&mut resolved_apis);
    dedupe_strings(&mut unsupported_apis);
    dedupe_strings(&mut emu_faults);

    let events = DynamicEvents {
        apis: apis.clone(),
        process_creates: process_creates.clone(),
        network: network_raw.clone(),
        registry_writes: registry_writes.clone(),
        file_writes: file_writes.clone(),
        libraries,
        resolved_apis,
        unsupported_apis,
        emu_faults,
    };

    let (caps, behaviors) = events_to_tags(&events);
    let network_iocs = network_strings_to_iocs(&network_raw);

    Ok((events, caps, behaviors, network_iocs))
}

fn ingest_api_record(
    item: &Value,
    apis: &mut Vec<String>,
    procs: &mut Vec<String>,
    network: &mut Vec<String>,
    registry: &mut Vec<String>,
    files: &mut Vec<String>,
    libraries: &mut Vec<String>,
    resolved: &mut Vec<String>,
) {
    let Some(api_name) = string_field(item, &["api_name", "api", "name"]) else {
        return;
    };
    apis.push(api_name.clone());
    let args = arg_strings(item);
    classify_api(
        &api_name,
        &args,
        procs,
        network,
        registry,
        files,
        libraries,
        resolved,
    );
}

fn ingest_event_record(
    item: &Value,
    apis: &mut Vec<String>,
    procs: &mut Vec<String>,
    network: &mut Vec<String>,
    registry: &mut Vec<String>,
    files: &mut Vec<String>,
    libraries: &mut Vec<String>,
    resolved: &mut Vec<String>,
) {
    let event = string_field(item, &["event"]).unwrap_or_default();
    let event_l = event.to_ascii_lowercase();

    if event_l == "api" || event_l.is_empty() && item.get("api_name").is_some() {
        ingest_api_record(
            item, apis, procs, network, registry, files, libraries, resolved,
        );
        return;
    }

    if event_l.contains("process") {
        if let Some(cmd) = string_field(item, &["cmdline", "command_line", "path", "image", "process"])
        {
            if !is_boring_path(&cmd) {
                procs.push(cmd);
            }
        }
        return;
    }

    if event_l.starts_with("net_") || event_l.contains("dns") || event_l.contains("http") {
        push_network_fields(item, network);
        return;
    }

    if event_l.starts_with("reg_") || event_l.contains("reg") {
        if let Some(path) = string_field(item, &["path", "key"]) {
            let value_name = string_field(item, &["value_name", "name"]);
            if let Some(vn) = value_name {
                registry.push(format!("{path}\\{vn}"));
            } else {
                registry.push(path);
            }
        }
        return;
    }

    if event_l.starts_with("file_") || event_l.contains("file") {
        if let Some(path) = string_field(item, &["path", "file"]) {
            if !is_boring_path(&path) {
                files.push(path);
            }
        }
    }
}

fn classify_api(
    api_name: &str,
    args: &[String],
    procs: &mut Vec<String>,
    network: &mut Vec<String>,
    registry: &mut Vec<String>,
    files: &mut Vec<String>,
    libraries: &mut Vec<String>,
    resolved: &mut Vec<String>,
) {
    let api_l = api_name.to_ascii_lowercase();
    let leaf = api_leaf(&api_l);

    if leaf.contains("createprocess")
        || leaf.contains("shellexecute")
        || leaf.contains("winexec")
        || leaf == "system"
        || leaf.starts_with("exec")
    {
        if let Some(cmd) = process_cmd_from_args(args) {
            procs.push(cmd);
        }
    }

    // RegOpenKeyEx(hkey, subkey, ...) / RegCreateKey / RegSetValue
    if leaf.contains("regopenkey")
        || leaf.contains("regcreatekey")
        || leaf.contains("regsetvalue")
        || leaf.contains("regsetkey")
        || leaf.contains("createservice")
    {
        if let Some(path) = registry_path_from_args(args) {
            registry.push(path);
        }
    }

    if leaf.contains("copyfile")
        || leaf.contains("movefile")
        || leaf.contains("writefile")
        || leaf.contains("createfile")
        || leaf.contains("replacefile")
        || leaf.contains("findfirstfile")
    {
        for a in args.iter().take(2) {
            if looks_like_filepath(a) && !is_boring_path(a) {
                files.push(a.clone());
            }
        }
    }

    if leaf.contains("loadlibrary") {
        if let Some(lib) = first_meaningful_arg(args) {
            libraries.push(lib);
        }
    }

    if leaf.contains("getprocaddress") {
        // args: [hModule, lpProcName]
        if let Some(name) = args.get(1).cloned().or_else(|| first_meaningful_arg(args)) {
            if !name.starts_with("0x") && name.len() > 1 {
                resolved.push(name);
            }
        }
    }

    if leaf.contains("internetopenurl")
        || leaf.contains("httpopenrequest")
        || leaf.contains("httpsendrequest")
        || leaf.contains("urldownload")
        || leaf.contains("winhttp")
    {
        for a in args {
            if looks_like_network(a) {
                network.push(a.clone());
            }
        }
    }

    if leaf == "connect"
        || leaf.contains("wsaconnect")
        || leaf.contains("getaddrinfo")
        || leaf.contains("gethostbyname")
        || leaf.starts_with("dnsquery")
    {
        for a in args {
            if looks_like_network(a) || looks_like_host_port(a) {
                network.push(a.clone());
            }
        }
    }
}

fn registry_path_from_args(args: &[String]) -> Option<String> {
    let meaningful: Vec<&String> = args
        .iter()
        .filter(|a| {
            !a.is_empty()
                && *a != &"0x0".to_string()
                && *a != "NULL"
                && !a.starts_with("0x")
                && a.len() > 1
        })
        .collect();
    if meaningful.is_empty() {
        return None;
    }
    // RegOpenKeyExA: [HKEY_LOCAL_MACHINE, SOFTWARE\..., options, access, phk]
    if meaningful.len() >= 2
        && meaningful[0].to_ascii_uppercase().starts_with("HKEY_")
    {
        return Some(format!("{}\\{}", meaningful[0], meaningful[1]));
    }
    Some(meaningful[0].clone())
}

fn process_cmd_from_args(args: &[String]) -> Option<String> {
    // CreateProcess: [appName, commandLine, ...] — prefer cmdline, else app.
    // ShellExecute: [hwnd, op, file, params, ...]
    // WinExec: [cmd, show]
    let candidates: Vec<&String> = args
        .iter()
        .filter(|a| !a.is_empty() && *a != "0x0" && *a != "NULL" && !a.starts_with("0x"))
        .collect();
    if candidates.is_empty() {
        return None;
    }
    // Prefer the longest printable arg that looks like a command/path.
    let mut best: Option<&String> = None;
    for c in &candidates {
        let l = c.to_ascii_lowercase();
        if l.contains(".exe")
            || l.contains("powershell")
            || l.contains("cmd")
            || l.contains("rundll")
            || l.contains("regsvr")
            || l.contains('\\')
            || l.contains('/')
            || c.contains(' ')
        {
            best = Some(c);
            break;
        }
    }
    best.or(Some(candidates[0])).cloned()
}

fn first_meaningful_arg(args: &[String]) -> Option<String> {
    args.iter()
        .find(|a| {
            !a.is_empty()
                && *a != &"0x0".to_string()
                && *a != "NULL"
                && !a.starts_with("0x")
                && a.len() > 1
        })
        .cloned()
}

fn push_network_fields(item: &Value, network: &mut Vec<String>) {
    for key in [
        "url", "server", "host", "domain", "query", "response", "dns", "ip", "dst", "address",
    ] {
        if let Some(Value::String(s)) = item.get(key) {
            if looks_like_network(s) || looks_like_host_port(s) || s.parse::<std::net::Ipv4Addr>().is_ok()
            {
                network.push(s.clone());
            } else if key == "query" || key == "domain" || key == "host" || key == "server" {
                // DNS queries are often bare hostnames Speakeasy already resolved.
                if !s.is_empty() && !s.starts_with("0x") {
                    network.push(s.clone());
                }
            }
        }
    }
    if let (Some(server), Some(port)) = (
        string_field(item, &["server", "host"]),
        item.get("port").and_then(|p| {
            p.as_u64()
                .map(|n| n.to_string())
                .or_else(|| p.as_str().map(|s| s.to_string()))
        }),
    ) {
        if !server.is_empty() {
            network.push(format!("{server}:{port}"));
        }
    }
    if let Some(headers) = string_field(item, &["headers"]) {
        // Pull Host: / absolute URL from HTTP headers blob.
        for line in headers.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("Host:") {
                let host = rest.trim();
                if !host.is_empty() {
                    network.push(host.to_string());
                }
            }
            for tok in line.split_whitespace() {
                if looks_like_network(tok) {
                    network.push(tok.to_string());
                }
            }
        }
    }
}

fn arg_strings(item: &Value) -> Vec<String> {
    let Some(args) = item.get("args").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    args.iter()
        .filter_map(|a| match a {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Object(map) => {
                // Speakeasy sometimes nests {name, value}
                map.get("value")
                    .and_then(|v| v.as_str())
                    .or_else(|| map.get("arg").and_then(|v| v.as_str()))
                    .map(|s| s.to_string())
            }
            _ => None,
        })
        .collect()
}

fn string_field(item: &Value, keys: &[&str]) -> Option<String> {
    let map = item.as_object()?;
    for key in keys {
        if let Some(Value::String(s)) = map.get(*key) {
            if !s.is_empty() {
                return Some(s.clone());
            }
        }
    }
    None
}

fn api_leaf(api_l: &str) -> &str {
    api_l.rsplit('.').next().unwrap_or(api_l)
}

fn looks_like_filepath(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains('\\')
        || l.contains('/')
        || l.ends_with(".exe")
        || l.ends_with(".dll")
        || l.ends_with(".sys")
        || l.ends_with(".tmp")
        || l.ends_with(".lnk")
        || l.ends_with(".dat")
        || l.ends_with(".bat")
        || l.ends_with(".ps1")
}

fn is_boring_path(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.is_empty()
        || l == "0x0"
        || l == "null"
        || l == "binary"
        || l.starts_with("0x") && !l.contains('\\')
}

fn looks_like_network(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.contains(".onion")
        || lower.parse::<std::net::Ipv4Addr>().is_ok()
        || (lower.contains('.')
            && lower.len() >= 4
            && !lower.contains(' ')
            && !lower.contains('\\')
            && lower.len() < 253
            && !lower.ends_with(".dll")
            && !lower.ends_with(".exe")
            && !lower.ends_with(".sys"))
}

fn looks_like_host_port(s: &str) -> bool {
    if let Some((host, port)) = s.rsplit_once(':') {
        return port.parse::<u16>().is_ok()
            && (host.parse::<std::net::Ipv4Addr>().is_ok() || looks_like_network(host));
    }
    false
}

fn events_to_tags(events: &DynamicEvents) -> (Vec<CapabilityTag>, Vec<BehaviorMatch>) {
    let mut caps = Vec::new();
    let mut behaviors = Vec::new();
    let api_blob = events.apis.join(" ").to_ascii_lowercase();
    let proc_blob = events.process_creates.join(" ").to_ascii_lowercase();

    let mut push_cap = |id: &str, label: &str, evidence: Vec<String>, confidence: u8| {
        if evidence.is_empty() {
            return;
        }
        caps.push(CapabilityTag {
            id: id.into(),
            label: label.into(),
            confidence,
            evidence,
        });
    };

    // Process execution
    let mut exec_ev = Vec::new();
    for a in &events.apis {
        let l = a.to_ascii_lowercase();
        let leaf = api_leaf(&l);
        if leaf.contains("createprocess") || leaf.contains("shellexecute") || leaf.contains("winexec")
        {
            exec_ev.push(format!("dynamic: {a}"));
        }
    }
    for p in events.process_creates.iter().take(8) {
        exec_ev.push(format!("dynamic: spawn {p}"));
    }
    exec_ev.sort();
    exec_ev.dedup();
    if !exec_ev.is_empty() {
        push_cap("exec", "Process execution", exec_ev.clone(), 88);
        behaviors.push(BehaviorMatch {
            name: "dynamic_process_create".into(),
            severity: 70,
            description: "Speakeasy observed process-creation / shell launch".into(),
            matched_apis: exec_ev,
        });
    }

    // Script / shell
    let mut script_ev = Vec::new();
    for p in &events.process_creates {
        let l = p.to_ascii_lowercase();
        if l.contains("powershell")
            || l.contains("pwsh")
            || l.contains("cmd.exe")
            || l.contains("wscript")
            || l.contains("cscript")
            || l.contains("mshta")
            || l.contains("rundll32")
            || l.contains("regsvr32")
        {
            script_ev.push(format!("dynamic: {p}"));
        }
    }
    if api_blob.contains("shellexecute") && proc_blob.contains("powershell") {
        script_ev.push("dynamic: ShellExecute → powershell".into());
    }
    if !script_ev.is_empty() {
        push_cap("script_exec", "Script / shell launch", script_ev.clone(), 92);
        behaviors.push(BehaviorMatch {
            name: "dynamic_script_launch".into(),
            severity: 75,
            description: "Speakeasy observed shell/script/LOLBin process launch".into(),
            matched_apis: script_ev,
        });
    }

    // Persistence / registry recon
    let mut pers = Vec::new();
    for a in &events.apis {
        let l = a.to_ascii_lowercase();
        let leaf = api_leaf(&l);
        if leaf.contains("regsetvalue")
            || leaf.contains("regcreatekey")
            || leaf.contains("regopenkey")
            || leaf.contains("createservice")
        {
            pers.push(format!("dynamic: {a}"));
        }
    }
    for r in events.registry_writes.iter().take(8) {
        pers.push(format!("dynamic: reg {r}"));
    }
    pers.sort();
    pers.dedup();
    if !pers.is_empty() {
        // Writes/creates stay high; opens alone are slightly softer.
        let conf = if events.apis.iter().any(|a| {
            let l = a.to_ascii_lowercase();
            let leaf = api_leaf(&l);
            leaf.contains("regsetvalue") || leaf.contains("regcreatekey")
        }) {
            85
        } else {
            70
        };
        push_cap("persistence", "Persistence", pers, conf);
    }

    // Dynamic resolve
    let mut dyn_ev = Vec::new();
    for a in &events.apis {
        let l = a.to_ascii_lowercase();
        let leaf = api_leaf(&l);
        if leaf.contains("loadlibrary") || leaf.contains("getprocaddress") {
            dyn_ev.push(format!("dynamic: {a}"));
        }
    }
    for lib in events.libraries.iter().take(6) {
        dyn_ev.push(format!("dynamic: load {lib}"));
    }
    // Skip MSVC/UCRT init resolves — they are not malware dyn_resolve signal.
    for api in events
        .resolved_apis
        .iter()
        .filter(|a| !super::is_runtime_init_api(a))
        .take(8)
    {
        dyn_ev.push(format!("dynamic: resolve {api}"));
    }
    dyn_ev.sort();
    dyn_ev.dedup();
    if !dyn_ev.is_empty() {
        push_cap("dyn_resolve", "Dynamic API resolve", dyn_ev, 90);
    }

    // Process enumeration
    let mut enum_ev = Vec::new();
    for a in &events.apis {
        let l = a.to_ascii_lowercase();
        let leaf = api_leaf(&l);
        if leaf.contains("createtoolhelp32snapshot")
            || leaf.contains("process32")
            || leaf.contains("module32")
            || leaf == "enumprocesses"
        {
            enum_ev.push(format!("dynamic: {a}"));
        }
    }
    if !enum_ev.is_empty() {
        push_cap("process_enum", "Process enumeration", enum_ev, 80);
    }

    // File drop — prefer distinctive destinations (dll/exe/sys) over repetitive probes.
    let mut api_drop = Vec::new();
    for a in &events.apis {
        let l = a.to_ascii_lowercase();
        let leaf = api_leaf(&l);
        if leaf.contains("copyfile") || leaf.contains("movefile") || leaf.contains("writefile") {
            api_drop.push(format!("dynamic: {a}"));
        }
    }
    api_drop.sort();
    api_drop.dedup();
    let mut ranked_files = events.file_writes.clone();
    ranked_files.sort_by_key(|f| {
        let l = f.to_ascii_lowercase();
        let score = if l.ends_with(".dll") || l.ends_with(".exe") || l.ends_with(".sys") {
            0
        } else if l.ends_with(".lnk") {
            2
        } else {
            1
        };
        (score, f.clone())
    });
    let mut drop_ev = api_drop;
    for f in ranked_files.into_iter().take(6) {
        drop_ev.push(format!("dynamic: file {f}"));
    }
    if !drop_ev.is_empty() {
        push_cap("file_drop", "File drop / write", drop_ev, 88);
    }

    // Network client — APIs called *or* WinINet/WinHTTP names resolved via GetProcAddress.
    let mut net = Vec::new();
    for a in &events.apis {
        let l = a.to_ascii_lowercase();
        let leaf = api_leaf(&l);
        if leaf.contains("internetopen")
            || leaf.contains("httpopen")
            || leaf.contains("httpsend")
            || leaf.contains("winhttp")
            || leaf.contains("urldownload")
            || leaf.contains("wsasocket")
            || leaf.contains("wsaconnect")
            || leaf == "connect"
            || leaf.contains("getadapters")
        {
            net.push(format!("dynamic: {a}"));
        }
    }
    for api in events
        .resolved_apis
        .iter()
        .filter(|a| !super::is_runtime_init_api(a))
    {
        let l = api.to_ascii_lowercase();
        if l.contains("internet") || l.starts_with("http") || l.contains("winhttp") || l.contains("urldownload")
        {
            net.push(format!("dynamic: resolve {api}"));
        }
    }
    for lib in &events.libraries {
        let l = lib.to_ascii_lowercase();
        if l.contains("wininet") || l.contains("winhttp") || l.contains("ws2_32") || l.contains("iphlpapi")
        {
            net.push(format!("dynamic: load {lib}"));
        }
    }
    for n in events.network.iter().take(10) {
        net.push(format!("dynamic: {n}"));
    }
    net.sort();
    net.dedup();
    if !net.is_empty() {
        let blob = net.join(" ").to_ascii_lowercase();
        let id = if blob.contains("http") || blob.contains("internet") || blob.contains("wininet") {
            "http_client"
        } else {
            "socket_client"
        };
        let label = if id == "http_client" {
            "HTTP client"
        } else {
            "Socket client"
        };
        push_cap(id, label, net, 90);
    }

    // Injection
    let mut inj = Vec::new();
    for a in &events.apis {
        let l = a.to_ascii_lowercase();
        let leaf = api_leaf(&l);
        if leaf.contains("virtualallocex")
            || leaf.contains("writeprocessmemory")
            || leaf.contains("createremotethread")
            || leaf.contains("ntunmapviewofsection")
        {
            inj.push(format!("dynamic: {a}"));
        }
    }
    if inj.len() >= 2 {
        push_cap("injection", "Process injection", inj, 90);
    }

    caps.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.id.cmp(&b.id)));
    (caps, behaviors)
}

fn network_strings_to_iocs(raw: &[String]) -> Vec<NetworkIoc> {
    let mut out = Vec::new();
    for s in raw {
        let lower = s.to_ascii_lowercase();
        let (kind, confidence) = if lower.starts_with("http://") || lower.starts_with("https://") {
            (IocKind::Url, 95)
        } else if lower.contains(".onion") {
            (IocKind::Onion, 95)
        } else if lower.parse::<std::net::Ipv4Addr>().is_ok() {
            (IocKind::Ipv4, 90)
        } else if looks_like_host_port(&lower) {
            (IocKind::Ipv4Port, 95)
        } else if lower.contains('.') && !lower.contains('\\') {
            (IocKind::Domain, 85)
        } else {
            continue;
        };
        let value = format!("dyn:{lower}");
        if out.iter().any(|i: &NetworkIoc| i.value == value) {
            continue;
        }
        out.push(NetworkIoc {
            kind,
            value,
            confidence,
            count: 1,
            private: false,
        });
    }
    out.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.value.cmp(&b.value)));
    out.truncate(40);
    out
}

fn dedupe_strings(v: &mut Vec<String>) {
    v.sort();
    v.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_v3_events_process_and_http() {
        let json = r#"{
          "report_version": "3.0.0",
          "entry_points": [{
            "events": [
              {"event": "api", "api_name": "kernel32.CreateProcessA", "args": ["", "powershell.exe -enc AAA"]},
              {"event": "process_create", "path": "C:\\\\Windows\\\\System32\\\\cmd.exe", "cmdline": "cmd.exe /c whoami"},
              {"event": "net_http", "server": "evil.example", "port": 80, "headers": "GET /gate HTTP/1.1\\nHost: evil.example\\n"},
              {"event": "net_dns", "query": "c2.evil.example", "response": "1.2.3.4"},
              {"event": "reg_write_value", "path": "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "value_name": "Update"}
            ]
          }]
        }"#;
        let (events, caps, behaviors, iocs) = map_speakeasy_json(json).unwrap();
        assert!(events.process_creates.iter().any(|p| p.contains("powershell")));
        assert!(events.process_creates.iter().any(|p| p.contains("cmd.exe")));
        assert!(events.network.iter().any(|n| n.contains("evil.example")));
        assert!(events.registry_writes.iter().any(|r| r.contains("Run")));
        assert!(caps.iter().any(|c| c.id == "exec"));
        assert!(caps.iter().any(|c| c.id == "script_exec"));
        assert!(caps.iter().any(|c| c.id == "http_client" || c.id == "socket_client"));
        assert!(behaviors.iter().any(|b| b.name == "dynamic_script_launch"));
        assert!(iocs.iter().any(|i| i.value.contains("evil.example")));
        assert!(iocs.iter().all(|i| i.value.starts_with("dyn:")));
    }

    #[test]
    fn maps_v1_apis_with_copyfile_args() {
        // Real Speakeasy 1.1 shape (Fanny-like): apis + args, no events stream.
        let json = r#"{
          "report_version": "1.1.0",
          "entry_points": [{
            "ep_type": "export.no_name",
            "apis": [
              {"pc": "0x100012d1", "api_name": "KERNEL32.CopyFileA",
               "args": ["C:\\\\Windows\\\\system32\\\\comhost.dll", "", "0x0"], "ret_val": "0x1"},
              {"pc": "0x10001", "api_name": "KERNEL32.CreateProcessA",
               "args": ["", "rundll32.exe agentcpd.dll,Install"], "ret_val": "0x1"},
              {"pc": "0x10002", "api_name": "ADVAPI32.RegSetValueExA",
               "args": ["Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon", "Shell"], "ret_val": "0x0"},
              {"pc": "0x10003", "api_name": "ADVAPI32.RegOpenKeyExA",
               "args": ["HKEY_LOCAL_MACHINE", "SOFTWARE\\\\Classes\\\\CLSID\\\\{AAAA}", "0x0", "0x20019", "0x1"], "ret_val": "0x0"},
              {"pc": "0x10004", "api_name": "KERNEL32.LoadLibraryA",
               "args": ["iphlpapi.dll"], "ret_val": "0x5fd00000"},
              {"pc": "0x10005", "api_name": "KERNEL32.GetProcAddress",
               "args": ["0x5fd00000", "GetAdaptersInfo"], "ret_val": "0x1"},
              {"pc": "0x10006", "api_name": "kernel32.Process32First",
               "args": ["0x1808", "0x121183c"], "ret_val": "0x1"}
            ]
          }],
          "strings": {
            "static": { "ansi": ["KERNEL32.CreateProcessA", "http://not-a-real-call.example/"] }
          }
        }"#;
        let (events, caps, _behaviors, iocs) = map_speakeasy_json(json).unwrap();
        assert_eq!(events.apis.len(), 7, "must not ingest strings table as APIs");
        assert!(events.file_writes.iter().any(|f| f.contains("comhost.dll")));
        assert!(events.process_creates.iter().any(|p| p.contains("rundll32")));
        assert!(events.registry_writes.iter().any(|r| r.contains("Winlogon")));
        assert!(events.registry_writes.iter().any(|r| r.contains("CLSID")));
        assert!(events.libraries.iter().any(|l| l.contains("iphlpapi")));
        assert!(events.resolved_apis.iter().any(|a| a == "GetAdaptersInfo"));
        assert!(caps.iter().any(|c| c.id == "file_drop"));
        assert!(caps.iter().any(|c| c.id == "exec"));
        assert!(caps.iter().any(|c| c.id == "script_exec"));
        assert!(caps.iter().any(|c| c.id == "persistence"));
        assert!(caps.iter().any(|c| c.id == "dyn_resolve"));
        assert!(caps.iter().any(|c| c.id == "process_enum"));
        assert!(caps.iter().any(|c| c.id == "http_client" || c.id == "socket_client"));
        let highs = events.highlights();
        assert!(highs.iter().any(|h| h.contains("comhost") || h.contains("iphlpapi")));
        // Strings table URL must not become a dyn IOC.
        assert!(!iocs.iter().any(|i| i.value.contains("not-a-real-call")));
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(map_speakeasy_json("not-json").is_err());
    }

    #[test]
    fn ignores_string_table_false_positives() {
        let json = r#"{
          "entry_points": [{"ep_type": "module_entry", "apis": []}],
          "strings": {
            "static": {
              "ansi": ["KERNEL32.CreateProcessA", "wininet.InternetOpenUrlA", "http://evil.example/gate"]
            }
          }
        }"#;
        let (events, caps, _, iocs) = map_speakeasy_json(json).unwrap();
        assert!(events.apis.is_empty());
        assert!(events.process_creates.is_empty());
        assert!(events.network.is_empty());
        assert!(caps.is_empty());
        assert!(iocs.is_empty());
    }
}
