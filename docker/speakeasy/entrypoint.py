#!/usr/bin/env python3
"""Fort Knox Speakeasy entrypoint.

Reads /work/sample.bin, emulates with Speakeasy, prints JSON report to stdout.
Never contacts the network (Docker --network=none + Speakeasy fake net).
Never writes dropped files or memory dumps to a host-visible path.

Coverage notes:
- Runs all DLL exports (`all_entrypoints=True`) — DllMain alone is often a no-op.
- Registers stubs for APIs Speakeasy 1.5.x leaves unimplemented so samples can
  continue past early exits (e.g. SetFileAttributesA, InitializeAcl).
- Applies a generic “lab Windows” profile: Win7-ish identity, rundll32 host
  process, Explorer/services inventory, USB + Fanny-oriented registry/FS seeds,
  and modules_always_exist so LoadLibrary of uncommon DLLs does not abort.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import traceback

SAMPLE = os.environ.get("VANGUARD_SAMPLE", "/work/sample.bin")
TIMEOUT = int(os.environ.get("VANGUARD_EMU_TIMEOUT", "40"))

# Predefined HKEY_* constants (Win32).
_HKEY_NAMES = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0x80000005: "HKEY_CURRENT_CONFIG",
}


def _make_ret(retval: object):
    """Speakeasy user hook: cb(emu, api_name, orig, argv) -> retval."""

    def _hook(_emu, _api_name, _orig, _argv):
        return retval

    return _hook


def _is_wide(api_name: str) -> bool:
    return api_name.lower().endswith("w")


def _read_str(emu, addr, wide: bool) -> str:
    if not addr:
        return ""
    try:
        return emu.read_mem_string(addr, 2 if wide else 1) or ""
    except Exception:
        return ""


def _write_ptr(emu, addr, value: int) -> None:
    if not addr:
        return
    try:
        ptr = emu.get_ptr_size()
        emu.mem_write(addr, int(value).to_bytes(ptr, "little"))
    except Exception:
        pass


def _write_u32(emu, addr, value: int) -> None:
    if not addr:
        return
    try:
        emu.mem_write(addr, int(value).to_bytes(4, "little"))
    except Exception:
        pass


def _reg_path(emu, api_name: str, hkey, subkey_addr) -> str:
    """Build a full registry path from HKEY handle + optional subkey string."""
    wide = _is_wide(api_name)
    sub = _read_str(emu, subkey_addr, wide)
    root = _HKEY_NAMES.get(int(hkey) & 0xFFFFFFFF)
    if root is None:
        # Already an open key handle — try path lookup.
        try:
            key = emu.reg_get_key(handle=hkey)
            if key is not None and hasattr(key, "get_path"):
                root = key.get_path()
        except Exception:
            root = None
    if not root:
        root = "HKEY_LOCAL_MACHINE"
    if not sub:
        return root
    if sub.startswith("\\"):
        return root + sub
    return root + "\\" + sub


def _hook_reg_create_key_ex(emu, api_name, _orig, argv):
    """Fill Speakeasy gap: RegCreateKeyExA/W (native only has RegCreateKey)."""
    # hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSec, phkResult, lpdwDisposition
    while len(argv) < 9:
        argv.append(0)
    hkey, subkey, _reserved, _cls, _opt, _sam, _sec, phk_result, lpdw_disp = argv[:9]
    path = _reg_path(emu, api_name, hkey, subkey)
    hnd = 0
    try:
        hnd = emu.reg_open_key(path, create=True) or 0
        if not hnd:
            emu.reg_create_key(path)
            hnd = emu.reg_open_key(path, create=True) or 0
    except Exception:
        hnd = 0
    if not hnd:
        hnd = 0xC0FFEE00  # decoy handle so callers can continue
    _write_ptr(emu, phk_result, hnd)
    _write_u32(emu, lpdw_disp, 1)  # REG_CREATED_NEW_KEY
    if len(argv) > 1:
        argv[1] = path  # improve report arg display when Speakeasy logs it
    return 0  # ERROR_SUCCESS


def _hook_reg_set_value_ex(emu, api_name, _orig, argv):
    """Fill Speakeasy gap: RegSetValueExA/W (not implemented in 1.5.11)."""
    # hKey, lpValueName, Reserved, dwType, lpData, cbData
    while len(argv) < 6:
        argv.append(0)
    hkey, name_addr, _reserved, dw_type, lp_data, cb_data = argv[:6]
    wide = _is_wide(api_name)
    value_name = _read_str(emu, name_addr, wide) or "(default)"
    path = ""
    try:
        key = emu.reg_get_key(handle=hkey)
        if key is not None and hasattr(key, "get_path"):
            path = key.get_path()
    except Exception:
        path = ""
    # Best-effort write into emulated registry when data looks like a string.
    if path and lp_data and cb_data and int(dw_type) in (1, 2):  # REG_SZ / REG_EXPAND_SZ
        try:
            data = _read_str(emu, lp_data, wide)
            if data and hasattr(emu, "reg_write"):
                emu.reg_write(path, value_name, data)
        except Exception:
            pass
    if len(argv) > 1:
        argv[1] = f"{path}\\{value_name}" if path else value_name
    return 0


def _hook_reg_delete_value(emu, api_name, _orig, argv):
    while len(argv) < 2:
        argv.append(0)
    _hkey, name_addr = argv[:2]
    argv[1] = _read_str(emu, name_addr, _is_wide(api_name)) or argv[1]
    return 0


def _hook_strncat(emu, _api_name, _orig, argv):
    """Speakeasy ships strncat_s but not strncat — implement real concat."""
    while len(argv) < 3:
        argv.append(0)
    dest, src, count = argv[:3]
    if not dest:
        return 0
    try:
        dst = emu.read_mem_string(dest, 1) if dest else ""
        src_s = emu.read_mem_string(src, 1) if src else ""
        n = int(count)
        if n >= 0:
            src_s = src_s[:n]
        emu.write_mem_string(dst + src_s, dest, width=1)
    except Exception:
        pass
    return dest


def _hook_rtl_pc_to_file_header(emu, _api_name, _orig, argv):
    """PVOID RtlPcToFileHeader(PVOID PcValue, PVOID *BaseOfImage) — common UCRT gap."""
    while len(argv) < 2:
        argv.append(0)
    pc, base_out = argv[0], argv[1]
    base = 0
    try:
        mods = []
        if hasattr(emu, "get_user_modules"):
            mods = list(emu.get_user_modules() or [])
        for mod in mods:
            try:
                mbase = int(getattr(mod, "get_base", lambda: 0)() or getattr(mod, "base", 0) or 0)
                msize = int(getattr(mod, "get_size", lambda: 0)() or getattr(mod, "size", 0) or 0)
                if mbase and msize and mbase <= int(pc) < mbase + msize:
                    base = mbase
                    break
            except Exception:
                continue
    except Exception:
        pass
    if not base and pc:
        # Best-effort PE-style align; unblocks MSVC CRT init on x64 samples.
        base = int(pc) & ~0xFFFF
    _write_ptr(emu, base_out, base)
    return base


# Only fill APIs Speakeasy 1.5.11 does NOT implement.
# Overriding real handlers (DeleteFile, LoadLibrary, strncat_s, …) corrupts paths.
# (module, api_name, retval_or_cb, argc)
API_STUBS = [
    # Registry gaps (Fanny died on RegCreateKeyExA before these existed)
    ("advapi32", "RegCreateKeyExA", _hook_reg_create_key_ex, 9),
    ("advapi32", "RegCreateKeyExW", _hook_reg_create_key_ex, 9),
    ("advapi32", "RegSetValueExA", _hook_reg_set_value_ex, 6),
    ("advapi32", "RegSetValueExW", _hook_reg_set_value_ex, 6),
    ("advapi32", "RegDeleteValueA", _hook_reg_delete_value, 2),
    ("advapi32", "RegDeleteValueW", _hook_reg_delete_value, 2),
    # File / resource gaps
    ("kernel32", "SetFileAttributesA", 1, 2),
    ("kernel32", "SetFileAttributesW", 1, 2),
    ("kernel32", "RemoveDirectoryA", 1, 1),
    ("kernel32", "RemoveDirectoryW", 1, 1),
    ("kernel32", "MoveFileA", 1, 2),
    ("kernel32", "MoveFileW", 1, 2),
    ("kernel32", "MoveFileExA", 1, 3),
    ("kernel32", "MoveFileExW", 1, 3),
    ("kernel32", "GetDiskFreeSpaceA", 1, 5),
    ("kernel32", "GetDiskFreeSpaceW", 1, 5),
    ("kernel32", "BeginUpdateResourceA", 0x1000, 2),
    ("kernel32", "BeginUpdateResourceW", 0x1000, 2),
    ("kernel32", "UpdateResourceA", 1, 6),
    ("kernel32", "UpdateResourceW", 1, 6),
    ("kernel32", "EndUpdateResourceA", 1, 2),
    ("kernel32", "EndUpdateResourceW", 1, 2),
    # CRT: strncat missing (only strncat_s exists)
    ("msvcrt", "strncat", _hook_strncat, 3),
    ("msvcrt", "_strncat", _hook_strncat, 3),
    ("msvcrt", "_abnormal_termination", 0, 0),
    # UI gap
    ("user32", "SetPropA", 1, 3),
    ("user32", "SetPropW", 1, 3),
    # ACL / security descriptor gaps
    ("advapi32", "InitializeAcl", 1, 3),
    ("advapi32", "InitializeSecurityDescriptor", 1, 2),
    ("advapi32", "SetSecurityDescriptorDacl", 1, 4),
    ("advapi32", "SetSecurityDescriptorGroup", 1, 3),
    ("advapi32", "SetSecurityDescriptorOwner", 1, 3),
    ("advapi32", "AddAccessAllowedAce", 1, 4),
    ("advapi32", "AccessCheck", 1, 8),
    ("advapi32", "IsValidSid", 1, 1),
    ("iphlpapi", "GetAdaptersAddresses", 0, 5),
    # UCRT / ntdll — GreenBug-family x64 dies here during CRT init.
    # Speakeasy may present this as ntdll or an api-ms-win-core-rtlsupport* forwarder.
    ("ntdll", "RtlPcToFileHeader", _hook_rtl_pc_to_file_header, 2),
    ("ntdll.dll", "RtlPcToFileHeader", _hook_rtl_pc_to_file_header, 2),
    (
        "api-ms-win-core-rtlsupport-l1-1-0",
        "RtlPcToFileHeader",
        _hook_rtl_pc_to_file_header,
        2,
    ),
    ("*", "RtlPcToFileHeader", _hook_rtl_pc_to_file_header, 2),
]


def _register_stubs(se) -> None:
    for module, api_name, retval_or_cb, argc in API_STUBS:
        cb = retval_or_cb if callable(retval_or_cb) else _make_ret(retval_or_cb)
        try:
            se.add_api_hook(cb, module=module, api_name=api_name, argc=argc)
        except Exception:
            pass


def _collect_unsupported(report_obj: dict) -> list[str]:
    out: list[str] = []
    for ep in report_obj.get("entry_points") or []:
        if not isinstance(ep, dict):
            continue
        err = ep.get("error") or {}
        if not isinstance(err, dict):
            continue
        if err.get("type") == "unsupported_api":
            name = err.get("api_name") or ""
            if name:
                out.append(str(name))
    # dedupe preserve order
    seen = set()
    uniq = []
    for n in out:
        k = n.lower()
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    return uniq


def _upsert_reg_key(keys: list, path: str, values: list) -> None:
    for k in keys:
        if isinstance(k, dict) and k.get("path") == path:
            existing = {v.get("name") for v in (k.get("values") or []) if isinstance(v, dict)}
            merged = list(k.get("values") or [])
            for v in values:
                if v.get("name") not in existing:
                    merged.append(v)
            k["values"] = merged
            return
    keys.append({"path": path, "values": values})


def _ensure_lab_processes(procs: list) -> list:
    """Keep Speakeasy defaults, ensure Explorer/svchost exist, host as rundll32."""
    by_name = {}
    for p in procs:
        if isinstance(p, dict) and p.get("name"):
            by_name[p["name"].lower()] = p

    extras = [
        {
            "name": "explorer",
            "base_addr": "0x05570000",
            "pid": 1200,
            "path": "C:\\Windows\\explorer.exe",
            "command_line": "C:\\Windows\\Explorer.EXE",
            "is_main_exe": False,
            "session": 1,
        },
        {
            "name": "svchost",
            "base_addr": "0x05560000",
            "pid": 800,
            "path": "C:\\Windows\\system32\\svchost.exe",
            "command_line": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
            "is_main_exe": False,
            "session": 0,
        },
        {
            "name": "winlogon",
            "base_addr": "0x05550000",
            "pid": 600,
            "path": "C:\\Windows\\system32\\winlogon.exe",
            "is_main_exe": False,
            "session": 1,
        },
        {
            "name": "services",
            "base_addr": "0x05530000",
            "pid": 500,
            "path": "C:\\Windows\\system32\\services.exe",
            "is_main_exe": False,
            "session": 0,
        },
        {
            "name": "lsass",
            "base_addr": "0x05540000",
            "pid": 520,
            "path": "C:\\Windows\\system32\\lsass.exe",
            "is_main_exe": False,
            "session": 0,
        },
    ]
    for e in extras:
        key = e["name"].lower()
        if key not in by_name:
            procs.append(e)
            by_name[key] = e

    # Host process: DLL samples are typically loaded via rundll32.
    main = by_name.get("main")
    rundll_cmd = "C:\\Windows\\system32\\rundll32.exe C:\\Windows\\system32\\sample.dll,#1"
    if main is None:
        procs.append(
            {
                "name": "main",
                "base_addr": "0x00400000",
                "pid": 1337,
                "path": "C:\\Windows\\system32\\rundll32.exe",
                "command_line": rundll_cmd,
                "is_main_exe": True,
                "session": 1,
            }
        )
    else:
        main["path"] = "C:\\Windows\\system32\\rundll32.exe"
        main["command_line"] = rundll_cmd
        main["is_main_exe"] = True
        main.setdefault("session", 1)
        main.setdefault("pid", 1337)
        # Clear other is_main_exe flags.
        for p in procs:
            if isinstance(p, dict) and p is not main:
                p["is_main_exe"] = False
    return procs


def enrich_config(cfg: dict) -> dict:
    """Overlay a generic lab Windows environment on Speakeasy defaults."""
    cfg = copy.deepcopy(cfg)
    cfg["description"] = "Vanguard Fort Knox lab Windows profile"
    cfg["timeout"] = TIMEOUT
    cfg["max_api_count"] = max(int(cfg.get("max_api_count") or 10000), 50000)

    # Win7 SP1-ish — matches Speakeasy default; keep explicit for clarity.
    cfg["os_ver"] = {
        "name": "windows",
        "major": 6,
        "minor": 1,
        "build": 7601,
    }
    cfg["current_dir"] = "C:\\Windows\\system32"
    # Always override — defaults use svchost which is wrong for DLL droppers.
    cfg["command_line"] = (
        "C:\\Windows\\system32\\rundll32.exe C:\\Windows\\system32\\sample.dll,#1"
    )
    cfg["hostname"] = "WIN7-LAB"
    cfg["domain"] = "WORKGROUP"
    cfg["user"] = {
        "name": "analyst",
        "is_admin": True,
        "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001",
    }
    env = dict(cfg.get("env") or {})
    env.update(
        {
            "comspec": "C:\\Windows\\system32\\cmd.exe",
            "systemroot": "C:\\Windows",
            "windir": "C:\\Windows",
            "temp": "C:\\Users\\analyst\\AppData\\Local\\Temp",
            "tmp": "C:\\Users\\analyst\\AppData\\Local\\Temp",
            "userprofile": "C:\\Users\\analyst",
            "systemdrive": "C:",
            "allusersprofile": "C:\\ProgramData",
            "programfiles": "C:\\Program Files",
            "username": "analyst",
            "computername": "WIN7-LAB",
            "userdomain": "WORKGROUP",
            "path": (
                "C:\\Windows\\system32;C:\\Windows;"
                "C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
            ),
        }
    )
    cfg["env"] = env

    # Drives: keep defaults; ensure removable F: and fixed C:.
    drives = list(cfg.get("drives") or [])
    types = {d.get("root_path", "").upper(): d for d in drives if isinstance(d, dict)}
    if "F:\\" not in types:
        drives.append(
            {
                "root_path": "F:\\",
                "drive_type": "DRIVE_REMOVABLE",
                "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-1000000000f1}\\",
            }
        )
    if "C:\\" not in types:
        drives.insert(
            0,
            {
                "root_path": "C:\\",
                "drive_type": "DRIVE_FIXED",
                "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000001}\\",
            },
        )
    cfg["drives"] = drives

    cfg["processes"] = _ensure_lab_processes(list(cfg.get("processes") or []))

    # Modules: synthesize missing DLLs so dyn-resolve paths continue.
    modules = dict(cfg.get("modules") or {})
    modules["modules_always_exist"] = True
    # Keep functions_always_exist false — inventing every export is too noisy/fake.
    modules["functions_always_exist"] = False
    cfg["modules"] = modules

    # Network adapter with a non-loopback LAN IP (identity / GetAdaptersInfo paths).
    network = dict(cfg.get("network") or {})
    adapters = list(network.get("adapters") or [])
    if not adapters:
        adapters = [
            {
                "name": "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
                "description": "Intel(R) PRO/1000 MT Network Connection",
                "mac_address": "00-0C-29-12-34-56",
                "type": "ethernet",
                "ip_address": "192.168.56.101",
                "subnet_mask": "255.255.255.0",
                "dhcp_enabled": True,
            }
        ]
    else:
        # Prefer a LAN address over 127.0.0.1 for samples that reject loopback.
        for a in adapters:
            if isinstance(a, dict) and a.get("ip_address") in (None, "", "127.0.0.1"):
                a["ip_address"] = "192.168.56.101"
                a["subnet_mask"] = a.get("subnet_mask") or "255.255.255.0"
    network["adapters"] = adapters
    dns = dict(network.get("dns") or {})
    names = dict(dns.get("names") or {})
    names.setdefault("default", "192.168.56.1")
    dns["names"] = names
    network["dns"] = dns
    cfg["network"] = network

    # Registry seeds — USB worm + Fanny string targets.
    reg = dict(cfg.get("registry") or {})
    keys = list(reg.get("keys") or [])
    _upsert_reg_key(
        keys,
        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\USBSTOR\\Enum",
        [
            {"name": "Count", "type": "REG_DWORD", "data": "0x00000001"},
            {
                "name": "0",
                "type": "REG_SZ",
                "data": "USB\\VID_0781&PID_5151\\1234567890ABCDEF",
            },
            {"name": "NextInstance", "type": "REG_DWORD", "data": "0x00000001"},
        ],
    )
    _upsert_reg_key(
        keys,
        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\PartMgr\\Enum",
        [
            {"name": "Count", "type": "REG_DWORD", "data": "0x00000001"},
            {
                "name": "0",
                "type": "REG_SZ",
                "data": "IDE\\DiskSanDisk_Cruzer_______\\1",
            },
        ],
    )
    _upsert_reg_key(
        keys,
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion",
        [
            {"name": "ProductName", "type": "REG_SZ", "data": "Windows 7 Professional"},
            {"name": "CurrentVersion", "type": "REG_SZ", "data": "6.1"},
            {"name": "CurrentBuildNumber", "type": "REG_SZ", "data": "7601"},
            {"name": "CSDVersion", "type": "REG_SZ", "data": "Service Pack 1"},
            {
                "name": "SystemRoot",
                "type": "REG_SZ",
                "data": "C:\\Windows",
            },
        ],
    )
    _upsert_reg_key(
        keys,
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        [
            {
                "name": "Shell",
                "type": "REG_SZ",
                "data": "explorer.exe",
            },
            {
                "name": "Userinit",
                "type": "REG_SZ",
                "data": "C:\\Windows\\system32\\userinit.exe,",
            },
        ],
    )
    _upsert_reg_key(
        keys,
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\MSNetMng",
        [
            {"name": "Installed", "type": "REG_DWORD", "data": "0x00000000"},
        ],
    )
    _upsert_reg_key(
        keys,
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        [],
    )
    reg["keys"] = keys
    cfg["registry"] = reg

    # Filesystem decoys (USB / optical / restore / system32 names Fanny searches).
    fs = dict(cfg.get("filesystem") or {})
    files = list(fs.get("files") or [])
    decoys = [
        {
            "mode": "full_path",
            "emu_path": "d:\\fanny.bmp",
            "byte_fill": {"byte": "0x42", "size": 64},
        },
        {
            "mode": "full_path",
            "emu_path": "f:\\autorun.inf",
            "byte_fill": {"byte": "0x41", "size": 64},
        },
        {
            "mode": "full_path",
            "emu_path": "f:\\fanny.bmp",
            "byte_fill": {"byte": "0x42", "size": 128},
        },
        {
            "mode": "full_path",
            "emu_path": "f:\\restore\\tmp.bin",
            "byte_fill": {"byte": "0x00", "size": 16},
        },
        {
            "mode": "full_path",
            "emu_path": "c:\\windows\\system32\\drivers\\null.sys",
            "byte_fill": {"byte": "0x4d", "size": 64},
        },
        {
            "mode": "full_path",
            "emu_path": "c:\\windows\\explorer.exe",
            "byte_fill": {"byte": "0x4d", "size": 256},
        },
    ]
    existing_paths = {
        f.get("emu_path", "").lower() for f in files if isinstance(f, dict)
    }
    for d in decoys:
        if d["emu_path"].lower() not in existing_paths:
            files.append(d)
    fs["files"] = files
    cfg["filesystem"] = fs
    return cfg


def main() -> int:
    if not os.path.isfile(SAMPLE):
        print(json.dumps({"error": f"sample missing: {SAMPLE}"}), file=sys.stderr)
        return 2

    mode = os.stat(SAMPLE).st_mode
    if mode & 0o111:
        print(json.dumps({"error": "sample has execute bits — refusing"}), file=sys.stderr)
        return 3

    try:
        import speakeasy
    except Exception as exc:  # pragma: no cover
        print(json.dumps({"error": f"speakeasy import failed: {exc}"}), file=sys.stderr)
        return 4

    try:
        os.chdir("/tmp")
    except OSError:
        pass

    try:
        base_cfg = dict(speakeasy.Speakeasy().config)
        cfg = enrich_config(base_cfg)
        se = speakeasy.Speakeasy(config=cfg)

        if hasattr(se, "set_timeout"):
            try:
                se.set_timeout(TIMEOUT)
            except Exception:
                pass

        _register_stubs(se)

        module = se.load_module(SAMPLE)
        try:
            se.run_module(module, all_entrypoints=True, emulate_children=True)
        except TypeError:
            try:
                se.run_module(module, all_entrypoints=True)
            except TypeError:
                se.run_module(module)

        report = None
        if hasattr(se, "get_json_report"):
            report = se.get_json_report()
        elif hasattr(se, "get_report"):
            raw = se.get_report()
            if isinstance(raw, str):
                report = raw
            elif hasattr(raw, "model_dump_json"):
                report = raw.model_dump_json()
            elif hasattr(raw, "dict"):
                report = json.dumps(raw.dict())
            else:
                report = json.dumps(raw, default=str)
        else:
            report = json.dumps({"error": "no report API on Speakeasy object"})

        # Normalize to object, attach gap telemetry for the host mapper.
        if isinstance(report, str):
            try:
                report_obj = json.loads(report.strip())
            except json.JSONDecodeError:
                sys.stdout.write(json.dumps({"raw_report": report.strip()}))
                sys.stdout.write("\n")
                return 0
        else:
            report_obj = report if isinstance(report, dict) else {"raw_report": report}

        unsupported = _collect_unsupported(report_obj)
        report_obj["vanguard"] = {
            "lab_profile": True,
            "unsupported_apis": unsupported,
        }

        try:
            if hasattr(se, "shutdown"):
                se.shutdown()
        except Exception:
            pass

        sys.stdout.write(json.dumps(report_obj, default=str))
        sys.stdout.write("\n")
        return 0
    except Exception as exc:
        err = {
            "error": str(exc),
            "traceback": traceback.format_exc()[-2000:],
        }
        print(json.dumps(err), file=sys.stderr)
        sys.stdout.write(json.dumps({"error": str(exc), "entry_points": []}))
        sys.stdout.write("\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
