# Vanguard-RE

High-speed, memory-safe static malware triage from the command line.

## Three Pillars

| Pillar | How |
|--------|-----|
| **Speed** | `memmap2` zero-copy I/O + focused static pipelines |
| **Accuracy** | Formal PE / ELF / Mach-O parsing (`goblin`), ImpHash, Shannon entropy, IAT heuristics, iced-x86 disassembly, crypto fingerprints, weak XOR recovery, network IOCs, toolchain fingerprinting |
| **Safety** | Rust memory safety + in-memory quarantine — samples are never executed on the host OS; optional Speakeasy emulation stages ephemeral non-executable bytes under `$TMPDIR` and runs only inside Docker `--network=none` |

## Architecture

```
┌──────────────────────────────────────────────────┐
│              Vanguard-RE CLI (vanguard)          │
└────────────────────────┬─────────────────────────┘
                         │
    ┌──────────┬─────────┼─────────┬──────────┐
    ▼          ▼         ▼         ▼          ▼
 Static    Disasm +   Signatures  Network   Crypto     Dynamic*
 Triage    Code       (hashes /   IOC       Constants  (Speakeasy
           Analysis   builtins)   Extractor Fingerprints in Docker)
```

\*Dynamic is optional and fail-closed: if Docker / the Speakeasy image is missing, the report continues static-only.

## What it extracts

| Layer | Signals |
|-------|---------|
| **Triage** | PE/ELF/Mach-O headers, ImpHash, entropy / packer hints, IAT threat score, capability tags |
| **Toolchain** | Source-language / compiler fingerprints (Go, Rust, .NET, MSVC via Rich header, GCC/MinGW, Delphi, VB6, Nim, AutoIt, PyInstaller) with the artifacts that matched; weak Delphi strings (`Borland`, …) are ignored on Raw blobs |
| **Signatures** | Lightweight builtin string/byte rules (no YARA-X / Wasmtime); Delphi section rule is gated on Delphi toolchain markers; WinINet dyn-resolve string rule requires `LoadLibrary`+`GetProcAddress` plus `InternetOpenUrl` or ≥4 WinINet names |
| **Network / C2** | Hardcoded IPv4 / IPv6 / `ip:port`, URLs, domains, `.onion` (+ DNS-resolve APIs) — scanned on every member and shown in the default report; emails / Bitcoin wallets also extracted; vendor schema noise is filtered |
| **Embedded archives** | Carves ZIP signatures from executable/resource bytes, decrypts members in memory, and recursively analyzes them with bomb limits |
| **Credential recovery** | Cracks encrypted embedded ZIPs by trying the sample's own plaintext strings as passwords (recovers WannaCry's `WNcry@2ol7`), then unlocks + analyzes the payload |
| **Possible secrets** | Heuristic password / API-key candidates; passwords need a nearby credential keyword (`password`, `login`, …) and only ≥75 print in the CLI |
| **Crypto** | AES / ChaCha20 / SHA / MD5 / Blowfish / PEM / Base64 / CryptoAPI imports via constant tables |
| **XOR recovery** | Deep-dive only: breaks short repeating XOR keys and reused keystreams via `C1⊕C2` cancel (“wave interference”); prints scheme, key, and recovered plaintext. Skips RTF/images/text; does **not** decrypt AES / `WANACRY!` / real ransomware crypto. `xor_loop` disasm hits raise confidence |
| **Strings** | Ranked ASCII + UTF-16LE extraction (not first-N file order), ransomware / C2 keyword filter, import DLLs |
| **Disassembly** | iced-x86 function recovery, interest ranking, k-means clusters, technique insights |
| **Code analysis** | Automated technique flags: PEB access, API hashing, XOR loops, stack strings, direct syscalls, indirect dispatch |
| **Dynamic (optional)** | Mandiant Speakeasy (Unicorn) inside Docker `--network=none` for up to **3** PE deep-dives (score ≥ 40, 45s each). Adds `dynamic:` evidence to caps / network IOCs (`dyn:` prefix). Never host-exec; no dropped files leave the container |

## Scoring & ranking

Threat scores come from IAT pattern matches and capability tags. Labels are built from **evidence that actually matched** — a high score never invents “injection / hollow” prose unless those APIs are present.

| Capability id | Meaning |
|---------------|---------|
| `injection` | Process injection / hollowing APIs (`VirtualAllocEx`, … — needs ≥2 hits; plain `VirtualAlloc` does not count) |
| `http_client` | WinINet / WinHTTP / URLDownload (IAT **or** exact name strings when dyn-resolve is present) |
| `socket_client` | Winsock / BSD sockets (needs ≥2 hits; `send` does not match `SendMessageA`) |
| `smb_enum` | Share / SMB discovery (`NetShareEnum`, …) |
| `c2_suspect` | Stronger HTTP combo (download-to-file or multi-API WinINet) |
| `persistence` | Services, run keys, tasks |
| `file_delete` / `file_drop` | Cleanup helpers and droppers |
| `exec` | Process-creation APIs (`CreateProcess`, `ShellExecute`, `system` / `exec*`, …) |
| `script_exec` | Shell/script/LOLBin **strings** (`powershell`, `cmd.exe`, `/bin/sh`, `rundll32`, …); confidence rises when an `exec` API is also present. Static only — does not prove the process ran |
| `crypto`, `anti_debug`, `keylog`, … | As matched |

Additional ranking rules:

- **DOS COM** still gets a useful floor score; generic **Raw** blobs no longer auto-score 35
- **Language packs** (`msg/m_*.wnry`, `.mui`, …), **non-PE `.wnry` resources** (`r.wnry`, configs — not `u.wnry`), and **source/build** (`.cpp`, `.tlog`, `.obj`, `.pdb`, …) are demoted so they cannot flood the ranking (skip with `--full`)
- **Content formats** beyond PE/ELF/Mach-O are classified by magic: ZIP, RTF, images (BMP/PNG/JPEG), printable text/config, and known encrypted headers (`WANACRY!`) — the banner shows a per-format mix instead of a opaque `other=` count
- **PE children of a high-score dropper** (score ≥ 70) get a floor of 40 so thin-IAT helpers like WannaCry `taskdl.exe` outrank demoted noise
- **.NET** samples with high toolchain confidence get a managed score floor (50+ at conf ≥ 90; higher with stealer/obfuscator/managed-net strings)
- **ELF / IoT bots** match IAT socket patterns when linked, and static/stripped loaders (Mirai `dlr.*`) get a string floor from markers like `MIRAI` / `GET /bins/mirai`
- Equal scores prefer PE/ELF/Mach-O/DOS over Raw so source trees cannot win a tie
- **`Ex` APIs are distinct** — `VirtualAlloc` does not match `VirtualAllocEx`; injection needs ≥2 corroborating APIs
- Ranking labels prefer including a network capability (`smb_enum` / `socket_client` / `http_client` / `c2_suspect`) when matched
- **Thin-IAT / delay-load** samples that already show `LoadLibrary`+`GetProcAddress` also get exact WinINet/WinHTTP API **name strings** folded into capability tagging (so `InternetOpenUrl` as a string can yield `http_client`)
- Deep-dives run by default on every executable and every scored member (disasm budget 32k insn); pass `--max-deep` only if you need to throttle huge archives
- **Delphi toolchain** weak string markers (`Borland`, …) are ignored on Raw/source blobs; PE/ELF/Mach-O still accept them

## Build & install

```bash
# Fast check while iterating
cargo check

# Rebuild release + install onto PATH (~/.local/bin)
# Also builds the Speakeasy Docker image when Docker is available
./install.sh

# Binary only (skip Docker image):
VANGUARD_SKIP_DOCKER=1 ./install.sh

# Or manually:
cargo build --release
cp target/release/vanguard ~/.local/bin/vanguard
docker build -t vanguard-speakeasy:latest ./docker/speakeasy
```

Builtin signature rules are a lightweight string/byte matcher. External `.yar` files are currently ignored with a note.

### Dynamic (optional): Speakeasy in Docker

Emulation is **not** sandbox detonation. Network is doubly blocked (Speakeasy fake net + Docker `--network=none`). Staging files are mode `0400`, never `+x`, wiped for their **full length** on Drop, and stale `$TMPDIR/vanguard-dyn-<pid>-<suffix>` trees are reaped on the next isolation probe. A hard kill (`SIGKILL`) of `vanguard` can skip Drop — leftover staging is owner-only (`0700`/`0400`) until the next run.

```bash
# Build the Speakeasy image (required once for dynamic; rebuild after entrypoint changes)
docker build -t vanguard-speakeasy:latest ./docker/speakeasy

# Record the local image id (shown in the CLI dynamic banner when ready)
docker image inspect --format '{{.Id}}' vanguard-speakeasy:latest

# Then the default command automatically emulates top PE deep-dives offline
vanguard sample.zip
```

The image runs Speakeasy with `all_entrypoints=True` (and `emulate_children`) so DLL exports are exercised — DllMain alone is often a no-op. The entrypoint applies a generic **lab Windows** profile (Win7-ish identity, `rundll32` host process, Explorer/services inventory, USB + Winlogon/MSNetMng registry seeds, decoy USB files, `modules_always_exist`) plus **API gap fillers with correct `argc`** for Speakeasy 1.5.x holes that abort entry points (notably `RegCreateKeyEx` / `RegSetValueEx`, resource-update APIs, ACL helpers). Remaining `unsupported_api` aborts surface in the report as `gap`. This is still an emulator fiction — useful for unlocking gated paths, not proof of real-world execution. The host mapper only trusts `entry_points[].apis[]` / `events[]` (plus entry-point errors) — Speakeasy’s static `strings` tables are ignored so they cannot fake dynamic caps.

| Env | Meaning |
|-----|---------|
| `VANGUARD_DYNAMIC=0` | Force-off dynamic (static-only) |
| `VANGUARD_SPEAKEASY_IMAGE=…` | Override image ref (default `vanguard-speakeasy:latest`). Prefer a digest pin: `vanguard-speakeasy@sha256:…` |

Pin / rebuild: Speakeasy **package** version is pinned in `docker/speakeasy/Dockerfile` (`speakeasy-emulator==…`). Rebuild after intentional upgrades. `./install.sh` prints the resolved image id after build. The CLI banner shows a short image id when isolation is ready so tag swap is visible.

**Leak checks (Fort Knox):** while emulating a sample that calls `InternetOpenUrl`, host `tcpdump`/firewall must see **zero** outbound from the container; `docker ps` must be clean after timeout kill; staging path must be gone after the run.

## Usage

```bash
vanguard <PATH>
```

Default report includes triage, ImpHash clusters, hardcoded C2/network IOCs (IPv4/IPv6, domains, URLs, onion + DNS APIs), and **deep-dives on every executable / scored member** (large disasm budget).

| Flag | Default | Meaning |
|------|---------|---------|
| `--password` / `-p` | `infected` | Password for encrypted ZIP archives |
| `--deep` / `--max-deep` | unlimited | Cap how many members get a deep-dive (default: no cap) |
| `--disasm-count` | `32768` | Max instructions to decode per deep-dive |
| `--min-deep-score` | `0` | Non-executables at/above this score are also deep-dived (executables always are) |
| `--full` | off | Keep language packs / source / raw noise in ranking **and** print full member lists + every triage block |
| `--color` | `auto` | ANSI colors in the report: `auto` (TTY + no `NO_COLOR`), `always`, or `never` |

Examples:

```bash
# Passworded malware ZIP (members stay in RAM)
vanguard /path/to/sample.zip -p infected

# Loose PE / ELF / Mach-O
vanguard /path/to/malware.exe --password ""

# Deeper disassembly budget on the top hit
vanguard /path/to/sample.zip --deep 1 --disasm-count 8000

# Noisy dump: no demotion + full member/triage listing
vanguard /path/to/sample.zip -p infected --full
```

Stdout prints a structured report: banner summary, ranking table, ImpHash clusters, then one merged block per interesting sample (identity + triage + deep-dive). Defaults hide score-0 rows, CRT import noise, language-pack string spam, and low-interest triage; use `--full` for the complete dump.

When weak XOR is recovered on a deep-dive, the sample block includes a named scheme plus key and plaintext:

```
  xor
    single-byte XOR 0x4b  conf=82  @0x1a00  span=128 B
      key    4b  "K"
      plain  "http://evil.example/gate..."
      note   IC L=1 (0.065); 94% printable
```

Passworded malware packs and ZIPs embedded inside binaries are decrypted into RAM only, then ranked, signature-scanned, and deep-dived — nothing is executed on the host OS.

## Containment

Two layers (see `containment_policy()`):

**Static quarantine (in-memory)**
- **No host exec** — sample bytes never run under the host OS loader
- Top-level and embedded ZIP members stay in process memory; never written as runnable files
- Recovered inner payloads (e.g. decrypted WannaCry `.wnry` files) are analyzed in RAM only
- Archive depth, member count, per-member/total bytes, central-directory scans, embedded-ZIP carves, and total sample count are capped; host files over 512 MiB are refused
- ZIP member reads are hard-bounded on actual decompression (not just declared sizes) to blunt zip bombs
- Path traversal / absolute / drive-style ZIP names are rejected; corpus walks do not follow symlinks

**Dynamic staging (ephemeral, optional)**
- Speakeasy may write `sample.bin` under `$TMPDIR/vanguard-dyn-<pid>-<suffix>/` (dir `0700`, file `0400`, never `+x`)
- Container flags include `--network=none`, `--cap-drop=ALL`, `no-new-privileges`, `--read-only`, `--ipc=private`, memory/CPU/pids/`nproc` limits, user `65534`, and a host wall-clock timeout (guest `VANGUARD_EMU_TIMEOUT` is set from Rust). UTS stays on Docker’s default private namespace (there is no valid `--uts=private` flag)
- Staging is wiped for its full length then unlinked on Drop; stale staging dirs matching the pid/suffix pattern are reaped on isolation probe
- Emulator drops never leave the container. If Docker/image is missing, dynamic is skipped (static-only)
- Trust the image: prefer `VANGUARD_SPEAKEASY_IMAGE=…@sha256:…`; the banner shows the resolved local image id

## License

MIT
