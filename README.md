# Vanguard-RE

High-speed, memory-safe static malware triage — interactive TUI only.

## Three Pillars

| Pillar | How |
|--------|-----|
| **Speed** | `memmap2` zero-copy I/O + focused static pipelines |
| **Accuracy** | Formal PE / ELF / Mach-O parsing (`goblin`), ImpHash, Shannon entropy, IAT heuristics, iced-x86 disassembly, crypto fingerprints, network IOCs, toolchain fingerprinting |
| **Safety** | Rust memory safety + in-memory quarantine — samples are never executed |

## Architecture

```
┌──────────────────────────────────────────────────┐
│              Vanguard-RE TUI (ratatui)            │
└────────────────────────┬─────────────────────────┘
                         │
    ┌──────────┬─────────┼─────────┬──────────┐
    ▼          ▼         ▼         ▼          ▼
 Static    Disasm +   Signatures  Network   Crypto
 Triage    Code       (hashes /   IOC       Constants
           Analysis   builtins)   Extractor Fingerprints
```

## What it extracts

| Layer | Signals |
|-------|---------|
| **Triage** | PE/ELF/Mach-O headers, ImpHash, entropy / packer hints, IAT threat score, capability tags |
| **Toolchain** | Source-language / compiler fingerprints (Go, Rust, .NET, MSVC via Rich header, GCC/MinGW, Delphi, VB6, Nim, AutoIt, PyInstaller) with the artifacts that matched |
| **Signatures** | Lightweight builtin string/byte rules (no YARA-X / Wasmtime) |
| **Network IOCs** | Hardcoded IPv4 / `ip:port`, URLs, domains, `.onion`, emails, checksum-validated Bitcoin wallets — ranked by confidence |
| **Embedded archives** | Carves ZIP signatures from executable/resource bytes, decrypts members in memory, and recursively analyzes them with bomb limits |
| **Credential recovery** | Cracks encrypted embedded ZIPs by trying the sample's own plaintext strings as passwords (recovers WannaCry's `WNcry@2ol7`), then unlocks + analyzes the payload |
| **Possible secrets** | Heuristic password / API-key candidates ranked by character-class mix, entropy band, and word-stem shape (lead generator, not proof) |
| **Crypto** | AES / ChaCha20 / SHA / MD5 / Blowfish / PEM / Base64 / CryptoAPI imports via constant tables |
| **Strings** | Ranked ASCII + UTF-16LE extraction (not first-N file order), ransomware / C2 keyword filter, import DLLs |
| **Disassembly** | iced-x86 with syntax highlighting, function recovery, interest ranking, k-means clusters |
| **Code analysis** | Automated technique flags: PEB access, API hashing, XOR loops, stack strings, direct syscalls, indirect dispatch |

## Build & install

```bash
# Fast check while iterating
cargo check

cargo build --release
cp target/release/vanguard ~/.local/bin/vanguard
```

Builtin signature rules are a lightweight string/byte matcher. External `.yar` files are currently ignored with a note.

## Usage

```bash
vanguard
```

Menu → **Investigate sample / ZIP** → paste path, set password if needed → Run.

Passworded malware packs (e.g. password `infected`) and ZIPs embedded inside binaries are decrypted into RAM only, then ranked, signature-scanned, and deep-dived in the UI.

### Deep-dive panels

| Panel | Contents |
|-------|----------|
| **Sample** | Name, format / arch / size, estimated OS + header evidence, hashes, packer hints, source language + artifacts |
| **Threat signals** | Risk + capability gauges, behaviors, sigs, crypto, techniques |
| **Findings tab** | Ranked analyst-useful strings and network IOCs |
| **Imports & dependencies tab** | DLLs, shared libraries, dylibs, and imported functions parsed from the binary |
| **Network IOCs** | C2 candidates (domains, IPs, URLs, onion, Bitcoin wallets), merged from decrypted embedded members |
| **Possible secrets** | Heuristic password / key candidates (verify manually) |
| **Embedded archives** | ZIPs carved from sample bytes; member listing, encrypted-payload flag, and any recovered password |
| **Function map** (`d`) | Interest-sorted functions, clusters, follow-call (disassembly lives here) |

### Keys

| Key | Action |
|-----|--------|
| ↑↓ / j k | Move / step instructions |
| g / G / Home / End | Jump top / bottom |
| Enter | Select / run / deep-dive / follow call |
| Tab | Next form field / switch deep-dive tab / switch disasm pane |
| d | Open function-map disasm explorer |
| [ ] | Previous / next recovered function |
| c | Cycle k-means function cluster filter |
| u / Backspace | Back after follow-call (or leave explorer) |
| b | Back to ranking (from deep-dive) |
| Esc / q | Back / quit |

## Containment

- **Static-only** — nothing is executed on the host
- Top-level and embedded ZIP members stay in process memory; never written as runnable files
- Recovered inner payloads (e.g. decrypted WannaCry `.wnry` files) are analyzed in RAM only, never dropped to disk as runnable files
- Recursive archive depth, member count, per-member size, and total extraction are bounded
- Dynamic analysis (if added later) would use a real microVM, not host exec

## License

MIT
