# Vanguard-RE

High-speed, memory-safe static malware triage — interactive TUI only.

## Three Pillars

| Pillar | How |
|--------|-----|
| **Speed** | `memmap2` zero-copy I/O + focused static pipelines |
| **Accuracy** | Formal PE / ELF / Mach-O parsing (`goblin`), ImpHash, Shannon entropy, IAT heuristics, iced-x86 disassembly, crypto fingerprints, network IOCs |
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
| **Signatures** | Lightweight builtin string/byte rules (no YARA-X / Wasmtime) |
| **Network IOCs** | Hardcoded IPv4 / `ip:port`, URLs, domains, `.onion`, emails — ranked by confidence; vendor/schema noise filtered |
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

Passworded malware packs (e.g. password `infected`) are decrypted into RAM only, then ranked, signature-scanned, and deep-dived in the UI.

### Deep-dive panels

| Panel | Contents |
|-------|----------|
| **Sample** | Name, format / arch / size, hashes, packer hints |
| **Threat signals** | Risk + capability gauges, behaviors, sigs, crypto |
| **Interesting strings** | Ranked analyst-useful strings and imported DLLs |
| **Network IOCs** | C2 candidates (domains, IPs, URLs, onion) |
| **Entry disassembly** | Highlighted listing + detected `techniques` |
| **Function map** (`d`) | Interest-sorted functions, clusters, follow-call |

### Keys

| Key | Action |
|-----|--------|
| ↑↓ / j k | Move / step instructions |
| g / G / Home / End | Jump top / bottom |
| Enter | Select / run / deep-dive / follow call |
| Tab | Next form field / switch disasm pane |
| d | Open function-map disasm explorer |
| [ ] | Previous / next recovered function |
| c | Cycle k-means function cluster filter |
| u / Backspace | Back after follow-call (or leave explorer) |
| b | Back to ranking (from deep-dive) |
| Esc / q | Back / quit |

## Containment

- **Static-only** — nothing is executed on the host
- ZIP members stay in process memory; never written as runnable files
- Dynamic analysis (if added later) would use a real microVM, not host exec

## License

MIT
