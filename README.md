# Vanguard-RE

High-speed, memory-safe static malware triage from the command line.

## Three Pillars

| Pillar | How |
|--------|-----|
| **Speed** | `memmap2` zero-copy I/O + focused static pipelines |
| **Accuracy** | Formal PE / ELF / Mach-O parsing (`goblin`), ImpHash, Shannon entropy, IAT heuristics, iced-x86 disassembly, crypto fingerprints, network IOCs, toolchain fingerprinting |
| **Safety** | Rust memory safety + in-memory quarantine — samples are never executed |

## Architecture

```
┌──────────────────────────────────────────────────┐
│              Vanguard-RE CLI (vanguard)          │
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
| **Disassembly** | iced-x86 function recovery, interest ranking, k-means clusters, technique insights |
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
vanguard <PATH> [--password infected] [--deep 3] [--disasm-count 4000] [--min-deep-score 70]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--password` / `-p` | `infected` | Password for encrypted ZIP archives |
| `--deep` | `3` | Number of top-scoring samples to deep-dive |
| `--disasm-count` | `4000` | Max instructions to decode per deep-dive |
| `--min-deep-score` | `70` | Minimum triage score required for a deep-dive |

Examples:

```bash
# Passworded malware ZIP (members stay in RAM)
vanguard /path/to/sample.zip -p infected

# Loose PE / ELF / Mach-O
vanguard /path/to/malware.exe --password ""

# Deeper disassembly budget on the top hit
vanguard /path/to/sample.zip --deep 1 --disasm-count 8000
```

Stdout reports ranking, ImpHash clusters, PE/ELF triage, then deep-dive sections (YARA, network IOCs, crypto, secrets, imports, strings, disasm insights).

Passworded malware packs and ZIPs embedded inside binaries are decrypted into RAM only, then ranked, signature-scanned, and deep-dived — nothing is executed.

## Containment

- **Static-only** — nothing is executed on the host
- Top-level and embedded ZIP members stay in process memory; never written as runnable files
- Recovered inner payloads (e.g. decrypted WannaCry `.wnry` files) are analyzed in RAM only, never dropped to disk as runnable files
- Recursive archive depth, member count, per-member size, and total extraction are bounded
- Dynamic analysis (if added later) would use a real microVM, not host exec

## License

MIT
