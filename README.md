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
| **Toolchain** | Source-language / compiler fingerprints (Go, Rust, .NET, MSVC via Rich header, GCC/MinGW, Delphi, VB6, Nim, AutoIt, PyInstaller) with the artifacts that matched; weak Delphi strings (`Borland`, …) are ignored on Raw blobs |
| **Signatures** | Lightweight builtin string/byte rules (no YARA-X / Wasmtime); Delphi section rule is gated on Delphi toolchain markers |
| **Network IOCs** | Hardcoded IPv4 / `ip:port`, URLs, domains, `.onion`, emails, checksum-validated Bitcoin wallets — ranked by confidence; vendor schema / truncated-host noise is filtered |
| **Embedded archives** | Carves ZIP signatures from executable/resource bytes, decrypts members in memory, and recursively analyzes them with bomb limits |
| **Credential recovery** | Cracks encrypted embedded ZIPs by trying the sample's own plaintext strings as passwords (recovers WannaCry's `WNcry@2ol7`), then unlocks + analyzes the payload |
| **Possible secrets** | Heuristic password / API-key candidates ranked by character-class mix, entropy band, and word-stem shape (lead generator, not proof) |
| **Crypto** | AES / ChaCha20 / SHA / MD5 / Blowfish / PEM / Base64 / CryptoAPI imports via constant tables |
| **Strings** | Ranked ASCII + UTF-16LE extraction (not first-N file order), ransomware / C2 keyword filter, import DLLs |
| **Disassembly** | iced-x86 function recovery, interest ranking, k-means clusters, technique insights |
| **Code analysis** | Automated technique flags: PEB access, API hashing, XOR loops, stack strings, direct syscalls, indirect dispatch |

## Scoring & ranking

Threat scores come from IAT pattern matches and capability tags. Labels are built from **evidence that actually matched** — a high score never invents “injection / hollow” prose unless those APIs are present.

| Capability id | Meaning |
|---------------|---------|
| `injection` | Process injection / hollowing APIs (`VirtualAllocEx`, … — needs ≥2 hits; plain `VirtualAlloc` does not count) |
| `http_client` | WinINet / WinHTTP / URLDownload |
| `socket_client` | Winsock / BSD sockets (needs ≥2 hits; `send` does not match `SendMessageA`) |
| `smb_enum` | Share / SMB discovery (`NetShareEnum`, …) |
| `c2_suspect` | Stronger HTTP combo (download-to-file or multi-API WinINet) |
| `persistence` | Services, run keys, tasks |
| `file_delete` / `file_drop` | Cleanup helpers and droppers |
| `crypto`, `anti_debug`, `keylog`, … | As matched |

Additional ranking rules:

- **DOS COM** still gets a useful floor score; generic **Raw** blobs no longer auto-score 35
- **Language packs** (`msg/m_*.wnry`, `.mui`, …), **non-PE `.wnry` resources** (`r.wnry`, configs — not `u.wnry`), and **source/build** (`.cpp`, `.tlog`, `.obj`, `.pdb`, …) are demoted so they cannot flood the ranking (skip with `--full`)
- **PE children of a high-score dropper** (score ≥ 70) get a floor of 40 so thin-IAT helpers like WannaCry `taskdl.exe` outrank demoted noise
- **.NET** samples with high toolchain confidence get a managed score floor (50+ at conf ≥ 90; higher with stealer/obfuscator/managed-net strings)
- **ELF / IoT bots** match IAT socket patterns when linked, and static/stripped loaders (Mirai `dlr.*`) get a string floor from markers like `MIRAI` / `GET /bins/mirai`
- Equal scores prefer PE/ELF/Mach-O/DOS over Raw so source trees cannot win a tie
- **`Ex` APIs are distinct** — `VirtualAlloc` does not match `VirtualAllocEx`; injection needs ≥2 corroborating APIs
- Ranking labels prefer including a network capability (`smb_enum` / `socket_client` / `http_client` / `c2_suspect`) when matched
- **Delphi toolchain** weak string markers (`Borland`, …) are ignored on Raw/source blobs; PE/ELF/Mach-O still accept them

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
vanguard <PATH> [--password infected] [--deep 3] [--disasm-count 4000] [--min-deep-score 70] [--full]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--password` / `-p` | `infected` | Password for encrypted ZIP archives |
| `--deep` | `3` | Number of top-scoring samples to deep-dive |
| `--disasm-count` | `4000` | Max instructions to decode per deep-dive |
| `--min-deep-score` | `70` | Minimum triage score required for a deep-dive |
| `--full` | off | Keep language packs / source / raw noise in ranking **and** print full member lists + every triage block |

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

Passworded malware packs and ZIPs embedded inside binaries are decrypted into RAM only, then ranked, signature-scanned, and deep-dived — nothing is executed.

## Containment

- **Static-only** — nothing is executed on the host
- Top-level and embedded ZIP members stay in process memory; never written as runnable files
- Recovered inner payloads (e.g. decrypted WannaCry `.wnry` files) are analyzed in RAM only, never dropped to disk as runnable files
- Recursive archive depth, member count, per-member size, and total extraction are bounded
- Dynamic analysis (if added later) would use a real microVM, not host exec

## License

MIT
