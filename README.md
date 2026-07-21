# Vanguard-RE

High-speed, memory-safe static malware triage — interactive TUI only.

## Three Pillars

| Pillar | How |
|--------|-----|
| **Speed** | `memmap2` zero-copy I/O + focused static pipelines |
| **Accuracy** | Formal PE / ELF / Mach-O parsing (`goblin`), ImpHash, Shannon entropy maps, IAT heuristics, iced-x86 disassembly |
| **Safety** | Rust memory safety + in-memory quarantine — samples are never executed |

## Architecture

```
┌────────────────────────────────────────┐
│         Vanguard-RE TUI (ratatui)      │
└───────────────────┬────────────────────┘
                    │
     ┌──────────────┼──────────────┐
     ▼              ▼              ▼
 Static Triage   Disassembly    Signature Engine
 Header Parser   Call Profiler  (hashes / builtins)
```

## Build & install

```bash
# Fast check while iterating
cargo check

cargo build --release
cp target/release/vanguard ~/.local/bin/vanguard
```

Builtin signature rules are a lightweight string/byte matcher (no embedded YARA-X / Wasmtime). External `.yar` files are currently ignored with a note.

## Usage

```bash
vanguard
```

Menu → **Investigate sample / ZIP** → paste path, set password if needed → Run.

Passworded malware packs (e.g. password `infected`) are decrypted into RAM only, then ranked, signature-scanned, and deep-dived in the UI.

### Keys

| Key | Action |
|-----|--------|
| ↑↓ / j k | Move / step instructions |
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
