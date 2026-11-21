# OpenJanitor

A free, open source disk cleaner for Windows. No paywalls, no telemetry.

> **Status:** early development (phase 0). Nothing here is ready for everyday use yet.

OpenJanitor finds temporary, obsolete, and unnecessary files and helps you reclaim disk space **safely**:

- **Scanning never deletes anything.** You review every finding before anything is removed.
- **Every finding explains itself:** which rule found it, why, and how risky it is.
- **A hard deny list** protects Windows, your personal folders, and your credentials. No rule can override it.
- **Quarantine** keeps removed items restorable for a while before they're gone for good.

The full design lives in [PLANNING.md](PLANNING.md).

## Repository layout

```
crates/
  oj-core/     scan engine and rule loading
  oj-safety/   deny list, path validation, deletion (the only crate allowed to delete files)
  oj-windows/  read-only wrappers around Windows APIs
  oj-cli/      command line tool (for development)
rules/         cleaning rules (TOML)
scripts/       development scripts
```

## Building

You need:

- [Rust](https://rustup.rs) (stable, MSVC toolchain)
- Visual Studio Build Tools with the **Desktop development with C++** workload

Then:

```powershell
cargo build
cargo test
```

## Trying the scanner

The command line tool lists what OpenJanitor would clean. It only reads; it never deletes or moves anything.

```powershell
cargo run -p oj-cli -- scan
cargo run -p oj-cli -- scan --details
cargo run -p oj-cli -- rules
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-3.0-or-later.
