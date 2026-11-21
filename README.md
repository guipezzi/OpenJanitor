# OpenJanitor

A free, open source disk cleaner for Windows. No paywalls, no telemetry.

> **Status:** early development. The app opens and runs a read-only scan, but it can't clean anything yet. Nothing here is ready for everyday use.

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
src-tauri/     desktop app shell (Tauri 2): the window and the commands the UI can call
ui/            user interface (React, TypeScript, Tailwind CSS, shadcn/ui)
rules/         cleaning rules (TOML)
scripts/       development scripts
docs/          extra documentation, such as asset licenses
```

## Building

You need:

- [Rust](https://rustup.rs) (stable, MSVC toolchain)
- Visual Studio Build Tools with the **Desktop development with C++** workload
- [Node.js](https://nodejs.org) 24 or later (LTS)
- Microsoft Edge WebView2, which comes with Windows 10 and 11

Install the UI dependencies once:

```powershell
npm install
```

## Running the app

```powershell
npm run dev
```

This opens the OpenJanitor window. The first run compiles the Rust code and takes a few minutes. Changes to the UI show up right away; changes to Rust code restart the app.

In this preview the app can only scan. It never deletes or moves anything.

## Testing

```powershell
cargo test --workspace
npm test
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

OpenJanitor is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version (GPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.
