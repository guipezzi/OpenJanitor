# Contributing to OpenJanitor

Thanks for helping. OpenJanitor deletes files on people's computers, so safety comes before everything else. Please read [PLANNING.md](PLANNING.md) first, especially §4 (safety model) and §9 (development guardrails).

## Ground rules

1. **Only `crates/oj-safety` may delete or move files.** CI fails if delete or move calls appear anywhere else (`scripts/check-guardrails.ps1`).
2. **Tests never touch the real system.** Use temporary folders and `SystemPaths::fake`, never real Windows or user folders.
3. **Every rule has a test**, and every deny-list entry has a test proving it's blocked.
4. **English everywhere:** code, comments, commits, issues, and docs.
5. **Small pull requests.** Changes to `oj-safety` get extra review.
6. `unsafe` code is only allowed in `crates/oj-windows`, in small, commented blocks.
7. **The UI never touches files directly.** It has no Tauri file system or shell plugin, and its capabilities (`src-tauri/capabilities/`) only allow `core:default`. Anything that reads or changes the disk is a Rust command in `src-tauri`.
8. **Every UI string is a translation key** in `ui/src/locales/en.json`. Don't write text directly in components.

## Before you open a pull request

Run the same checks CI runs:

```powershell
./scripts/check-guardrails.ps1
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm ci
npm run lint
npm run typecheck
npm test
```

## Dry-run mode

Debug builds default to **dry-run**: destructive operations are reported instead of performed. Set `OJ_DRY_RUN=0` to turn it off on purpose, or `OJ_DRY_RUN=1` to force it on in release builds.

## Adding a cleaning rule

Rules are TOML files in `rules/`. They're data only: a rule can't run commands or scripts. See PLANNING.md §5.3 for the format.

1. Add the rule to a file in `rules/` (or a new file, registered in `crates/oj-core/src/rule.rs`).
2. Use only the allowed variables (`%TEMP%`, `%LOCALAPPDATA%`, `%WINDIR%`, …; see `crates/oj-core/src/vars.rs`).
3. Add a fixture test in `crates/oj-core/tests/fixtures.rs` that builds a fake folder layout and checks the findings.
4. If the rule needs to reach inside a protected folder, the exception goes into `crates/oj-safety/src/deny.rs` and gets reviewed like code. Rule files can never add exceptions.
