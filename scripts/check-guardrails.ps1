<#
.SYNOPSIS
    Fails if code outside crates/oj-safety can delete or move files.

.DESCRIPTION
    PLANNING.md section 9, rule 1: only the safety kernel may delete or move files.
    This scans Rust, TypeScript, and JavaScript sources (tests included) and
    every Cargo.toml / package.json for delete and move APIs.

    It also keeps the UI away from the file system: the Tauri file system and
    shell plugins are banned, and the window's capabilities (the files in
    src-tauri/capabilities, and any declared in src-tauri/tauri.conf.json)
    can't grant fs or shell permissions. The UI can only call the Rust
    commands in src-tauri.

    Two files outside oj-safety may hold such a call, because unsafe code must
    live in oj-windows: crates/oj-windows/src/file_move.rs, the raw Win32 move
    behind quarantine, and crates/oj-windows/src/recycle_bin.rs, the shell call
    that empties the Recycle Bin. They're skipped here, and calling their
    functions (move_no_replace, shell_empty_recycle_bin) anywhere outside
    oj-safety fails the check.
#>

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$patterns = @(
    '\bremove_file\b'
    '\bremove_dir(_all)?\b'
    '\brename\s*\('
    '\bDeleteFile[AW]?\b'
    '\bRemoveDirectory[AW]?\b'
    '\bMoveFile(Ex|WithProgress)?[AW]?\b'
    '\bSHFileOperation[AW]?\b'
    '\bIFileOperation\b'
    '\bFileDispositionInfo(Ex)?\b'
    '\bfs\.(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|rename|renameSync)\b'
    '\bSHEmptyRecycleBin[AW]?\b'
    '\bmove_no_replace\b'
    '\bshell_empty_recycle_bin\b'
    'tauri-plugin-fs'
    '@tauri-apps/plugin-fs'
    'tauri-plugin-shell'
    '@tauri-apps/plugin-shell'
)
$regex = [string]::Join('|', $patterns)

# Permissions only mean something where capabilities are declared. Elsewhere
# the same text is harmless, such as Explorer's "shell:RecycleBinFolder".
$permission = '"(fs|shell):'

$excluded = @(
    (Join-Path $root 'crates\oj-safety')
    (Join-Path $root 'target')
    (Join-Path $root '.git')
    (Join-Path $root 'ui\dist')
    (Join-Path $root 'src-tauri\gen')
)
$allowedFiles = @(
    (Join-Path $root 'crates\oj-windows\src\file_move.rs')
    (Join-Path $root 'crates\oj-windows\src\recycle_bin.rs')
)

$capabilities = @(
    Get-ChildItem -Path (Join-Path $root 'src-tauri\capabilities') -Recurse -File -ErrorAction SilentlyContinue
    Get-Item -Path (Join-Path $root 'src-tauri\tauri.conf.json') -ErrorAction SilentlyContinue
)

$files = @(
    # Lockfiles too, so a banned plugin pulled in by another dependency is caught.
    Get-ChildItem -Path $root -Recurse -File -Include *.rs, *.ts, *.tsx, *.js, *.jsx, *.mjs, Cargo.toml, Cargo.lock, package.json, package-lock.json
    $capabilities
) |
    Where-Object {
        $path = $_.FullName
        -not ($excluded | Where-Object { $path.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase) }) -and
        -not ($allowedFiles | Where-Object { $path.Equals($_, [StringComparison]::OrdinalIgnoreCase) }) -and
        $path -notmatch '\\node_modules\\'
    }

$violations = foreach ($file in $files) {
    $pattern = if ($capabilities.FullName -contains $file.FullName) { "$regex|$permission" } else { $regex }
    Select-String -Path $file.FullName -Pattern $pattern -AllMatches |
        ForEach-Object {
            $relative = $_.Path.Substring($root.Length + 1)
            "{0}:{1}: {2}" -f $relative, $_.LineNumber, $_.Line.Trim()
        }
}

if ($violations) {
    Write-Host 'Delete or move calls, or UI file system access, found outside crates/oj-safety (PLANNING.md section 9):' -ForegroundColor Red
    $violations | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host ("Guardrails OK: checked {0} files, no delete or move calls outside crates/oj-safety and no UI file system access." -f @($files).Count)
