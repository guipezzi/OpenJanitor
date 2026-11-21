<#
.SYNOPSIS
    Fails if code outside crates/oj-safety can delete or move files.

.DESCRIPTION
    PLANNING.md section 9, rule 1: only the safety kernel may delete or move files.
    This scans Rust, TypeScript, and JavaScript sources (tests included) and
    every Cargo.toml / package.json for delete and move APIs.
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
    'tauri-plugin-fs'
    '@tauri-apps/plugin-fs'
)
$regex = [string]::Join('|', $patterns)

$excluded = @(
    (Join-Path $root 'crates\oj-safety')
    (Join-Path $root 'target')
    (Join-Path $root '.git')
)

$files = Get-ChildItem -Path $root -Recurse -File -Include *.rs, *.ts, *.tsx, *.js, *.jsx, *.mjs, Cargo.toml, package.json |
    Where-Object {
        $path = $_.FullName
        -not ($excluded | Where-Object { $path.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase) }) -and
        $path -notmatch '\\node_modules\\'
    }

$violations = foreach ($file in $files) {
    Select-String -Path $file.FullName -Pattern $regex -AllMatches |
        ForEach-Object {
            $relative = $_.Path.Substring($root.Length + 1)
            "{0}:{1}: {2}" -f $relative, $_.LineNumber, $_.Line.Trim()
        }
}

if ($violations) {
    Write-Host 'Delete or move calls found outside crates/oj-safety (PLANNING.md section 9):' -ForegroundColor Red
    $violations | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host ("Guardrails OK: checked {0} files, no delete or move calls outside crates/oj-safety." -f @($files).Count)
