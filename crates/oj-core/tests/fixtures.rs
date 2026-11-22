//! One fixture test per bundled rule (PLANNING.md §5.3): a fake folder
//! layout and the findings the rule should produce.

mod common;

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use common::{FakeMachine, junction, new_file, old_file, set_age, write_file};
use oj_core::{RuleSet, RuleStatus};

fn bundled() -> RuleSet {
    RuleSet::bundled().unwrap()
}

#[test]
fn user_temp_finds_old_files_only() {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    old_file(&temp.join("old.tmp"));
    old_file(&temp.join(r"setup-1234\old.log"));
    new_file(&temp.join("fresh.tmp"));

    assert_eq!(
        m.found(&bundled(), "windows.temp.user"),
        vec![temp.join("old.tmp"), temp.join(r"setup-1234\old.log")]
    );
    let report = m.scan(&bundled());
    let rule = report
        .rules
        .iter()
        .find(|r| r.rule_id == "windows.temp.user")
        .unwrap();
    assert_eq!(rule.skipped_recent, 1);
    assert!(rule.size_on_disk > 0);
}

#[test]
fn user_temp_never_follows_junctions() {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    let elsewhere = m.root.join("elsewhere");
    old_file(&temp.join("old.tmp"));
    old_file(&elsewhere.join("important.docx"));
    junction(&temp.join("link"), &elsewhere);

    assert_eq!(
        m.found(&bundled(), "windows.temp.user"),
        vec![temp.join("old.tmp")]
    );
}

#[test]
fn user_temp_never_reports_protected_files() {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    old_file(&temp.join("old.tmp"));
    old_file(&temp.join(r".ssh\id_ed25519"));
    old_file(&temp.join(r"profile\Cookies"));

    assert_eq!(
        m.found(&bundled(), "windows.temp.user"),
        vec![temp.join("old.tmp")]
    );
}

#[test]
fn hard_linked_files_count_as_freeing_nothing() {
    let m = FakeMachine::new();
    let temp = m.system.local_app_data.join("Temp");
    old_file(&temp.join("a.bin"));
    fs::hard_link(temp.join("a.bin"), m.root.join("kept-copy.bin")).unwrap();

    let report = m.scan(&bundled());
    let finding = report
        .findings
        .iter()
        .find(|f| f.path == temp.join("a.bin"))
        .unwrap();
    assert_eq!(finding.size_on_disk, 0);
    assert!(finding.evidence.iter().any(|e| e.contains("hard links")));
}

#[test]
fn system_temp_finds_files_inside_windows_temp_only() {
    let m = FakeMachine::new();
    let windows = &m.system.windows;
    old_file(&windows.join(r"Temp\installer.log"));
    old_file(&windows.join(r"System32\kernel32.dll"));

    assert_eq!(
        m.found(&bundled(), "windows.temp.system"),
        vec![windows.join(r"Temp\installer.log")]
    );
}

#[test]
fn crash_dumps_finds_dmp_files_only() {
    let m = FakeMachine::new();
    let dumps = m.system.local_app_data.join("CrashDumps");
    old_file(&dumps.join("app.exe.1234.dmp"));
    old_file(&dumps.join("notes.txt"));

    assert_eq!(
        m.found(&bundled(), "windows.crash-dumps.user"),
        vec![dumps.join("app.exe.1234.dmp")]
    );
}

#[test]
fn thumbnail_cache_finds_cache_databases_only() {
    let m = FakeMachine::new();
    let explorer = m.system.local_app_data.join(r"Microsoft\Windows\Explorer");
    old_file(&explorer.join("thumbcache_256.db"));
    old_file(&explorer.join("iconcache_32.db"));
    old_file(&explorer.join("ExplorerStartupLog.etl"));
    old_file(&explorer.join(r"sub\thumbcache_96.db"));

    assert_eq!(
        m.found(&bundled(), "windows.thumbnail-cache"),
        vec![
            explorer.join("iconcache_32.db"),
            explorer.join("thumbcache_256.db"),
        ]
    );
}

#[test]
fn missing_locations_are_reported_not_failed() {
    let m = FakeMachine::new();
    let report = m.scan(&bundled());
    for rule in &report.rules {
        assert!(
            matches!(
                rule.status,
                RuleStatus::NoLocations | RuleStatus::NotDetected
            ),
            "{}: {:?}",
            rule.rule_id,
            rule.status
        );
        assert_eq!(rule.findings, 0);
    }
}

#[test]
fn every_bundled_rule_has_a_fixture_test() {
    // Keep in sync with the tests below (PLANNING.md §9, rule 5).
    let tested = [
        "windows.temp.user",
        "windows.temp.system",
        "windows.thumbnail-cache",
        "windows.crash-dumps.user",
        "windows.crash-dumps.system",
        "windows.error-reports.user",
        "windows.error-reports.system",
        "windows.logs.old",
        "windows.shader-cache.directx",
        "gpu.nvidia.shader-cache",
        "gpu.amd.shader-cache",
        "gpu.intel.shader-cache",
        "browser.chrome.cache",
        "browser.edge.cache",
        "browser.brave.cache",
        "browser.opera.cache",
        "browser.firefox.cache",
        "app.discord.cache",
        "app.teams.cache",
        "app.slack.cache",
        "app.vscode.cache",
    ];
    let bundled: Vec<String> = bundled().iter().map(|r| r.rule.id.clone()).collect();
    assert_eq!(bundled, tested);
}

/// Old enough for every rule's minimum age (the longest is 30 days).
const VERY_OLD: Duration = Duration::from_secs(40 * 24 * 60 * 60);

/// Creates every file (old enough for any rule) and checks that `rule_id`
/// finds exactly the ones marked `true`.
fn assert_finds(m: &FakeMachine, rule_id: &str, files: &[(PathBuf, bool)]) {
    for (path, _) in files {
        write_file(path, 8192);
        set_age(path, VERY_OLD);
    }
    let mut expected: Vec<PathBuf> = files
        .iter()
        .filter(|(_, found)| *found)
        .map(|(path, _)| path.clone())
        .collect();
    expected.sort();
    assert_eq!(m.found(&bundled(), rule_id), expected, "{rule_id}");
}

// ----- Crash dumps and error reports -----

#[test]
fn system_crash_dumps_finds_dumps_and_memory_dmp() {
    let m = FakeMachine::new();
    let win = &m.system.windows;
    assert_finds(
        &m,
        "windows.crash-dumps.system",
        &[
            (win.join(r"Minidump\112226-01.dmp"), true),
            (
                win.join(r"LiveKernelReports\WATCHDOG\WD-20261120.dmp"),
                true,
            ),
            (win.join("MEMORY.DMP"), true),
            (win.join(r"Minidump\readme.txt"), false),
            (win.join(r"System32\config.dmp"), false),
        ],
    );
}

#[test]
fn user_error_reports_finds_archived_and_queued_reports() {
    let m = FakeMachine::new();
    let wer = m.system.local_app_data.join(r"Microsoft\Windows\WER");
    assert_finds(
        &m,
        "windows.error-reports.user",
        &[
            (
                wer.join(r"ReportArchive\AppCrash_app.exe_1\Report.wer"),
                true,
            ),
            (wer.join(r"ReportQueue\AppHang_app.exe_2\memory.hdmp"), true),
            (wer.join(r"Temp\in-progress.xml"), false),
        ],
    );
}

#[test]
fn system_error_reports_stay_inside_the_allowed_folders() {
    let m = FakeMachine::new();
    let wer = m.system.program_data.join(r"Microsoft\Windows\WER");
    assert_finds(
        &m,
        "windows.error-reports.system",
        &[
            (wer.join(r"ReportArchive\Kernel_1\Report.wer"), true),
            (wer.join(r"ReportQueue\AppCrash_svc.exe_2\Report.wer"), true),
            (wer.join(r"Temp\in-progress.xml"), false),
        ],
    );
}

#[test]
fn old_windows_logs_need_30_days_and_skip_measured_boot() {
    let m = FakeMachine::new();
    let logs = m.system.windows.join("Logs");
    let old = Duration::from_secs(40 * 24 * 60 * 60);
    let found = [
        logs.join(r"CBS\CbsPersist_20260101.log"),
        logs.join(r"CBS\CbsPersist_20260101.cab"),
        logs.join(r"WindowsUpdate\WindowsUpdate.20260101.etl"),
    ];
    let left_alone = [
        logs.join(r"MeasuredBoot\0000000001-0000000000.log"),
        logs.join(r"DISM\notes.txt"),
    ];
    for path in found.iter().chain(&left_alone) {
        write_file(path, 8192);
        set_age(path, old);
    }
    // Three days old: too recent for this rule.
    old_file(&logs.join(r"CBS\CBS.log"));

    let mut expected = found.to_vec();
    expected.sort();
    assert_eq!(m.found(&bundled(), "windows.logs.old"), expected);
}

// ----- Shader caches -----

#[test]
fn shader_caches_skip_files_used_in_the_last_30_days() {
    let m = FakeMachine::new();
    let cache = m.system.local_app_data.join(r"NVIDIA\DXCache");
    // Three days old: a game played recently.
    old_file(&cache.join("recent.nvph"));
    write_file(&cache.join("stale.nvph"), 8192);
    set_age(&cache.join("stale.nvph"), VERY_OLD);

    assert_eq!(
        m.found(&bundled(), "gpu.nvidia.shader-cache"),
        vec![cache.join("stale.nvph")]
    );
}

#[test]
fn driver_shader_caches_are_low_risk_but_not_recommended() {
    for compiled in bundled().iter() {
        let rule = &compiled.rule;
        let is_driver_cache = rule.id.starts_with("gpu.");
        if is_driver_cache {
            assert_eq!(rule.risk, oj_core::Risk::Low, "{}", rule.id);
        }
        assert_eq!(rule.recommended, !is_driver_cache, "{}", rule.id);
    }
}

#[test]
fn directx_shader_cache_finds_everything_inside() {
    let m = FakeMachine::new();
    let cache = m.system.local_app_data.join("D3DSCache");
    assert_finds(
        &m,
        "windows.shader-cache.directx",
        &[(cache.join(r"14e06600741f2647\shader.idx"), true)],
    );
}

#[test]
fn nvidia_shader_cache_finds_both_locations_only() {
    let m = FakeMachine::new();
    let local = m.system.local_app_data.join("NVIDIA");
    let local_low = m.system.user_profile.join(r"AppData\LocalLow\NVIDIA");
    assert_finds(
        &m,
        "gpu.nvidia.shader-cache",
        &[
            (local.join(r"DXCache\abc.toc"), true),
            (local.join(r"GLCache\1\2.bin"), true),
            (local_low.join(r"DXCache\def.toc"), true),
            (local_low.join(r"PerDriverVersion\DXCache\ghi.toc"), true),
            (
                local.join(r"NvBackend\ApplicationOntology\data.json"),
                false,
            ),
        ],
    );
}

#[test]
fn amd_shader_cache_leaves_settings_alone() {
    let m = FakeMachine::new();
    let amd = m.system.local_app_data.join("AMD");
    assert_finds(
        &m,
        "gpu.amd.shader-cache",
        &[
            (amd.join(r"DxCache\a.parc"), true),
            (amd.join(r"VkCache\b.parc"), true),
            (amd.join(r"CN\settings.json"), false),
        ],
    );
}

#[test]
fn intel_shader_cache_finds_everything_inside() {
    let m = FakeMachine::new();
    let cache = m
        .system
        .user_profile
        .join(r"AppData\LocalLow\Intel\ShaderCache");
    assert_finds(
        &m,
        "gpu.intel.shader-cache",
        &[(cache.join(r"CompiledShaders\x.bin"), true)],
    );
}

// ----- Browsers -----

/// Chrome, Edge, and Brave share Chromium's layout.
fn assert_chromium_cache_only(rule_id: &str, user_data: &str) {
    let m = FakeMachine::new();
    let data = m.system.local_app_data.join(user_data);
    assert_finds(
        &m,
        rule_id,
        &[
            (data.join(r"Default\Cache\Cache_Data\f_000001"), true),
            (data.join(r"Profile 1\Code Cache\js\index"), true),
            (data.join(r"Default\GPUCache\data_0"), true),
            (data.join(r"GrShaderCache\data_1"), true),
            (data.join(r"Default\History"), false),
            (data.join(r"Default\Network\Cookies"), false),
            (
                data.join(r"Default\Local Storage\leveldb\000003.log"),
                false,
            ),
            (
                data.join(r"Default\Service Worker\CacheStorage\abc\index"),
                false,
            ),
            (data.join(r"Default\Extensions\abc\1.0\Cache\x.js"), false),
            // Personal-data names stay protected even inside a cache folder.
            (data.join(r"Default\Cache\Login Data"), false),
            (data.join("Local State"), false),
        ],
    );
}

#[test]
fn chrome_cache_finds_cache_folders_only() {
    assert_chromium_cache_only("browser.chrome.cache", r"Google\Chrome\User Data");
}

#[test]
fn edge_cache_finds_cache_folders_only() {
    assert_chromium_cache_only("browser.edge.cache", r"Microsoft\Edge\User Data");
}

#[test]
fn brave_cache_finds_cache_folders_only() {
    assert_chromium_cache_only(
        "browser.brave.cache",
        r"BraveSoftware\Brave-Browser\User Data",
    );
}

#[test]
fn opera_cache_covers_local_roaming_and_gx() {
    let m = FakeMachine::new();
    let local = m.system.local_app_data.join(r"Opera Software\Opera Stable");
    let roaming = m
        .system
        .roaming_app_data
        .join(r"Opera Software\Opera Stable");
    let gx = m
        .system
        .local_app_data
        .join(r"Opera Software\Opera GX Stable");
    assert_finds(
        &m,
        "browser.opera.cache",
        &[
            (local.join(r"Cache\Cache_Data\f_1"), true),
            (roaming.join(r"Code Cache\js\index"), true),
            (roaming.join(r"GPUCache\data_0"), true),
            (roaming.join(r"Default\Cache\Cache_Data\f_2"), true),
            (gx.join(r"Cache\Cache_Data\f_3"), true),
            (roaming.join("Cookies"), false),
            (
                roaming.join(r"Service Worker\CacheStorage\abc\index"),
                false,
            ),
            (roaming.join(r"Local Storage\leveldb\000003.log"), false),
        ],
    );
}

#[test]
fn firefox_cache_reads_the_local_profile_half_only() {
    let m = FakeMachine::new();
    let profile = m
        .system
        .local_app_data
        .join(r"Mozilla\Firefox\Profiles\abc123.default-release");
    let roaming_profile = m
        .system
        .roaming_app_data
        .join(r"Mozilla\Firefox\Profiles\abc123.default-release");
    assert_finds(
        &m,
        "browser.firefox.cache",
        &[
            (profile.join(r"cache2\entries\0A1B2C"), true),
            (profile.join(r"startupCache\scriptCache.bin"), true),
            (profile.join(r"thumbnails\page.png"), true),
            (profile.join(r"jumpListCache\icon.ico"), true),
            (profile.join(r"shader-cache\blob"), true),
            (profile.join(r"safebrowsing\google.vlpset"), false),
            (roaming_profile.join(r"cache2\entries\never-here"), false),
            (roaming_profile.join("places.sqlite"), false),
        ],
    );
}

// ----- Apps -----

#[test]
fn discord_cache_leaves_messages_and_the_app_alone() {
    let m = FakeMachine::new();
    let discord = m.system.roaming_app_data.join("discord");
    let ptb = m.system.roaming_app_data.join("discordptb");
    assert_finds(
        &m,
        "app.discord.cache",
        &[
            (discord.join(r"Cache\Cache_Data\f_1"), true),
            (discord.join(r"Code Cache\js\index"), true),
            (discord.join(r"GPUCache\data_0"), true),
            (discord.join(r"ShaderCache\data_1"), true),
            (ptb.join(r"Cache\Cache_Data\f_2"), true),
            (discord.join(r"Local Storage\leveldb\000003.log"), false),
            (
                discord.join(r"1.0.9269\modules\discord_voice\x.node"),
                false,
            ),
            (discord.join("settings.json"), false),
        ],
    );
}

#[test]
fn teams_cache_stays_inside_the_webview_caches() {
    let m = FakeMachine::new();
    let teams = m
        .system
        .local_app_data
        .join(r"Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams");
    let webview = teams.join("EBWebView");
    assert_finds(
        &m,
        "app.teams.cache",
        &[
            (webview.join(r"WV2Profile_tfw\Cache\Cache_Data\f_1"), true),
            (webview.join(r"WV2Profile_tfw\Code Cache\js\index"), true),
            (webview.join(r"GrShaderCache\data_0"), true),
            (
                webview.join(r"WV2Profile_tfw\IndexedDB\teams.db\000003.log"),
                false,
            ),
            (teams.join(r"Logs\MSTeams_2026-11-20.log"), false),
            (teams.join("app_settings.json"), false),
        ],
    );
}

#[test]
fn slack_cache_covers_both_installs() {
    let m = FakeMachine::new();
    let slack = m.system.roaming_app_data.join("Slack");
    let store = m
        .system
        .local_app_data
        .join(r"Packages\91750D7E.Slack_8she8kybcnzg4\LocalCache\Roaming\Slack");
    assert_finds(
        &m,
        "app.slack.cache",
        &[
            (slack.join(r"Cache\Cache_Data\f_1"), true),
            (slack.join(r"GPUCache\data_0"), true),
            (store.join(r"Code Cache\js\index"), true),
            (slack.join(r"storage\root-state.json"), false),
            (slack.join(r"Local Storage\leveldb\000003.log"), false),
        ],
    );
}

#[test]
fn vscode_cache_leaves_settings_and_unsaved_work_alone() {
    let m = FakeMachine::new();
    let code = m.system.roaming_app_data.join("Code");
    assert_finds(
        &m,
        "app.vscode.cache",
        &[
            (code.join(r"Cache\Cache_Data\f_1"), true),
            (code.join(r"CachedData\0123abcd\chrome\js\x.code"), true),
            (
                code.join(r"CachedExtensionVSIXs\ms-python.python-2026.1.0"),
                true,
            ),
            (code.join(r"User\settings.json"), false),
            (code.join(r"User\workspaceStorage\abc\state.vscdb"), false),
            (code.join(r"Backups\1234\file\untitled-1"), false),
            (code.join(r"logs\20261120T101010\main.log"), false),
        ],
    );
}
