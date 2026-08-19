//! Command-line front end for the `onopen` library.

use anyhow::{Context, Result};
use clap::Parser;
use onopen::report::{self, HumanOptions, Report};
use onopen::{ScanOptions, scan, scanner_ids};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "onopen",
    version,
    about = "See what runs when you open a repository.",
    long_about = "onopen inspects the configuration files in a repository and reports \
every path that would execute a command — a VS Code task set to run on folder open, \
an agent hook, an MCP server, an install script, a git hook.\n\n\
It only reads and parses. It never executes what it finds."
)]
struct Cli {
    /// Repository to inspect
    #[arg(default_value = ".", value_name = "PATH")]
    path: PathBuf,

    /// Emit machine-readable JSON
    #[arg(long)]
    json: bool,

    /// Print why each finding is an execution path
    #[arg(short, long)]
    explain: bool,

    /// Hide files that were inspected and came back clean
    #[arg(short, long)]
    quiet: bool,

    /// Always exit 0, even when execution paths are found
    #[arg(long)]
    no_fail: bool,

    /// Run only these scanners (comma-separated)
    #[arg(long, value_delimiter = ',', value_name = "ID")]
    only: Vec<String>,

    /// Skip these scanners (comma-separated)
    #[arg(long, value_delimiter = ',', value_name = "ID")]
    skip: Vec<String>,

    /// How deep to look for sub-projects. 0 inspects the root alone
    #[arg(long, value_name = "N", default_value_t = onopen::DEFAULT_MAX_DEPTH)]
    depth: usize,

    /// List the available scanners and exit
    #[arg(long)]
    list_scanners: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.list_scanners {
        for id in scanner_ids() {
            println!("{id}");
        }
        return ExitCode::SUCCESS;
    }

    match run(&cli) {
        Ok(found_immediate) => {
            if found_immediate && !cli.no_fail {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("onopen: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Returns whether the scan found something that runs on its own.
fn run(cli: &Cli) -> Result<bool> {
    let root = cli
        .path
        .canonicalize()
        .with_context(|| format!("cannot read {}", cli.path.display()))?;

    let opts = ScanOptions {
        only: cli.only.clone(),
        skip: cli.skip.clone(),
        max_depth: cli.depth,
    };
    let mut unit = scan(&root, &opts)?;

    let cleared = std::mem::take(&mut unit.cleared);
    let report = Report::build(display_path(&cli.path, &root), unit);

    if cli.json {
        println!("{}", report::render_json(&report));
    } else {
        let opts = HumanOptions {
            explain: cli.explain,
            quiet: cli.quiet,
            cleared,
        };
        print!("{}", report::render_human(&report, &opts));
    }

    Ok(report.should_fail())
}

/// Prefer what the user typed; fall back to the resolved path, stripped of the
/// Windows verbatim prefix that `canonicalize` adds.
fn display_path(given: &Path, resolved: &Path) -> String {
    let given = given.to_string_lossy();
    if given != "." {
        return given.replace('\\', "/");
    }
    resolved
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}
