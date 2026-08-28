//! MCP server declarations.
//!
//! An MCP server configured in a repository is a process the agent spawns when
//! the session starts. `"command": "npx", "args": ["-y", "whatever"]` is a
//! download-and-run that no lockfile covers.

use super::{Ctx, Scanner, command_text};
use crate::finding::{Finding, ScanUnit, Severity};
use serde_json::Value;

pub struct Mcp;

const MCP_FILES: &[&str] = &[
    ".mcp.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
];

/// Both key names are in use: `mcpServers` (Claude, Cursor) and `servers` (VS Code).
const SERVER_KEYS: &[&str] = &["mcpServers", "servers"];

impl Scanner for Mcp {
    fn id(&self) -> &'static str {
        "mcp"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();

        for rel in MCP_FILES {
            let Some(doc) = ctx.json(rel, &mut unit) else {
                continue;
            };

            let before = unit.findings.len();
            let mut had_servers_block = false;

            for key in SERVER_KEYS {
                let Some(servers) = doc.get(*key).and_then(Value::as_object) else {
                    continue;
                };
                had_servers_block = true;

                for (name, cfg) in servers {
                    report_server(name, cfg, rel, &mut unit);
                }
            }

            // Only mark clean if this file actually declared servers. Otherwise
            // another scanner owns it and would double-report it as cleared.
            if had_servers_block && unit.findings.len() == before {
                unit.clear(*rel);
            }
        }

        unit
    }
}

fn report_server(name: &str, cfg: &Value, rel: &str, unit: &mut ScanUnit) {
    // Remote servers do not execute locally, but they do receive whatever the
    // agent sends them.
    if let Some(url) = cfg.get("url").and_then(Value::as_str) {
        unit.push(Finding::new(
            "mcp/remote-server",
            rel,
            format!("mcp server: {name}"),
            url,
            Severity::Note,
            "Remote MCP server receives tool traffic from the agent session.",
        ));
        return;
    }

    let Some(cmd) = cfg.get("command").and_then(command_text) else {
        return;
    };
    let args = cfg.get("args").and_then(command_text).unwrap_or_default();
    let full = if args.is_empty() {
        cmd.clone()
    } else {
        format!("{cmd} {args}")
    };

    // `npx -y` / `uvx` / `bunx` fetch and execute in one step, with no lockfile.
    let fetches = ["npx", "uvx", "bunx", "pnpm dlx", "yarn dlx"]
        .iter()
        .any(|p| full.contains(p));

    let (rule, note) = if fetches {
        (
            "mcp/server-fetches-and-runs",
            "Downloads and executes a package at session start; no lockfile pins this.",
        )
    } else {
        (
            "mcp/server-spawns-process",
            "Spawned as a local process when the agent session starts.",
        )
    };

    unit.push(Finding::new(
        rule,
        rel,
        format!("mcp server: {name}"),
        full,
        Severity::Immediate,
        note,
    ));
}
