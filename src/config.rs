use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Pre-compiled regex cache, keyed by pattern string.
pub type RegexCache = HashMap<String, Regex>;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfig {
    #[serde(default = "default_entry_table")]
    pub entry_table: String,
    #[serde(default)]
    pub local_rules: bool,
}

fn default_entry_table() -> String {
    "input".to_string()
}

impl Default for GlobalConfig {
    fn default() -> Self {
        GlobalConfig {
            entry_table: default_entry_table(),
            local_rules: false,
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    Off,
    Matched,
    All,
}

impl Default for AuditLevel {
    fn default() -> Self {
        AuditLevel::Off
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuditConfig {
    pub audit_file: Option<String>,
    #[serde(default)]
    pub audit_level: AuditLevel,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Passthrough,
    #[serde(rename = "force_passthrough")]
    ForcePassthrough,
    Forward,
    Evaluate,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Regex pattern on tool name (matches any tool if omitted)
    pub tool: Option<String>,
    /// Regex pattern on command string (for Bash tool)
    pub command: Option<String>,
    /// Regex pattern on file_path (for Read/Write/Edit/MultiEdit/Glob)
    pub file_path: Option<String>,
    /// Regex pattern on subagent_type (for Task tool)
    pub subagent_type: Option<String>,
    /// Regex pattern on prompt (for Task tool)
    pub prompt: Option<String>,
    /// Regex pattern on the effective cwd at the time the command runs (Bash only;
    /// for other tools matches the HookInput cwd). AND-ed with other conditions.
    pub cwd: Option<String>,
    /// Regex pattern matched against each argument individually (Bash only).
    /// Rule condition is satisfied if any single argument matches.
    pub arg: Option<String>,
    /// Exception to `arg`: rule does NOT fire if any argument matches this pattern.
    pub arg_not: Option<String>,
    /// Regex pattern matched against `<` redirect targets (Bash only).
    /// Rule condition is satisfied if any stdin redirect target matches.
    pub stdin: Option<String>,
    /// Exception to `stdin`: rule does NOT fire if any stdin redirect target matches.
    pub stdin_not: Option<String>,
    /// Regex pattern matched against `>` / `>>` redirect targets (Bash only).
    /// Rule condition is satisfied if any stdout redirect target matches.
    pub stdout: Option<String>,
    /// Exception to `stdout`: rule does NOT fire if any stdout redirect target matches.
    pub stdout_not: Option<String>,
    /// Exception to `cwd`: rule does NOT fire if the effective cwd matches this pattern.
    pub cwd_not: Option<String>,
    /// Regex matched against environment variable strings ("VAR=value").
    /// For Bash: checked against both inline prefix assignments AND the system environment.
    /// For other tools: checked against the system environment only.
    /// Rule fires if any env string matches.
    pub env: Option<String>,
    /// Exception to `env`: rule does NOT fire if any env string matches this pattern.
    pub env_not: Option<String>,
    /// Relative path that must exist (checked from cwd up to git root).
    /// Rule fires only if this file/directory is found.
    pub has_file: Option<String>,
    /// Exception: rule does NOT fire if this relative path exists.
    pub has_file_not: Option<String>,
    /// The action to take
    pub action: Action,
    /// Human-readable reason (used in output)
    pub reason: Option<String>,
    /// Target table for Forward/Evaluate actions
    pub target: Option<String>,
    /// For `evaluate` action: flag whose next arg is a shell string to re-parse.
    /// Example: `"-c"` for `sh -c '...'`. Mutually exclusive with `positional`.
    pub flag_arg: Option<String>,
    /// For `evaluate` action: number of positional (non-flag) args to skip before
    /// the subcommand. Example: `1` for `timeout` (skip duration), `1` for `ssh`
    /// (skip destination). Default 0 when `flag_arg` is not set.
    pub positional: Option<usize>,
    /// For `evaluate` action: flags that consume the following arg as their value.
    /// Unknown flags starting with `-` are treated as boolean (no value consumed).
    #[serde(default)]
    pub opts_with_args: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TableConfig {
    #[serde(default = "default_table_action")]
    pub default: Action,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

fn default_table_action() -> Action {
    Action::Deny
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub constants: HashMap<String, String>,
    #[serde(default)]
    pub table: HashMap<String, TableConfig>,
    #[serde(skip)]
    pub regex_cache: RegexCache,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "perm" => crate::dsl::parse_dsl(&content),
            _ => {
                let mut config: Config =
                    toml::from_str(&content).context("Failed to parse TOML config")?;
                config.resolve_constants()?;
                config.validate()?;
                config.compile_regexes()?;
                Ok(config)
            }
        }
    }

    fn resolve_constants(&mut self) -> Result<()> {
        // Build a regex that matches $name or ${name}
        let ref_re = Regex::new(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}|\$([a-zA-Z_][a-zA-Z0-9_]*)").unwrap();
        let constants = self.constants.clone();

        let substitute = |field: &mut Option<String>| -> Result<()> {
            let Some(s) = field else { return Ok(()) };
            let mut result = String::new();
            let mut last = 0;
            for cap in ref_re.captures_iter(s) {
                let m = cap.get(0).unwrap();
                let name = cap.get(1).or_else(|| cap.get(2)).unwrap().as_str();
                let value = constants.get(name).with_context(|| {
                    format!("Unknown constant '${name}' in pattern {:?}", s)
                })?;
                result.push_str(&s[last..m.start()]);
                result.push_str(value);
                last = m.end();
            }
            result.push_str(&s[last..]);
            *s = result;
            Ok(())
        };

        for table in self.table.values_mut() {
            for rule in &mut table.rules {
                substitute(&mut rule.tool)?;
                substitute(&mut rule.command)?;
                substitute(&mut rule.file_path)?;
                substitute(&mut rule.subagent_type)?;
                substitute(&mut rule.prompt)?;
                substitute(&mut rule.cwd)?;
                substitute(&mut rule.cwd_not)?;
                substitute(&mut rule.arg)?;
                substitute(&mut rule.arg_not)?;
                substitute(&mut rule.stdin)?;
                substitute(&mut rule.stdin_not)?;
                substitute(&mut rule.stdout)?;
                substitute(&mut rule.stdout_not)?;
                substitute(&mut rule.env)?;
                substitute(&mut rule.env_not)?;
            }
        }

        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        // Check entry table exists
        let entry = &self.global.entry_table;
        if !self.table.contains_key(entry) {
            bail!("Entry table '{}' not found in config", entry);
        }

        // Validate all forward/evaluate targets exist
        for (table_name, table) in &self.table {
            for (i, rule) in table.rules.iter().enumerate() {
                match &rule.action {
                    Action::Forward => {
                        match &rule.target {
                            None => bail!(
                                "Rule {i} in table '{table_name}' has action 'forward' but no target"
                            ),
                            Some(target) => {
                                if !self.table.contains_key(target) {
                                    bail!(
                                        "Rule {i} in table '{table_name}' forwards to unknown table '{target}'"
                                    );
                                }
                            }
                        }
                    }
                    Action::Evaluate => {
                        if rule.flag_arg.is_some() && rule.positional.is_some() {
                            bail!(
                                "Rule {i} in table '{table_name}' cannot have both 'flag_arg' and 'positional'"
                            );
                        }
                        if let Some(target) = &rule.target {
                            if !self.table.contains_key(target) {
                                bail!(
                                    "Rule {i} in table '{table_name}' evaluates to unknown table '{target}'"
                                );
                            }
                        }
                    }
                    _ => {}
                }
                if let Some(path) = &rule.has_file {
                    if path.starts_with('/') || path.contains("..") {
                        bail!("Rule {i} in table '{table_name}': has_file must be a relative path without '..', got '{path}'");
                    }
                }
                if let Some(path) = &rule.has_file_not {
                    if path.starts_with('/') || path.contains("..") {
                        bail!("Rule {i} in table '{table_name}': has_file_not must be a relative path without '..', got '{path}'");
                    }
                }
            }
        }

        Ok(())
    }

    /// Pre-compile all regex patterns in the config into a cache.
    pub fn compile_regexes(&mut self) -> Result<()> {
        let mut cache = RegexCache::new();

        let mut compile = |pattern: &Option<String>| -> Result<()> {
            if let Some(p) = pattern {
                if !cache.contains_key(p.as_str()) {
                    let re = Regex::new(p)
                        .map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", p, e))?;
                    cache.insert(p.clone(), re);
                }
            }
            Ok(())
        };

        for table in self.table.values() {
            for rule in &table.rules {
                compile(&rule.tool)?;
                compile(&rule.command)?;
                compile(&rule.file_path)?;
                compile(&rule.subagent_type)?;
                compile(&rule.prompt)?;
                compile(&rule.cwd)?;
                compile(&rule.cwd_not)?;
                compile(&rule.arg)?;
                compile(&rule.arg_not)?;
                compile(&rule.stdin)?;
                compile(&rule.stdin_not)?;
                compile(&rule.stdout)?;
                compile(&rule.stdout_not)?;
                compile(&rule.env)?;
                compile(&rule.env_not)?;
            }
        }

        self.regex_cache = cache;
        Ok(())
    }

    pub fn summary(&self) -> String {
        let mut lines = vec![format!(
            "Entry table: {}",
            self.global.entry_table
        )];
        for (name, table) in &self.table {
            lines.push(format!(
                "  Table '{}': {} rules, default={:?}",
                name,
                table.rules.len(),
                table.default
            ));
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn parse_config(s: &str) -> Config {
        toml::from_str(s).expect("valid config")
    }

    #[test]
    fn test_default_global() {
        let c = parse_config(
            r#"
[table.input]
default = "allow"
"#,
        );
        assert_eq!(c.global.entry_table, "input");
    }

    #[test]
    fn test_action_parsing() {
        let c = parse_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
tool = "Bash"
command = "^ls"
action = "allow"
"#,
        );
        assert_eq!(c.table["input"].rules[0].action, Action::Allow);
    }

    #[test]
    fn test_forward_rule() {
        let c = parse_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
action = "forward"
target = "scrutiny"

[table.scrutiny]
default = "deny"
"#,
        );
        assert_eq!(c.table["input"].rules[0].action, Action::Forward);
        assert_eq!(
            c.table["input"].rules[0].target.as_deref(),
            Some("scrutiny")
        );
    }

    #[test]
    fn test_constants_substituted() {
        let mut c = parse_config(
            r#"
[constants]
safe_cmds = "^(ls|pwd|echo)\\b"

[table.input]
default = "deny"

[[table.input.rules]]
command = "$safe_cmds"
action = "allow"
"#,
        );
        c.resolve_constants().unwrap();
        assert_eq!(
            c.table["input"].rules[0].command.as_deref(),
            Some(r"^(ls|pwd|echo)\b")
        );
    }

    #[test]
    fn test_constants_braces_syntax() {
        let mut c = parse_config(
            r#"
[constants]
home = "^/home/user"

[table.input]
default = "deny"

[[table.input.rules]]
file_path = "${home}/dev/.*"
action = "allow"
"#,
        );
        c.resolve_constants().unwrap();
        assert_eq!(
            c.table["input"].rules[0].file_path.as_deref(),
            Some("^/home/user/dev/.*")
        );
    }

    #[test]
    fn test_constants_unknown_ref_errors() {
        let mut c = parse_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "$undefined"
action = "allow"
"#,
        );
        assert!(c.resolve_constants().is_err());
    }

    #[test]
    fn test_validate_missing_entry_table() {
        let c = parse_config(
            r#"
[global]
entry_table = "nonexistent"

[table.input]
default = "allow"
"#,
        );
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_evaluate_rule_parsing() {
        let c = parse_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^(sh|bash)\\b"
action = "evaluate"
flag_arg = "-c"

[[table.input.rules]]
command = "^sudo\\b"
action = "evaluate"
target = "sudo_table"
opts_with_args = ["-u", "-g"]

[table.sudo_table]
default = "deny"
"#,
        );
        assert_eq!(c.table["input"].rules[0].action, Action::Evaluate);
        assert_eq!(c.table["input"].rules[0].flag_arg.as_deref(), Some("-c"));
        assert_eq!(c.table["input"].rules[1].opts_with_args, vec!["-u", "-g"]);
        assert_eq!(
            c.table["input"].rules[1].target.as_deref(),
            Some("sudo_table")
        );
    }

    #[test]
    fn test_evaluate_validate_flag_arg_and_positional_exclusive() {
        let c = parse_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^sh\\b"
action = "evaluate"
flag_arg = "-c"
positional = 1
"#,
        );
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_force_passthrough_allowed_as_table_default_toml() {
        let c = parse_config(
            r#"
[table.input]
default = "force_passthrough"
"#,
        );
        let result = c.validate();
        assert!(result.is_ok(), "force_passthrough should be allowed as table default");
        assert_eq!(c.table["input"].default, Action::ForcePassthrough);
    }

    #[test]
    fn test_force_passthrough_action_parsing() {
        let c = parse_config(
            r#"
[table.input]
default = "deny"

[[table.input.rules]]
tool = "Bash"
command = "^ls"
action = "force_passthrough"
reason = "Force passthrough for ls"
"#,
        );
        assert_eq!(c.table["input"].rules[0].action, Action::ForcePassthrough);
        assert_eq!(
            c.table["input"].rules[0].reason.as_deref(),
            Some("Force passthrough for ls")
        );
    }

    #[test]
    fn test_evaluate_validate_target_must_exist() {
        let c = parse_config(
            r#"
[table.input]
default = "allow"

[[table.input.rules]]
command = "^sudo\\b"
action = "evaluate"
target = "nonexistent"
"#,
        );
        assert!(c.validate().is_err());
    }
}
