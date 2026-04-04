use permiter::config::Config;
use permiter::engine::{evaluate, evaluate_with_local, Decision};
use pretty_assertions::assert_eq;
use std::path::Path;

fn load_example_config() -> Config {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("example.toml");
    Config::load(&path).expect("example.toml should be valid")
}

fn bash(cmd: &str) -> serde_json::Value {
    serde_json::json!({"command": cmd})
}

fn read_input(path: &str) -> serde_json::Value {
    serde_json::json!({"file_path": path})
}

fn write_input(path: &str) -> serde_json::Value {
    serde_json::json!({"file_path": path})
}

fn task_input(subagent_type: &str, prompt: &str) -> serde_json::Value {
    serde_json::json!({"subagent_type": subagent_type, "prompt": prompt})
}

const CWD: &str = "/home/user/dev/project";

#[test]
fn test_bash_safe_readonly_allowed() {
    let config = load_example_config();
    let cwd = Path::new(CWD);

    for cmd in &["ls -la", "pwd", "echo hello", "cat /etc/hosts", "which git"] {
        let result = evaluate(&config, "Bash", &bash(cmd), cwd).unwrap();
        assert_eq!(
            result.decision,
            Decision::Allow,
            "Expected allow for: {cmd}"
        );
    }
}

#[test]
fn test_bash_rm_denied() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Bash",
        &bash("rm -rf /tmp/test"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_bash_compound_with_rm_denied() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Bash",
        &bash("cargo build && rm -rf target/"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_bash_cargo_passthrough() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Bash",
        &bash("cargo test --release"),
        Path::new(CWD),
    )
    .unwrap();
    // cargo is not explicitly allowed — falls through to passthrough
    assert_eq!(result.decision, Decision::Passthrough);
}

#[test]
fn test_bash_git_allowed() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Bash",
        &bash("git status"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_bash_sudo_denied() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Bash",
        &bash("sudo apt install something"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_bash_empty_command_passthrough() {
    let config = load_example_config();
    let result = evaluate(&config, "Bash", &bash(""), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Passthrough);
}

#[test]
fn test_read_dev_allowed() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Read",
        &read_input("/home/user/dev/project/src/main.rs"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_read_outside_dev_denied() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Read",
        &read_input("/home/user/secrets.txt"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_read_system_file_allowed() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Read",
        &read_input("/etc/hosts"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_write_dev_allowed() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Write",
        &write_input("/home/user/dev/project/output.txt"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_write_outside_dev_denied() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Write",
        &write_input("/tmp/evil.sh"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_task_general_purpose_allowed() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Task",
        &task_input("general-purpose", "Search for files"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_task_unknown_type_denied() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "Task",
        &task_input("dangerous-agent", "do something bad"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_unknown_tool_denied() {
    let config = load_example_config();
    let result = evaluate(
        &config,
        "UnknownTool",
        &serde_json::json!({}),
        Path::new(CWD),
    )
    .unwrap();
    // Unknown tools have no fields to match, fall through to default = deny
    assert_eq!(result.decision, Decision::Deny);
}

fn load_example_perm() -> Config {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("example.perm");
    Config::load(&path).expect("example.perm should be valid")
}

/// Build a minimal config programmatically for fine-grained testing
fn minimal_config(toml: &str) -> Config {
    let mut c: Config = toml::from_str(toml).expect("valid toml");
    c.compile_regexes().expect("valid regexes");
    c
}

// ── DSL config integration tests ─────────────────────────────────────────
// Mirror the key TOML tests against example.perm to ensure parity.

#[test]
fn test_perm_bash_safe_allowed() {
    let config = load_example_perm();
    let cwd = Path::new(CWD);
    for cmd in &["ls -la", "pwd", "echo hello", "cat /etc/hosts"] {
        let result = evaluate(&config, "Bash", &bash(cmd), cwd).unwrap();
        assert_eq!(result.decision, Decision::Allow, "Expected allow for: {cmd}");
    }
}

#[test]
fn test_perm_bash_rm_denied() {
    let config = load_example_perm();
    let result = evaluate(&config, "Bash", &bash("rm -rf /tmp/test"), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_perm_bash_cargo_passthrough() {
    let config = load_example_perm();
    let result = evaluate(&config, "Bash", &bash("cargo test --release"), Path::new(CWD)).unwrap();
    // cargo is not explicitly allowed — hits catch-all passthrough
    assert_eq!(result.decision, Decision::Passthrough);
}

#[test]
fn test_perm_bash_sudo_denied() {
    let config = load_example_perm();
    let result = evaluate(&config, "Bash", &bash("sudo apt install something"), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_perm_read_dev_allowed() {
    let config = load_example_perm();
    let result = evaluate(&config, "Read", &read_input("/home/user/dev/project/src/main.rs"), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_perm_read_outside_denied() {
    let config = load_example_perm();
    let result = evaluate(&config, "Read", &read_input("/home/user/secrets.txt"), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_perm_write_dev_allowed() {
    let config = load_example_perm();
    let result = evaluate(&config, "Write", &write_input("/home/user/dev/project/output.txt"), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_perm_write_outside_denied() {
    let config = load_example_perm();
    let result = evaluate(&config, "Write", &write_input("/tmp/evil.sh"), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_perm_evaluate_sh_c_rm_denied() {
    let config = load_example_perm();
    let result = evaluate(&config, "Bash", &bash("sh -c 'rm -rf /'"), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_perm_evaluate_bash_c_safe_allowed() {
    let config = load_example_perm();
    let result = evaluate(&config, "Bash", &bash("bash -c 'ls /tmp'"), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_perm_evaluate_timeout_rm_denied() {
    let config = load_example_perm();
    let result = evaluate(&config, "Bash", &bash("timeout 30 rm -rf /"), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_perm_unknown_tool_denied() {
    let config = load_example_perm();
    let result = evaluate(&config, "UnknownTool", &serde_json::json!({}), Path::new(CWD)).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_pipe_chain_all_allowed() {
    let config = minimal_config(
        r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^(cat|grep|sort|wc)\\b"
action = "allow"
"#,
    );
    let result = evaluate(
        &config,
        "Bash",
        &bash("cat file.txt | grep foo | sort | wc -l"),
        Path::new("/tmp"),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_pipe_chain_one_denied() {
    let config = minimal_config(
        r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^cat\\b"
action = "allow"

[[table.input.rules]]
command = "^bash\\b"
action = "deny"
reason = "no bash"
"#,
    );
    let result = evaluate(
        &config,
        "Bash",
        &bash("cat file | bash"),
        Path::new("/tmp"),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

// ── evaluate action integration tests ────────────────────────────────────

#[test]
fn test_evaluate_sh_c_rm_denied_via_example() {
    let config = load_example_config();
    // sh -c 'rm -rf /' — evaluate rule in shell_scrutiny extracts "rm -rf /",
    // recycled through entry → forwarded to shell_scrutiny → denied
    let result = evaluate(
        &config,
        "Bash",
        &bash("sh -c 'rm -rf /'"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_evaluate_bash_c_safe_command_allowed() {
    let config = load_example_config();
    // bash -c 'ls /tmp' — evaluate extracts "ls /tmp", recycled → allowed by safe cmds
    let result = evaluate(
        &config,
        "Bash",
        &bash("bash -c 'ls /tmp'"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_evaluate_timeout_rm_denied_via_example() {
    let config = load_example_config();
    // timeout 30 rm -rf / — evaluate skips "30", subcommand "rm -rf /" denied
    let result = evaluate(
        &config,
        "Bash",
        &bash("timeout 30 rm -rf /"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_evaluate_sudo_still_denied_via_example() {
    let config = load_example_config();
    // sudo is explicitly denied before any evaluate rule can fire
    let result = evaluate(
        &config,
        "Bash",
        &bash("sudo rm -rf /"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_evaluate_sudo_with_custom_config() {
    // Config where sudo evaluate extracts subcommand into a scrutiny table
    let config = minimal_config(
        r#"
[table.input]
default = "deny"

[[table.input.rules]]
command = "^(cargo|ls)\\b"
action = "allow"

[[table.input.rules]]
command = "^sudo\\b"
action = "evaluate"
opts_with_args = ["-u", "-g"]
target = "sudo_cmds"

[table.sudo_cmds]
default = "deny"

[[table.sudo_cmds.rules]]
command = "^cargo\\b"
action = "allow"

[[table.sudo_cmds.rules]]
command = "^rm\\b"
action = "deny"
reason = "rm denied"
"#,
    );
    // sudo cargo build — subcommand allowed in sudo_cmds
    let result = evaluate(
        &config,
        "Bash",
        &bash("sudo cargo build"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // sudo -u nobody rm -rf / — flags consumed, subcommand denied in sudo_cmds
    let result = evaluate(
        &config,
        "Bash",
        &bash("sudo -u nobody rm -rf /"),
        Path::new(CWD),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

// ── New feature integration tests ───────────────────────────────────────

#[test]
fn test_force_passthrough_in_dsl_config() {
    // Parse a DSL config with force passthrough, verify it works
    let config_str = r#"
entry input
table input default passthrough {
    Bash command /^curl\b/ arg /^(-X|--request)$/ -> force passthrough "Destructive curl needs review"
}
"#;
    let config = permiter::dsl::parse_dsl(config_str).unwrap();
    let result = evaluate(
        &config,
        "Bash",
        &serde_json::json!({"command": "curl -X PUT http://localhost/api"}),
        Path::new("/home/user/dev/myproject"),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::ForcePassthrough);
}

#[test]
fn test_has_file_integration() {
    let tmp = std::env::temp_dir().join("permiter_integ_has_file");
    let _ = std::fs::remove_dir_all(&tmp);
    let venv_bin = tmp.join(".venv/bin");
    std::fs::create_dir_all(&venv_bin).unwrap();
    std::fs::write(venv_bin.join("pip"), "").unwrap();
    std::fs::create_dir_all(tmp.join(".git")).unwrap();

    let config_str = r#"
entry input
table input default passthrough {
    Bash command /^pip\b/ has_file ".venv/bin/pip" -> allow "pip in venv project"
}
"#;
    let config = permiter::dsl::parse_dsl(config_str).unwrap();
    let result = evaluate(
        &config,
        "Bash",
        &serde_json::json!({"command": "pip install requests"}),
        &tmp,
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_local_rules_end_to_end() {
    use permiter::local::{discover_local_dir, load_local_rules};

    let tmp = std::env::temp_dir().join("permiter_integ_local");
    let _ = std::fs::remove_dir_all(&tmp);
    let permiter_dir = tmp.join(".permiter");
    std::fs::create_dir_all(&permiter_dir).unwrap();
    std::fs::create_dir_all(tmp.join(".git")).unwrap();
    std::fs::write(
        permiter_dir.join("python.perm"),
        r#"Bash command /^pip\b/ -> allow "pip allowed in this project""#,
    )
    .unwrap();

    let config_str = r#"
local_rules = true
entry input
table input default passthrough {
    Bash command /^rm/ -> deny "rm not allowed"
}
"#;
    let config = permiter::dsl::parse_dsl(config_str).unwrap();
    let local = discover_local_dir(&tmp).map(|dir| load_local_rules(&dir).unwrap());

    // pip: global passthrough -> local allow
    let result = evaluate_with_local(
        &config,
        "Bash",
        &serde_json::json!({"command": "pip install foo"}),
        &tmp,
        local.as_ref(),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // rm: global deny -> local never runs
    let result = evaluate_with_local(
        &config,
        "Bash",
        &serde_json::json!({"command": "rm -rf /"}),
        &tmp,
        local.as_ref(),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny);

    // ls: global passthrough, local no match -> passthrough
    let result = evaluate_with_local(
        &config,
        "Bash",
        &serde_json::json!({"command": "ls -la"}),
        &tmp,
        local.as_ref(),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Passthrough);

    std::fs::remove_dir_all(&tmp).unwrap();
}
