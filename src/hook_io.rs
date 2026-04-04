use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// JSON payload sent by Claude Code on a PreToolUse hook event.
#[derive(Debug, Deserialize, Clone)]
pub struct HookInput {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
}

impl HookInput {
    pub fn read_from_stdin() -> Result<Self> {
        let buf = std::io::read_to_string(std::io::stdin())
            .context("reading hook input from stdin")?;
        serde_json::from_str(&buf).context("parsing hook input JSON")
    }
}

/// JSON payload returned to Claude Code with the permission decision.
#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    decision: PermissionDecision,
    #[serde(rename = "suppressOutput")]
    suppress_output: bool,
}

#[derive(Debug, Serialize)]
struct PermissionDecision {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    verdict: &'static str,
    #[serde(rename = "permissionDecisionReason")]
    reason: String,
}

impl HookOutput {
    fn new(verdict: &'static str, reason: String) -> Self {
        Self {
            decision: PermissionDecision {
                hook_event_name: "PreToolUse",
                verdict,
                reason,
            },
            suppress_output: true,
        }
    }

    pub fn allow(reason: String) -> Self {
        Self::new("allow", reason)
    }

    pub fn deny(reason: String) -> Self {
        Self::new("deny", reason)
    }

    pub fn write_to_stdout(&self) -> Result<()> {
        serde_json::to_writer(std::io::stdout(), self)
            .context("writing hook output to stdout")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn allow_serializes_correctly() {
        let output = HookOutput::allow("safe command".into());
        let v = serde_json::to_value(&output).unwrap();

        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "safe command");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["suppressOutput"], true);
    }

    #[test]
    fn deny_serializes_correctly() {
        let output = HookOutput::deny("dangerous".into());
        let v = serde_json::to_value(&output).unwrap();

        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "dangerous");
    }

    #[test]
    fn hook_input_deserializes() {
        let json = serde_json::json!({
            "session_id": "abc",
            "transcript_path": "/tmp/t",
            "cwd": "/home",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"}
        });
        let input: HookInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input["command"], "ls -la");
    }
}
