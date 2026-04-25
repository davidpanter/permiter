---
name: permiter
description: Use when the user mentions permiter, asks to add/edit a permiter rule, references the permiter config, or asks why a command is blocked/allowed by permiter. Do NOT use for generic Claude Code settings.json questions.
---

# permiter

permiter is an iptables-inspired `PreToolUse` hook for Claude Code. It intercepts every tool call, decomposes compound shell commands into sub-commands (splitting on `&&`, `|`, `;`, `$(...)`, etc.), and evaluates each independently against a chain of rule tables. The strictest result across all sub-commands wins.

## Key locations

| | Path |
|-|------|
| Binary | `/home/dave/dev/permiter/target/release/permiter` |
| Global config | `/home/dave/.config/permiter.perm` |
| Audit log | `/tmp/claude-tool-use.json` |
| Project rules | `.permiter/*.perm` in project root |

## Adding rules

**Project-local rule** (applies only in this repo):

1. Create `.permiter/<name>.perm` in the project root — **not** `settings.local.json`
2. Add `.permiter/` to `.gitignore`
3. Verify with `permiter check` (see Testing)

```
# .permiter/project.perm
Bash command /^npm run build\b/ -> allow "npm run build"
Bash command /^kubectl\b/ -> allow "all kubectl"
```

**Global rule** (applies everywhere): edit `/home/dave/.config/permiter.perm`

`settings.local.json` Bash entries have no effect — permiter intercepts before Claude Code's permission check runs. Any `Bash(...)` entries there are vestigial.

## Rule DSL syntax

```
[Tool] [conditions...] -> action ["reason"]
```

**Tool** — bare name is exact match (`Bash`, `Read`, `Write`, `Edit`, `Glob`). Omit to match any tool.

**Conditions:**

| Field | Matches |
|-------|---------|
| `command /regex/` | Full sub-command string (Bash) |
| `arg /regex/` | Any individual argument |
| `file_path /regex/` | File path (Read/Write/Edit/Glob) |
| `cwd /regex/` | Effective working directory |
| `has_file "path"` | Relative path exists (walks up to git root) |

Prefix any condition with `!` to negate: `!arg /^--insecure$/`

**Variables** — reusable regex fragments:
```
let safe_cmds = /^(ls|pwd|echo)\b/
Bash command $safe_cmds -> allow "safe"
```

**Actions:**

| Action | Effect |
|--------|--------|
| `allow` | Permit |
| `deny` | Block (Claude sees an error) |
| `passthrough` | No opinion — Claude Code decides |
| `force passthrough` | Passthrough that local rules cannot override |
| `forward table_name` | Delegate to another table |
| `evaluate flag -c` | Extract subcommand from `-c` flag and re-evaluate |
| `evaluate skip N` | Skip N positional args, treat rest as subcommand |

**Decision strictness** (for compound commands): `deny > force passthrough > passthrough > allow`

## Local rules

Local rules fire **only when the global config returns `passthrough`** — they cannot override a global `allow` or `deny`.

Restrictions in local rules (enforced by permiter):
- Actions: `allow`, `deny`, `passthrough` only
- No `forward`, `evaluate`, `force passthrough`, tables, `entry`, or `audit`
- DSL `.perm` format only; `let` variables are allowed

## Testing rules

Always run `permiter check` **from inside the project directory** (local rules are resolved from cwd):

```bash
cd /path/to/project
/home/dave/dev/permiter/target/release/permiter check \
  -c /home/dave/.config/permiter.perm \
  --tool Bash --command "kubectl delete pod foo"
# → Decision: ALLOW  Source: .permiter/
```

Also test the **negative case** from outside the project to confirm scope:
```bash
cd /tmp
/home/dave/dev/permiter/target/release/permiter check \
  -c /home/dave/.config/permiter.perm \
  --tool Bash --command "kubectl delete pod foo"
# → Decision: PASSTHROUGH  (local rule did not fire)
```

Other tools use `--file_path` instead of `--command`:
```bash
permiter check -c ... --tool Read --file_path "/etc/passwd"
```

## Diagnosing a blocked or passthroughed command

### Audit log (what actually happened)

The audit log at `/tmp/claude-tool-use.json` records every rule match as JSON lines. Each line is one evaluated sub-command:

```json
{"timestamp":"2026-01-01T12:00:00Z","tool":"Bash","field":"command","check_string":"rm -rf /","cwd":"/home/dave/project","decision":"deny","reason":"rm is not allowed","table":"shell_scrutiny","rule_index":0,"source":"global"}
```

**To find which sub-command in a compound bash command went to passthrough:**

```bash
# Last N decisions — shows each decomposed sub-command separately
tail -n 50 /tmp/claude-tool-use.json | jq -r '
  [.timestamp, .decision, .check_string, .reason // ""] | @tsv
'

# Filter to just passthrough decisions
tail -n 100 /tmp/claude-tool-use.json | jq -r '
  select(.decision == "passthrough") |
  [.timestamp, .check_string, .table, .reason // ""] | @tsv
'

# Show the full last command's sub-commands (group by timestamp proximity)
tail -n 20 /tmp/claude-tool-use.json | jq -r '
  [.decision, .check_string] | @tsv
'
```

The `check_string` field is the exact sub-command that was evaluated. For a compound command like `cd /tmp && rm file && echo done`, you'll see three separate entries.

### Verbose rule trace

For a detailed trace of which rule matched and why:
```bash
RUST_LOG=debug /home/dave/dev/permiter/target/release/permiter check \
  -c /home/dave/.config/permiter.perm \
  --tool Bash --command "your full compound command"
```

This shows every sub-command permiter decomposed out of the compound command, which table and rule matched each one, and the final merged decision.
