# permiter

An iptables-inspired `PreToolUse` hook for [Claude Code](https://github.com/anthropics/claude-code). It intercepts every tool call Claude makes, decomposes shell commands into their constituent sub-commands, evaluates each against a chain of rule tables, and returns the strictest decision.  The idea is to provide considerably more flexiblity to define and tune rules for Claude.  

## Installation

### Homebrew

```sh
brew tap davidpanter/tap
brew install permiter
```

### From source

```sh
cargo install --git https://github.com/davidpanter/permiter
```

Or clone and build:

```sh
git clone https://github.com/davidpanter/permiter
cd permiter
cargo build --release
# binary is at target/release/permiter
```

### Hook setup

Add permiter as a Claude Code hook in `~/.claude/settings.local.json` (or a project-level `.claude/settings.local.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "permiter run -c /path/to/config.perm"
          }
        ]
      }
    ]
  }
}
```

## CLI

```sh
permiter run -c <config>            # hook mode: read stdin, write stdout
permiter validate -c <config>       # validate config, print table/rule counts
permiter check -c <config> \        # test a specific input against the config
    --tool Bash --command "rm -rf /"
```

### `check` flags

| Flag          | Description                                    |
|---------------|------------------------------------------------|
| `--tool`      | Tool name (required) — `Bash`, `Read`, `Write`, etc. |
| `--command`   | Command string (for Bash)                      |
| `--file_path` | File path (for Read/Write/Edit/Glob)           |
| `--cwd`       | Working directory (default: `.`)               |

`check` exits with code 1 on deny — useful for scripting.

Set `RUST_LOG=debug` for verbose rule evaluation output.

## Config Formats

permiter supports two config formats. The file extension determines the parser:

- **`.perm`** — a purpose-built DSL (recommended, more concise)
- **`.toml`** — standard TOML (more verbose, better editor support)

Both formats produce the same internal config. See [`example.perm`](example.perm) and [`example.toml`](example.toml) for equivalent reference configs, and [`contrib/`](contrib/) for ready-made snippets (kubectl, git, scripting venvs, MCP allowlists, …) you can lift into your own config.

---

## DSL Format (`.perm`)

### Variables

Define reusable regex patterns with `let` and reference them with `$name`:

```
let safe_cmds = /^(ls|pwd|echo|cat|grep|find)\b/
let dev_dir = /^\/home\/user\/dev\/.*/

table input default deny {
    Bash command $safe_cmds -> allow "Safe read-only commands"
    Read file_path $dev_dir -> allow "Dev reads allowed"
}
```

### Tables

```
table <name> default <allow|deny|passthrough> {
    <rules...>
}
```

### Rules

Rules are written one per line inside a table block. A rule is a sequence of conditions followed by an arrow (`->`) and an action:

```
<tool> <condition> <condition> ... -> <action> ["reason"]
```

**Tool shorthand:** A bare identifier at the start of a rule (e.g. `Bash`) is automatically wrapped as `^Bash$` for exact matching. Omit it to match any tool.

**Conditions** use a keyword followed by a regex or string:

```
Bash command /^git\b/ -> allow "Git allowed"
Read file_path /^\/etc\/.*/ -> allow
command /^rm\b/ !arg /^--dry-run$/ -> deny "rm without --dry-run"
```

**Negation:** Prefix a condition with `!` to invert it (becomes a `_not` exception):

```
command /^curl\b/ !arg /evil/ -> allow "curl, but not to evil"
```

### Actions in DSL

```
-> allow "reason"
-> deny "reason"
-> passthrough
-> force passthrough "reason"
-> forward table_name
-> evaluate flag -c
-> evaluate skip 1
-> evaluate flag -c target other_table
-> evaluate skip 1 opts [-u, -g]
```

### Global directives

```
entry input                                       # entry table (default: input)
audit file "/tmp/permiter-audit.json" level matched
local_rules = true                                # enable .permiter/ project rules
```

### Comments

Lines starting with `#` are comments. Inline `#` comments are also supported.

---

## TOML Format

### Global settings

```toml
[global]
entry_table = "input"     # which table to start evaluation in (default: "input")
local_rules = false       # enable .permiter/ project-local rules (default: false)

[audit]
audit_file  = "/tmp/permiter-audit.json"
audit_level = "matched"   # off | matched | all
```

### Constants

Define reusable regex fragments in `[constants]` and reference them with `$name` or `${name}` in any pattern field:

```toml
[constants]
home      = "^/home/user"
safe_cmds = "^(ls|pwd|echo|cat|grep|find)\\b"

[[table.input.rules]]
command   = "$safe_cmds"
action    = "allow"

[[table.input.rules]]
file_path = "${home}/dev/.*"
action    = "allow"
```

Referencing an undefined constant is a hard error at load time.

### Tables and rules

```toml
[table.input]
default = "deny"        # allow | deny | passthrough

[[table.input.rules]]
tool    = "^Bash$"
command = "^(ls|pwd)\\b"
action  = "allow"
reason  = "Safe read-only commands"

[[table.input.rules]]
tool    = "^Bash$"
action  = "forward"
target  = "shell_scrutiny"
```

---

## Rule Reference

### How rules match

All fields in a rule are optional except `action`. A rule matches when **every** specified condition matches. Omitting a field means "match anything".

All pattern fields are [Rust regex](https://docs.rs/regex) and are matched case-sensitively with `is_match` (not anchored unless you use `^`/`$`).

### Actions

| Action              | Effect |
|---------------------|--------|
| `allow`             | Permit the tool call |
| `deny`              | Block the tool call (Claude sees an error) |
| `passthrough`       | No opinion — let Claude Code decide (exit 0, no output) |
| `force passthrough` | Like passthrough, but immune to local rule override (see [Local Rules](#local-rules)) |
| `forward`           | Delegate to another table (`target` required) |
| `evaluate`          | Extract a subcommand and recursively evaluate it (see [Evaluate](#evaluate-action)) |

### Decision merging

For compound shell commands (`cmd1 && cmd2 | cmd3`), permiter evaluates every sub-command independently and takes the **strictest** result:

```
deny > force passthrough > passthrough > allow
```

### Universal condition fields

| Field  | Matches against |
|--------|----------------|
| `tool` | The tool name (`Bash`, `Read`, `Write`, `Edit`, `MultiEdit`, `Glob`, `Task`, `mcp__*`, ...) |
| `cwd`  | The effective working directory (Bash: tracks `cd`; other tools: from HookInput) |
| `env`  | Environment variable strings as `VAR=value`. For Bash: includes inline prefix assignments. |

### Bash-specific condition fields

| Field     | Matches against |
|-----------|----------------|
| `command` | The full command string of each decomposed sub-command |
| `arg`     | Each argument individually — fires if **any** arg matches |
| `stdin`   | Each `<` redirect target — fires if **any** matches |
| `stdout`  | Each `>` / `>>` redirect target — fires if **any** matches |

### File tool condition fields (Read, Write, Edit, MultiEdit, Glob)

| Field       | Matches against |
|-------------|----------------|
| `file_path` | The file path argument |

### Task tool condition fields

| Field          | Matches against |
|----------------|----------------|
| `subagent_type`| The agent type string |
| `prompt`       | The prompt string |

### Filesystem condition fields

| Field      | Type   | Matches when... |
|------------|--------|-----------------|
| `has_file` | string | The relative path exists (searched from cwd up to git root) |

`has_file` takes a plain path, not a regex. Must be relative with no `..` traversal.

```
# DSL
Bash command /^pip\b/ has_file ".venv/bin/pip" -> allow "pip in venv"

# TOML
[[table.input.rules]]
command  = "^pip\\b"
has_file = ".venv/bin/pip"
action   = "allow"
```

### Exception fields

Each condition that supports exceptions has a `_not` counterpart. When a `_not` field matches, the rule does **not** fire — regardless of the positive field.

| Exception field  | Cancels match when...               |
|------------------|--------------------------------------|
| `cwd_not`        | effective cwd matches the pattern    |
| `arg_not`        | any argument matches the pattern     |
| `stdin_not`      | any stdin redirect target matches    |
| `stdout_not`     | any stdout redirect target matches   |
| `env_not`        | any env variable string matches      |
| `has_file_not`   | the relative path exists             |

In the DSL, exceptions are written with `!`:

```
command /^curl\b/ !arg /^--insecure$/ -> allow
```

In TOML, use the `_not` field directly:

```toml
command = "^curl\\b"
arg_not = "^--insecure$"
action  = "allow"
```

### Other rule fields

| Field    | Purpose |
|----------|---------|
| `action` | **Required.** The action to take. |
| `reason` | Human-readable string included in deny messages and audit log. |
| `target` | Required for `forward`. Optional for `evaluate` (defaults to entry table). |

---

## Forward Chains and Cycle Detection

`forward` rules delegate evaluation to another table. The result from the target table is returned as-is. Cycles (table A -> table B -> table A) are detected and treated as a deny.

---

## Evaluate Action

The `evaluate` action extracts a subcommand from a wrapper command and recursively evaluates it. This handles patterns like `sh -c '...'`, `timeout 5 rm file`, and `sudo -u user cmd`.

### Extraction modes

| Mode         | TOML field   | DSL syntax  | Behaviour |
|--------------|-------------|-------------|-----------|
| Flag         | `flag_arg`  | `flag -c`   | Find the flag (e.g. `-c`), take its next argument as a shell string |
| Positional   | `positional`| `skip N`    | Skip N positional (non-flag) arguments, treat the rest as the subcommand |

`flag_arg` and `positional` are mutually exclusive.

### Options that consume arguments

Some wrapper commands have flags that take a value (e.g. `sudo -u root`). Use `opts_with_args` (TOML) or `opts [...]` (DSL) to tell the parser which flags consume the next argument:

```
# DSL
command /^sudo\b/ -> evaluate skip 1 opts [-u, -g]

# TOML
[[table.shell_scrutiny.rules]]
command        = "^sudo\\b"
action         = "evaluate"
positional     = 1
opts_with_args = ["-u", "-g"]
```

### Target table

By default, extracted subcommands are evaluated through the entry table. Specify `target` to evaluate through a different table:

```
# DSL
command /^sh\b/ -> evaluate flag -c target shell_scrutiny

# TOML
flag_arg = "-c"
action   = "evaluate"
target   = "shell_scrutiny"
```

### Depth limit

Evaluate chains are limited to **5 levels** of nesting. Exceeding this depth results in an automatic deny.

---

## Shell Command Decomposition

When Claude calls the `Bash` tool, permiter parses the full command string into individual sub-commands before evaluation. Each sub-command is evaluated independently.

### What is decomposed

| Construct | Behaviour |
|-----------|-----------|
| `;` `&&` `\|\|` `\|` newlines | Split into separate sub-commands |
| `$(...)` `` `...` `` | Recursively parsed; inner commands evaluated |
| `(...)` subshells | Cwd changes inside do **not** propagate out |
| `{...; }` command groups | Cwd changes **do** propagate (same shell context) |
| `\<newline>` | Line continuation — collapsed to a space before parsing |
| `"..."` `'...'` | Quoted strings — operators inside are not parsed |
| Here-docs `<<EOF` | Body is treated as inert data |

### cd tracking and path resolution

permiter tracks the effective working directory across sub-commands. `cd` updates the tracked cwd; subsequent commands see the updated value in their `cwd` field and in resolved argument paths.

```bash
cd /tmp && rm secret.txt
#          ^^^^^^^^^^^^ effective_cwd = /tmp, resolved arg = /tmp/secret.txt
```

Subshells inherit the current cwd but cannot propagate changes back to the parent context.

### Variable assignment stripping

Shell commands often have variable assignment prefixes. These are stripped so that rule conditions match the actual command being run, not the assignment boilerplate:

```bash
FOO=bar git commit -m "msg"
# -> rules match against: git commit -m "msg"

export DEBIAN_FRONTEND=noninteractive apt-get install -y curl
# -> rules match against: apt-get install -y curl
```

Handled prefixes: plain `VAR=val`, `export`, `local`, `declare`, `typeset`, `readonly`.

---

## Local Rules

Projects can define their own rules in a `.permiter/` directory. Local rules can **relax** passthrough decisions — they only run when global rules return `passthrough`.

### Enabling

Local rules are off by default. Enable them in your global config:

```
# DSL
local_rules = true

# TOML
[global]
local_rules = true
```

### How it works

1. Global config evaluates the tool call
2. If the result is `allow`, `deny`, or `force passthrough` — that's final
3. If the result is `passthrough`, permiter looks for a `.permiter/` directory by walking from the working directory up to the nearest git root
4. All `*.perm` files in that directory are loaded (sorted alphabetically) and evaluated as a flat rule list
5. The local result replaces the global passthrough

### Restrictions

Local rules are intentionally limited to prevent projects from undermining your global policy:

- **Allowed actions:** `allow`, `deny`, `passthrough`
- **Not allowed:** `forward`, `evaluate`, `force passthrough`, tables, `entry`, `audit`
- **Format:** DSL only (`.perm` files)
- Variables (`let`) are allowed

### Example

```
# .permiter/python.perm
Bash command /^pip\b/ -> allow "pip allowed in this project"
Bash command /^pytest\b/ -> allow "pytest allowed"
```

### Force passthrough

The `force passthrough` action in global rules produces a passthrough that **skips local rule evaluation entirely**. Use this when you want passthrough behavior that projects cannot override:

```
command /^curl\b/ arg /^(-X|--request)$/ -> force passthrough "Write curl needs review"
```

---

## Audit Logging

When `audit_level` is set, permiter appends JSON lines to `audit_file`:

```json
{"timestamp":"2026-01-01T12:00:00Z","tool":"Bash","field":"command","check_string":"rm -rf /","cwd":"/home/user/project","decision":"deny","reason":"rm is not allowed","table":"shell_scrutiny","rule_index":0,"source":"global"}
```

| Level     | What is logged |
|-----------|----------------|
| `off`     | Nothing |
| `matched` | Every rule match (allow or deny decisions) |
| `all`     | Everything including passthrough decisions |

---

## Quick-Start Example

```
let safe_cmds = /^(ls|pwd|echo|cat|grep|find)\b/
let dev_dir = /^\/home\/user\/dev\/.*/

audit file "/tmp/permiter-audit.json" level matched

table input default deny {
    Bash command $safe_cmds -> allow "Safe read-only commands"
    Bash -> forward shell_scrutiny
    Read file_path $dev_dir -> allow "Dev reads allowed"
    Write file_path $dev_dir -> allow "Dev writes allowed"
    Edit file_path $dev_dir -> allow "Dev edits allowed"
}

table shell_scrutiny default passthrough {
    command /^rm\b/ -> deny "rm is not allowed"
    command /^(sudo|su)\b/ -> deny "Privilege escalation not allowed"
    command /^(sh|bash|zsh)\b/ -> evaluate flag -c
    command /^timeout\b/ -> evaluate skip 1
    command /^(git|gh)\b/ -> allow "Version control allowed"
    command /^(mkdir|touch|cp|mv|ln)\b/ -> allow "File operations allowed"
}
```

## A note on security
The goal of this tool is to make the permissions systems more flexible.  You can create very restrictive or very permissive rulesets.  Be aware that this does not attempt evaluate everything that be happening in a complex command, the analysis is fairly superficial and purposely obfuscated commands could well slip through.  Evaluate your use case and follow best practices concerning AI agents and code.  This tool is provided as is and makes not guarantees about security, use at your own risk.

## License

[MIT](LICENSE)
