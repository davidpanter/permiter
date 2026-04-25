# contrib/

Copy-pasteable rule snippets for common workflows. These are **not**
standalone configs — they're fragments meant to be lifted into your
own `permiter.perm` (typically `~/.config/permiter.perm`).

Each file has a header comment with:
- What it does
- Where it goes (which table, or top-level)
- Variables it expects you to define (or that it defines)

## Files

| File | What |
|------|------|
| [injection-guards.perm](injection-guards.perm) | Newline-in-arg, sudo, ssh denies — defensive baseline |
| [shell-wrappers.perm](shell-wrappers.perm) | `evaluate` rules for `sh -c`, `timeout`, `xargs`, `nice`, `env`… |
| [git-safe.perm](git-safe.perm) | Read-only git subcommands + a `git_worktree` sub-table |
| [kubectl-readonly.perm](kubectl-readonly.perm) | Allow `kubectl get/describe/logs/...`, passthrough mutations |
| [scripting-venv.perm](scripting-venv.perm) | Allow `pip`/`python`/`npm`/`node`/`bun` only when project venv/lockfile is present |
| [curl-restricted.perm](curl-restricted.perm) | Allow `curl` only to localhost or read-only GitHub API |
| [systemctl-readonly.perm](systemctl-readonly.perm) | Allow `systemctl status/show/list-*`, passthrough mutations |
| [mcp-common-allowlist.perm](mcp-common-allowlist.perm) | Allow popular read-only MCP servers by tool-name prefix |

## How to combine

A typical config layout:

```
# top-level
let home = /^\/home\/you(\/.*)?$/
audit file "/tmp/claude-tool-use.json" level matched

# (paste injection-guard let-vars here, if any)

table input default passthrough {
    Bash -> forward bash_commands
    # (paste mcp-common-allowlist rules here)
}

table bash_commands default passthrough {
    # (paste injection-guards rules first — denies must come early)
    # (paste shell-wrappers rules)
    # (paste git-safe, kubectl-readonly, etc.)
    # (paste curl-restricted, systemctl-readonly)
    command /^(pip3?|python3?|npm|npx|node|bun|tsx?)\b/ -> forward scripting_languages
}

# (paste git_worktree table from git-safe.perm)
# (paste scripting_languages table from scripting-venv.perm)
```

After editing, validate:

```sh
permiter validate -c ~/.config/permiter.perm
```

And spot-check rules:

```sh
permiter check -c ~/.config/permiter.perm --tool Bash --command "git status"
```
