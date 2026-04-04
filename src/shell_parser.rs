use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedCommand {
    pub program: String,
    pub args: Vec<String>,
    pub effective_cwd: PathBuf,
    pub raw: String,
    /// Targets of `<` redirections
    pub redirects_in: Vec<String>,
    /// Targets of `>` and `>>` redirections
    pub redirects_out: Vec<String>,
    /// Inline `VAR=value` assignments from the command prefix (e.g. `FOO=bar curl …`)
    pub env_vars: Vec<String>,
}

impl ParsedCommand {
    /// Returns the full check string: "program arg1 arg2 ..."
    /// For bare assignment statements (program is empty), returns the raw text.
    /// Command-substitution placeholders (`$()` and `` `...` ``) are stripped
    /// from args; the inner commands are emitted as separate ParsedCommands.
    pub fn check_string(&self) -> String {
        if self.program.is_empty() {
            return self.raw.trim().to_string();
        }
        let cleaned: Vec<String> = self.args.iter()
            .map(|a| a.replace("$()", "").replace("`...`", ""))
            .filter(|a| !a.is_empty())
            .collect();
        if cleaned.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, cleaned.join(" "))
        }
    }
}

/// Tokenize a shell command string into a list of ParsedCommand structs.
/// Tracks effective_cwd across `cd` commands, handles operators, subshells,
/// command groups, and command substitutions.
pub fn parse_commands(input: &str, cwd: &Path) -> Vec<ParsedCommand> {
    // Collapse line continuations before parsing: `\<newline>` is whitespace in shell
    let normalized = input.replace("\\\n", " ");
    let mut parser = Parser::new(&normalized, cwd.to_path_buf());
    parser.parse();
    parser.commands
}

struct Parser {
    input: Vec<char>,
    pos: usize,
    cwd: PathBuf,
    commands: Vec<ParsedCommand>,
}

impl Parser {
    fn new(input: &str, cwd: PathBuf) -> Self {
        Parser {
            input: input.chars().collect(),
            pos: 0,
            cwd,
            commands: Vec::new(),
        }
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn peek2(&self) -> Option<char> {
        self.input.get(self.pos + 1).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.input.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn parse(&mut self) {
        self.parse_command_list(false);
    }

    /// Parse a sequence of commands separated by ; && || | newline
    /// Returns true if we consumed a closing delimiter (} or ) or backtick end)
    fn parse_command_list(&mut self, in_subshell: bool) {
        loop {
            self.skip_whitespace_and_newlines();

            if self.pos >= self.input.len() {
                break;
            }

            // Check for closing delimiters
            if let Some(c) = self.peek() {
                if in_subshell && (c == ')' || c == '}') {
                    break;
                }
            }

            // Skip empty statements
            if let Some(';') | Some('\n') = self.peek() {
                self.advance();
                continue;
            }

            // Check for heredoc (<<)
            // We handle it by parsing the command then skipping the heredoc body

            let before = self.pos;
            self.parse_single_command();

            // After a command, consume operators
            self.skip_whitespace();
            if let Some(c) = self.peek() {
                match c {
                    ';' | '\n' => {
                        self.advance();
                    }
                    '&' => {
                        self.advance(); // first &
                        if self.peek() == Some('&') {
                            self.advance(); // second &
                        }
                    }
                    '|' => {
                        self.advance(); // first |
                        if self.peek() == Some('|') {
                            self.advance(); // second |
                        }
                    }
                    ')' | '}' if in_subshell => break,
                    _ => {
                        // Safety: if parse_single_command didn't advance (e.g. stray
                        // `)` or `}` at top level), skip the character to prevent
                        // an infinite loop.
                        if self.pos == before {
                            self.advance();
                        }
                    }
                }
            }
        }
    }

    fn skip_whitespace_and_newlines(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn parse_single_command(&mut self) {
        self.skip_whitespace();

        if self.pos >= self.input.len() {
            return;
        }

        // Check for subshell (...)
        if self.peek() == Some('(') {
            self.parse_subshell();
            return;
        }

        // Check for command group { ... }
        if self.peek() == Some('{') {
            self.parse_command_group();
            return;
        }

        // Parse a simple command (possibly with pipes inline handled by caller)
        let start_pos = self.pos;
        let cwd = self.cwd.clone();
        let mut words: Vec<String> = Vec::new();
        let mut redirects_in: Vec<String> = Vec::new();
        let mut redirects_out: Vec<String> = Vec::new();

        loop {
            self.skip_whitespace();
            match self.peek() {
                None | Some(';') | Some('\n') => break,
                Some('&') => {
                    // && or & (background)
                    break;
                }
                Some('|') => {
                    // | or ||
                    break;
                }
                Some(')') | Some('}') => break,
                Some('<') => {
                    // Redirect or heredoc
                    self.advance();
                    if self.peek() == Some('<') {
                        self.advance();
                        // heredoc: capture delimiter but don't treat body as commands
                        let delim = self.read_word();
                        self.skip_heredoc(&delim);
                        break;
                    } else if self.peek() == Some('&') {
                        // <&N — fd-to-fd input redirect; consume and ignore
                        self.advance(); // &
                        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                            self.advance();
                        }
                    } else {
                        self.skip_whitespace();
                        let target = self.read_word();
                        if !target.is_empty() {
                            redirects_in.push(target);
                        }
                    }
                }
                Some('>') => {
                    self.advance();
                    let append = self.peek() == Some('>');
                    if append {
                        self.advance(); // >>
                    }
                    if !append && self.peek() == Some('&') {
                        // >&N — fd-to-fd output redirect; consume and ignore
                        self.advance(); // &
                        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                            self.advance();
                        }
                    } else {
                        self.skip_whitespace();
                        let target = self.read_word();
                        if !target.is_empty() {
                            redirects_out.push(target);
                        }
                    }
                }
                Some(_) => {
                    let word = self.read_word();
                    if !word.is_empty() {
                        // If the word is purely digits and the next char is > or <,
                        // it's an fd number prefix for a redirect — don't treat as an arg.
                        let is_fd_prefix = word.chars().all(|c| c.is_ascii_digit())
                            && matches!(self.peek(), Some('>') | Some('<'));
                        if !is_fd_prefix {
                            words.push(word);
                        }
                    }
                }
            }
        }

        if words.is_empty() {
            return;
        }

        // Reconstruct raw from input slice
        let raw: String = self.input[start_pos..self.pos].iter().collect();
        let raw = raw.trim().to_string();

        // Strip leading variable assignments (VAR=value) and assignment builtins
        // (export/local/declare/typeset/readonly) that don't execute external commands.
        // Any $(...) inside these has already been parsed and emitted above.
        //
        // Captured assignments are stored in `env_vars` as "VAR=value" strings so
        // that rule matching can inspect them via the `env` field.
        //
        // in_assignment_builtin tracks whether we've seen export/local/etc so that
        // bare identifiers (e.g. `export FOO`) and flags (e.g. `declare -x`) are
        // also stripped rather than mistaken for commands.
        let mut cmd_words = words.as_slice();
        let mut env_vars: Vec<String> = Vec::new();
        let mut in_assignment_builtin = false;
        loop {
            match cmd_words.first().map(|s| s.as_str()) {
                None => break,
                // Shell assignment builtins
                Some("export" | "local" | "declare" | "typeset" | "readonly") => {
                    in_assignment_builtin = true;
                    cmd_words = &cmd_words[1..];
                }
                // Flags on assignment builtins (e.g. declare -x, local -i)
                Some(w) if w.starts_with('-') => {
                    if in_assignment_builtin {
                        cmd_words = &cmd_words[1..];
                    } else {
                        break;
                    }
                }
                Some(w) => {
                    if let Some(eq_pos) = w.find('=') {
                        // VAR=value — capture and strip if VAR is a valid identifier
                        let before = &w[..eq_pos];
                        if before.chars().all(|c| c.is_alphanumeric() || c == '_') {
                            // Normalise: strip any $() placeholder from the value side
                            let value_part = &w[eq_pos + 1..];
                            let clean_val = value_part
                                .replace("$()", "")
                                .replace("`...`", "");
                            env_vars.push(format!("{}={}", before, clean_val));
                            cmd_words = &cmd_words[1..];
                            continue;
                        }
                    } else if in_assignment_builtin
                        && w.chars().all(|c| c.is_alphanumeric() || c == '_')
                    {
                        // Bare identifier after an assignment builtin (e.g. `export FOO`)
                        // — it's a variable name with no value, capture as "FOO="
                        env_vars.push(format!("{}=", w));
                        cmd_words = &cmd_words[1..];
                        continue;
                    }
                    break;
                }
            }
        }

        // Bare assignment statement (no real command after stripping):
        // emit a synthetic ParsedCommand so `env` rules can match against it.
        // check_string() will use `raw` for `command` pattern matching.
        if cmd_words.is_empty() {
            if env_vars.is_empty() {
                return; // truly empty (e.g. just `cd`)
            }
            self.commands.push(ParsedCommand {
                program: String::new(),
                args: vec![],
                effective_cwd: cwd,
                raw,
                redirects_in,
                redirects_out,
                env_vars,
            });
            return;
        }

        let program = cmd_words[0].clone();
        let args: Vec<String> = cmd_words[1..].to_vec();

        // Handle cd specially to update cwd
        if program == "cd" {
            let new_dir = args.first().map(|s| s.as_str()).unwrap_or("~");
            self.cwd = resolve_path(&self.cwd, new_dir);
            // Don't emit a ParsedCommand for cd itself — it's a shell builtin
            // that we track but don't evaluate against rules
            return;
        }

        self.commands.push(ParsedCommand {
            program,
            args,
            effective_cwd: cwd,
            raw,
            redirects_in,
            redirects_out,
            env_vars,
        });
    }

    fn parse_subshell(&mut self) {
        // ( ... ) — fork cwd, changes don't propagate back
        assert_eq!(self.advance(), Some('('));
        let saved_cwd = self.cwd.clone();
        self.parse_command_list(true);
        if self.peek() == Some(')') {
            self.advance();
        }
        self.cwd = saved_cwd;
    }

    fn parse_command_group(&mut self) {
        // { ... } — same shell context, cwd changes propagate
        assert_eq!(self.advance(), Some('{'));
        self.parse_command_list(true);
        if self.peek() == Some('}') {
            self.advance();
        }
        // cwd changes from group propagate to caller (already updated self.cwd)
    }

    /// Read a single word, handling quotes and command substitutions
    fn read_word(&mut self) -> String {
        let mut result = String::new();

        loop {
            match self.peek() {
                None => break,
                Some(' ') | Some('\t') | Some('\n') | Some(';') | Some('&') | Some('|')
                | Some(')') | Some('}') | Some('>') | Some('<') => break,
                Some('\'') => {
                    self.advance();
                    // Single-quoted: literal until closing '
                    loop {
                        match self.advance() {
                            None | Some('\'') => break,
                            Some(c) => result.push(c),
                        }
                    }
                }
                Some('"') => {
                    self.advance();
                    // Double-quoted: handle $() and `` inside
                    loop {
                        match self.peek() {
                            None => break,
                            Some('"') => {
                                self.advance();
                                break;
                            }
                            Some('$') if self.peek2() == Some('(') => {
                                self.advance(); // $
                                self.advance(); // (
                                // Parse inner commands
                                let saved_cwd = self.cwd.clone();
                                self.parse_command_list(true);
                                if self.peek() == Some(')') {
                                    self.advance();
                                }
                                self.cwd = saved_cwd;
                            }
                            Some('`') => {
                                self.advance();
                                let saved_cwd = self.cwd.clone();
                                self.parse_backtick();
                                self.cwd = saved_cwd;
                            }
                            Some(c) => {
                                self.advance();
                                result.push(c);
                            }
                        }
                    }
                }
                Some('$') if self.peek2() == Some('(') => {
                    self.advance(); // $
                    self.advance(); // (
                    // Command substitution: parse inner commands (subshell semantics)
                    let saved_cwd = self.cwd.clone();
                    self.parse_command_list(true);
                    if self.peek() == Some(')') {
                        self.advance();
                    }
                    self.cwd = saved_cwd;
                    result.push_str("$()");
                }
                Some('`') => {
                    self.advance();
                    let saved_cwd = self.cwd.clone();
                    self.parse_backtick();
                    self.cwd = saved_cwd;
                    result.push_str("`...`");
                }
                Some(c) => {
                    self.advance();
                    result.push(c);
                }
            }
        }

        result
    }

    fn parse_backtick(&mut self) {
        // Parse until closing backtick
        loop {
            match self.peek() {
                None => break,
                Some('`') => {
                    self.advance();
                    break;
                }
                Some('$') if self.peek2() == Some('(') => {
                    self.advance();
                    self.advance();
                    self.parse_command_list(true);
                    if self.peek() == Some(')') {
                        self.advance();
                    }
                }
                _ => {
                    // Parse commands inside backtick
                    let before = self.pos;
                    self.parse_single_command();
                    // Safety: if nothing advanced, skip the character to prevent infinite loop
                    if self.pos == before {
                        self.advance();
                    }
                }
            }
        }
    }

    fn skip_heredoc(&mut self, delimiter: &str) {
        // Skip until we find a line that is exactly `delimiter`
        let delimiter = delimiter.trim_matches(|c: char| c == '\'' || c == '"');
        loop {
            // Read a line
            let mut line = String::new();
            loop {
                match self.advance() {
                    None => return,
                    Some('\n') => break,
                    Some(c) => line.push(c),
                }
            }
            if line.trim() == delimiter {
                return;
            }
        }
    }
}

/// Resolve a path relative to cwd. Handles ~, ., ..
fn resolve_path(cwd: &Path, path: &str) -> PathBuf {
    if path == "~" || path.starts_with("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        if path == "~" {
            PathBuf::from(home)
        } else {
            PathBuf::from(home).join(&path[2..])
        }
    } else if path.starts_with('/') {
        PathBuf::from(path)
    } else {
        normalize_path(&cwd.join(path))
    }
}

/// Normalize path (remove . and .. components without hitting filesystem)
fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn parse(input: &str) -> Vec<ParsedCommand> {
        parse_commands(input, Path::new("/home/user"))
    }

    fn parse_from(input: &str, cwd: &str) -> Vec<ParsedCommand> {
        parse_commands(input, Path::new(cwd))
    }

    fn programs(cmds: &[ParsedCommand]) -> Vec<&str> {
        cmds.iter().map(|c| c.program.as_str()).collect()
    }

    fn cmd_cwd<'a>(cmds: &'a [ParsedCommand], program: &str) -> &'a Path {
        cmds.iter()
            .find(|c| c.program == program)
            .unwrap_or_else(|| panic!("no command '{program}'"))
            .effective_cwd
            .as_path()
    }

    // ── Basic parsing ────────────────────────────────────────────────────────

    #[test]
    fn test_simple_command() {
        let cmds = parse("ls -la");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "ls");
        assert_eq!(cmds[0].args, vec!["-la"]);
        assert_eq!(cmds[0].effective_cwd, Path::new("/home/user"));
    }

    #[test]
    fn test_semicolon_sequence() {
        let cmds = parse("ls; pwd; echo hello");
        assert_eq!(programs(&cmds), vec!["ls", "pwd", "echo"]);
    }

    #[test]
    fn test_and_chain() {
        let cmds = parse("cargo build && cargo test");
        assert_eq!(programs(&cmds), vec!["cargo", "cargo"]);
    }

    #[test]
    fn test_or_chain() {
        let cmds = parse("ls file || echo missing");
        assert_eq!(programs(&cmds), vec!["ls", "echo"]);
    }

    #[test]
    fn test_pipe() {
        let cmds = parse("cat file | grep pattern");
        assert_eq!(programs(&cmds), vec!["cat", "grep"]);
    }

    #[test]
    fn test_empty_input() {
        let cmds = parse("");
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_whitespace_only() {
        let cmds = parse("   \t  \n  ");
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_multiline() {
        let cmds = parse("ls\npwd\necho hello");
        assert_eq!(programs(&cmds), vec!["ls", "pwd", "echo"]);
    }

    #[test]
    fn test_check_string() {
        let cmds = parse("rm -rf /tmp/test");
        assert_eq!(cmds[0].check_string(), "rm -rf /tmp/test");
    }

    // ── stray delimiters (must not hang) ───────────────────────────────────

    #[test]
    fn test_stray_close_paren_does_not_hang() {
        let cmds = parse(")");
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_stray_close_brace_does_not_hang() {
        let cmds = parse("}");
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_stray_delimiters_after_command() {
        let cmds = parse("echo hello; )");
        assert_eq!(programs(&cmds), vec!["echo"]);
    }

    // ── fd redirection ───────────────────────────────────────────────────────

    #[test]
    fn test_fd_redirect_stderr_to_stdout() {
        // 2>&1 should not add "2" as an arg and should not add anything to redirects_out
        let cmds = parse("command 2>&1");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "command");
        assert_eq!(cmds[0].args, Vec::<String>::new());
        assert!(cmds[0].redirects_out.is_empty());
    }

    #[test]
    fn test_fd_redirect_with_file_redirect() {
        // command > file 2>&1 — file redirect is kept, fd redirect is ignored
        let cmds = parse("command > file 2>&1");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "command");
        assert_eq!(cmds[0].args, Vec::<String>::new());
        assert_eq!(cmds[0].redirects_out, vec!["file"]);
    }

    #[test]
    fn test_fd_redirect_stdout_to_fd() {
        // >&2 — redirect stdout to stderr; no file targets
        let cmds = parse("command >&2");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "command");
        assert!(cmds[0].redirects_out.is_empty());
    }

    #[test]
    fn test_fd_redirect_input() {
        // 0<&3 — fd-to-fd input redirect; no file targets
        let cmds = parse("command 0<&3");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "command");
        assert_eq!(cmds[0].args, Vec::<String>::new());
        assert!(cmds[0].redirects_in.is_empty());
    }

    #[test]
    fn test_normal_redirect_after_fd_redirect() {
        // Normal redirects still work when mixed with fd redirects
        let cmds = parse("cmd 2>&1 > out.txt");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].redirects_out, vec!["out.txt"]);
        assert_eq!(cmds[0].args, Vec::<String>::new());
    }

    #[test]
    fn test_check_string_no_args() {
        let cmds = parse("pwd");
        assert_eq!(cmds[0].check_string(), "pwd");
    }

    // ── normalize_path ───────────────────────────────────────────────────────

    #[test]
    fn test_normalize_absolute_no_dotdot() {
        assert_eq!(normalize_path(Path::new("/a/b/c")), Path::new("/a/b/c"));
    }

    #[test]
    fn test_normalize_dotdot_in_middle() {
        assert_eq!(normalize_path(Path::new("/a/b/../c")), Path::new("/a/c"));
    }

    #[test]
    fn test_normalize_multiple_dotdot() {
        assert_eq!(
            normalize_path(Path::new("/a/b/c/../../d")),
            Path::new("/a/d")
        );
    }

    #[test]
    fn test_normalize_dot_stripped() {
        assert_eq!(normalize_path(Path::new("/a/./b/./c")), Path::new("/a/b/c"));
    }

    #[test]
    fn test_normalize_dotdot_at_root_stays_root() {
        // Going above root keeps root
        assert_eq!(normalize_path(Path::new("/../..")), Path::new("/"));
    }

    #[test]
    fn test_normalize_trailing_slash_irrelevant() {
        // PathBuf ignores trailing slash in joins
        assert_eq!(normalize_path(Path::new("/a/b/")), Path::new("/a/b"));
    }

    // ── resolve_path ─────────────────────────────────────────────────────────

    #[test]
    fn test_resolve_absolute_path() {
        let cwd = Path::new("/home/user");
        assert_eq!(resolve_path(cwd, "/etc/hosts"), Path::new("/etc/hosts"));
    }

    #[test]
    fn test_resolve_relative_path() {
        let cwd = Path::new("/home/user");
        assert_eq!(
            resolve_path(cwd, "projects"),
            Path::new("/home/user/projects")
        );
    }

    #[test]
    fn test_resolve_dotdot() {
        let cwd = Path::new("/home/user");
        assert_eq!(resolve_path(cwd, ".."), Path::new("/home"));
    }

    #[test]
    fn test_resolve_dot() {
        let cwd = Path::new("/home/user");
        assert_eq!(resolve_path(cwd, "."), Path::new("/home/user"));
    }

    #[test]
    fn test_resolve_relative_with_dotdot() {
        let cwd = Path::new("/home/user");
        assert_eq!(
            resolve_path(cwd, "../other"),
            Path::new("/home/other")
        );
    }

    #[test]
    fn test_resolve_tilde_alone() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let cwd = Path::new("/tmp");
        assert_eq!(resolve_path(cwd, "~"), PathBuf::from(&home));
    }

    #[test]
    fn test_resolve_tilde_subdir() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let cwd = Path::new("/tmp");
        assert_eq!(
            resolve_path(cwd, "~/projects"),
            PathBuf::from(home).join("projects")
        );
    }

    #[test]
    fn test_resolve_absolute_ignores_cwd() {
        // Absolute path should completely ignore the cwd
        let cwd = Path::new("/some/deep/directory");
        assert_eq!(resolve_path(cwd, "/var/log"), Path::new("/var/log"));
    }

    // ── cd tracking ──────────────────────────────────────────────────────────

    #[test]
    fn test_cd_absolute() {
        let cmds = parse("cd /tmp; ls");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/tmp"));
    }

    #[test]
    fn test_cd_relative() {
        let cmds = parse("cd projects; ls");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/home/user/projects"));
    }

    #[test]
    fn test_cd_parent() {
        let cmds = parse("cd ..; ls");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/home"));
    }

    #[test]
    fn test_cd_two_parents() {
        let cmds = parse_from("cd ../..; ls", "/home/user/projects");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/home"));
    }

    #[test]
    fn test_cd_dot_no_change() {
        let cmds = parse("cd .; ls");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/home/user"));
    }

    #[test]
    fn test_cd_no_arg_goes_home() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let cmds = parse("cd; ls");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new(&home));
    }

    #[test]
    fn test_cd_chained_relative_steps() {
        // Each cd is relative to the result of the previous one
        let cmds = parse_from("cd a; cd b; cd c; ls", "/root");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/root/a/b/c"));
    }

    #[test]
    fn test_cd_absolute_resets_then_relative() {
        let cmds = parse("cd /var; cd log; ls");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/var/log"));
    }

    #[test]
    fn test_cd_command_gets_correct_cwd_before_update() {
        // The command immediately before a cd sees the pre-cd cwd
        let cmds = parse("ls; cd /tmp; pwd");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/home/user"));
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/tmp"));
    }

    #[test]
    fn test_cd_tilde() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let cmds = parse("cd ~; ls");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new(&home));
    }

    #[test]
    fn test_cd_with_and_operator() {
        // cd && cmd — cd's effect should propagate even with &&
        let cmds = parse("cd /tmp && ls");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/tmp"));
    }

    // ── Subshell isolation ───────────────────────────────────────────────────

    #[test]
    fn test_subshell_cwd_not_propagated() {
        let cmds = parse("(cd /tmp; ls); pwd");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/tmp"));
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/home/user"));
    }

    #[test]
    fn test_subshell_multiple_cds_not_propagated() {
        let cmds = parse("(cd /a; cd b; ls); pwd");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/a/b"));
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/home/user"));
    }

    #[test]
    fn test_nested_subshells() {
        // Inner cd visible to inner ls, not to outer pwd
        let cmds = parse("((cd /inner; ls); pwd)");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/inner"));
        // pwd is in the outer subshell which also doesn't propagate, but its
        // cwd is /home/user (the outer subshell inherited it unchanged)
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/home/user"));
    }

    #[test]
    fn test_subshell_after_group_inherits_group_cwd() {
        // Group changes propagate; subsequent subshell inherits that cwd
        let cmds = parse("{ cd /tmp; }; (ls)");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/tmp"));
    }

    // ── Command group propagation ────────────────────────────────────────────

    #[test]
    fn test_command_group_cwd_propagated() {
        let cmds = parse("{ cd /tmp; ls; }; pwd");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/tmp"));
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/tmp"));
    }

    #[test]
    fn test_command_group_nested() {
        let cmds = parse("{ cd /a; { cd b; ls; }; pwd; }");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/a/b"));
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/a/b"));
    }

    #[test]
    fn test_command_group_last_cd_wins() {
        // Two cds inside a group — second one is what propagates
        let cmds = parse("{ cd /tmp; cd /var; ls; }; pwd");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/var"));
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/var"));
    }

    // ── Command substitution ─────────────────────────────────────────────────

    #[test]
    fn test_command_substitution_parses_inner() {
        let cmds = parse("echo $(ls /tmp)");
        assert!(cmds.iter().any(|c| c.program == "ls"));
        assert!(cmds.iter().any(|c| c.program == "echo"));
    }

    #[test]
    fn test_command_substitution_cd_does_not_propagate() {
        // cd inside $() is subshell — outer cwd unchanged
        let cmds = parse("echo $(cd /tmp; cat file); pwd");
        assert_eq!(cmd_cwd(&cmds, "cat"), Path::new("/tmp"));
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/home/user"));
    }

    #[test]
    fn test_nested_command_substitution() {
        let cmds = parse("echo $(echo $(ls /nested))");
        assert!(cmds.iter().any(|c| c.program == "ls"));
        // All echos accounted for
        let echo_count = cmds.iter().filter(|c| c.program == "echo").count();
        assert_eq!(echo_count, 2);
    }

    #[test]
    fn test_command_substitution_in_double_quotes() {
        let cmds = parse(r#"echo "result: $(date)""#);
        assert!(cmds.iter().any(|c| c.program == "date"));
        assert!(cmds.iter().any(|c| c.program == "echo"));
    }

    #[test]
    fn test_backtick_substitution_parses_inner() {
        let cmds = parse("echo `ls /tmp`");
        assert!(cmds.iter().any(|c| c.program == "ls"));
        assert!(cmds.iter().any(|c| c.program == "echo"));
    }

    #[test]
    fn test_single_quoted_dollar_paren_is_literal() {
        // Inside single quotes, $() is not a substitution — no inner commands
        let cmds = parse("echo '$(rm -rf /)'");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
        // rm must NOT appear
        assert!(!cmds.iter().any(|c| c.program == "rm"));
    }

    // ── Pipeline cwd ─────────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_all_commands_share_cwd() {
        let cmds = parse("cd /tmp && cat file | grep pattern | wc -l");
        // All of cat, grep, wc should see /tmp
        for cmd in &cmds {
            assert_eq!(
                cmd.effective_cwd,
                Path::new("/tmp"),
                "{} should see /tmp",
                cmd.program
            );
        }
    }

    #[test]
    fn test_pipeline_count() {
        let cmds = parse("cat a | grep b | sort | uniq -c | wc -l");
        assert_eq!(programs(&cmds), vec!["cat", "grep", "sort", "uniq", "wc"]);
    }

    // ── Redirects ────────────────────────────────────────────────────────────

    #[test]
    fn test_output_redirect_not_parsed_as_command() {
        let cmds = parse("ls > /tmp/out.txt");
        assert_eq!(programs(&cmds), vec!["ls"]);
    }

    #[test]
    fn test_append_redirect_not_parsed_as_command() {
        let cmds = parse("echo hello >> /tmp/log.txt");
        assert_eq!(programs(&cmds), vec!["echo"]);
    }

    #[test]
    fn test_input_redirect_not_parsed_as_command() {
        let cmds = parse("cat < /tmp/input.txt");
        assert_eq!(programs(&cmds), vec!["cat"]);
    }

    #[test]
    fn test_redirect_with_pipe() {
        let cmds = parse("cat < input.txt | grep foo > output.txt");
        assert_eq!(programs(&cmds), vec!["cat", "grep"]);
    }

    #[test]
    fn test_stdout_redirect_captured() {
        let cmds = parse("echo hello > /tmp/out.txt");
        assert_eq!(cmds[0].redirects_out, vec!["/tmp/out.txt"]);
        assert!(cmds[0].redirects_in.is_empty());
    }

    #[test]
    fn test_stdout_append_redirect_captured() {
        let cmds = parse("echo hello >> /tmp/log.txt");
        assert_eq!(cmds[0].redirects_out, vec!["/tmp/log.txt"]);
    }

    #[test]
    fn test_stdin_redirect_captured() {
        let cmds = parse("cat < /etc/hosts");
        assert_eq!(cmds[0].redirects_in, vec!["/etc/hosts"]);
        assert!(cmds[0].redirects_out.is_empty());
    }

    #[test]
    fn test_multiple_redirects_captured() {
        // Both stdin and stdout on the same command
        let cmds = parse("sort < /tmp/input.txt > /tmp/output.txt");
        assert_eq!(cmds[0].redirects_in, vec!["/tmp/input.txt"]);
        assert_eq!(cmds[0].redirects_out, vec!["/tmp/output.txt"]);
    }

    #[test]
    fn test_redirect_captured_per_command_in_pipeline() {
        let cmds = parse("cat < input.txt | grep foo > output.txt");
        let cat = cmds.iter().find(|c| c.program == "cat").unwrap();
        let grep = cmds.iter().find(|c| c.program == "grep").unwrap();
        assert_eq!(cat.redirects_in, vec!["input.txt"]);
        assert!(cat.redirects_out.is_empty());
        assert_eq!(grep.redirects_out, vec!["output.txt"]);
        assert!(grep.redirects_in.is_empty());
    }

    #[test]
    fn test_no_redirect_fields_empty() {
        let cmds = parse("ls -la");
        assert!(cmds[0].redirects_in.is_empty());
        assert!(cmds[0].redirects_out.is_empty());
    }

    // ── Heredoc ──────────────────────────────────────────────────────────────

    #[test]
    fn test_heredoc_body_not_parsed() {
        // The rm inside the heredoc body must not be extracted as a command
        let cmds = parse("cat <<EOF\nrm -rf /\nEOF\necho done");
        assert!(!cmds.iter().any(|c| c.program == "rm"));
        assert!(cmds.iter().any(|c| c.program == "echo"));
    }

    #[test]
    fn test_heredoc_only_outer_command_parsed() {
        let cmds = parse("cat <<END\nhello world\nEND");
        assert_eq!(programs(&cmds), vec!["cat"]);
    }

    // ── Variable assignments and builtins ─────────────────────────────────────

    #[test]
    fn test_variable_assignment_stripped() {
        let cmds = parse("FOO=bar ls");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "ls");
    }

    #[test]
    fn test_multiple_variable_assignments_stripped() {
        let cmds = parse("A=1 B=two C=3 cargo build");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "cargo");
        assert_eq!(cmds[0].args, vec!["build"]);
    }

    #[test]
    fn test_assignment_only_emits_synthetic_command() {
        let cmds = parse("FOO=bar");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "");
        assert_eq!(cmds[0].check_string(), "FOO=bar");
        assert_eq!(cmds[0].env_vars, vec!["FOO=bar"]);
    }

    #[test]
    fn test_export_assignment_emits_synthetic_command() {
        let cmds = parse("export FOO=bar");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "");
        assert_eq!(cmds[0].check_string(), "export FOO=bar");
        assert_eq!(cmds[0].env_vars, vec!["FOO=bar"]);
    }

    #[test]
    fn test_export_multiple_assignments_emits_synthetic_command() {
        let cmds = parse("export FOO=bar BAZ=qux");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "");
        assert_eq!(cmds[0].env_vars, vec!["FOO=bar", "BAZ=qux"]);
    }

    #[test]
    fn test_export_no_value_emits_synthetic_command() {
        // export VAR (just marks existing var for export)
        let cmds = parse("export FOO");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "");
        assert_eq!(cmds[0].env_vars, vec!["FOO="]);
    }

    #[test]
    fn test_export_with_substitution_extracts_inner_command() {
        // export TEST=$(ls) — emits ls (from substitution) + synthetic assignment
        let cmds = parse("export TEST=$(ls /tmp)");
        assert!(cmds.iter().any(|c| c.program == "ls"));
        // Synthetic assignment also emitted
        assert!(cmds.iter().any(|c| c.program.is_empty()));
    }

    #[test]
    fn test_bare_assignment_with_substitution_extracts_inner_command() {
        // TEST=$(ls) — ls emitted from substitution, synthetic assignment also emitted
        let cmds = parse("TEST=$(ls /tmp)");
        assert!(cmds.iter().any(|c| c.program == "ls"));
        assert!(cmds.iter().any(|c| c.program.is_empty()));
    }

    #[test]
    fn test_declare_assignment_emits_synthetic_command() {
        let cmds = parse("declare -x FOO=bar");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "");
        assert_eq!(cmds[0].env_vars, vec!["FOO=bar"]);
    }

    #[test]
    fn test_local_assignment_emits_synthetic_command() {
        let cmds = parse("local FOO=bar");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "");
        assert_eq!(cmds[0].env_vars, vec!["FOO=bar"]);
    }

    #[test]
    fn test_readonly_assignment_emits_synthetic_command() {
        let cmds = parse("readonly FOO=bar");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "");
        assert_eq!(cmds[0].env_vars, vec!["FOO=bar"]);
    }

    #[test]
    fn test_export_then_command_not_stripped() {
        // export followed by a non-assignment word — unusual but shouldn't lose the command
        // e.g. someone writing a weird script; after stripping export we see a real command
        let cmds = parse("export; ls");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "ls");
    }

    // ── env_vars capture ─────────────────────────────────────────────────────

    #[test]
    fn test_inline_env_var_captured() {
        let cmds = parse("FOO=bar curl https://example.com");
        assert_eq!(cmds[0].program, "curl");
        assert_eq!(cmds[0].env_vars, vec!["FOO=bar"]);
    }

    #[test]
    fn test_multiple_inline_env_vars_captured() {
        let cmds = parse("A=1 B=two C=3 cargo build");
        assert_eq!(cmds[0].program, "cargo");
        assert_eq!(cmds[0].env_vars, vec!["A=1", "B=two", "C=3"]);
    }

    #[test]
    fn test_no_inline_env_vars_empty() {
        let cmds = parse("curl https://example.com");
        assert!(cmds[0].env_vars.is_empty());
    }

    #[test]
    fn test_export_assignment_captured() {
        // export FOO=bar emits no command but the assignment is attached to nothing;
        // if there's a subsequent command the env var is on the *export* half, not curl
        let cmds = parse("FOO=bar; curl https://example.com");
        // First statement (assignment only) emits nothing
        // curl has no inline env vars — the FOO=bar was a separate statement
        let curl = cmds.iter().find(|c| c.program == "curl").unwrap();
        assert!(curl.env_vars.is_empty());
    }

    #[test]
    fn test_env_var_value_with_equals() {
        // VAR=a=b — the key is VAR, value is a=b
        let cmds = parse("VAR=a=b ls");
        assert_eq!(cmds[0].env_vars, vec!["VAR=a=b"]);
    }

    // ── Quoting ──────────────────────────────────────────────────────────────

    #[test]
    fn test_single_quotes_preserve_operators() {
        let cmds = parse("echo 'hello; world'");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].args, vec!["hello; world"]);
    }

    #[test]
    fn test_single_quotes_preserve_pipe() {
        let cmds = parse("echo 'a | b'");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].args, vec!["a | b"]);
    }

    #[test]
    fn test_double_quotes_preserve_spaces() {
        let cmds = parse(r#"echo "hello world""#);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].args, vec!["hello world"]);
    }

    #[test]
    fn test_double_quotes_preserve_semicolons() {
        let cmds = parse(r#"echo "a; b; c""#);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].args, vec!["a; b; c"]);
    }

    // ── Newlines as command separators ───────────────────────────────────────

    #[test]
    fn test_newline_separates_commands() {
        // Newline outside quotes: two distinct commands, rm is evaluated
        let cmds = parse("echo \"Test\"\nrm -f something");
        assert_eq!(programs(&cmds), vec!["echo", "rm"]);
    }

    #[test]
    fn test_newline_inside_double_quotes_is_literal() {
        // Newline inside double quotes: rm is part of echo's argument, not a command
        let cmds = parse("echo \"Test\nrm -f something\"");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
        assert!(!cmds.iter().any(|c| c.program == "rm"));
    }

    #[test]
    fn test_newline_inside_single_quotes_is_literal() {
        // Same for single quotes
        let cmds = parse("echo 'Test\nrm -f something'");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
        assert!(!cmds.iter().any(|c| c.program == "rm"));
    }

    // ── Line continuations ────────────────────────────────────────────────────

    #[test]
    fn test_line_continuation_joins_command() {
        // \<newline> should be treated as whitespace — one command, not two
        let cmds = parse("curl \\\n  https://api.github.com/repos");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "curl");
        assert_eq!(cmds[0].args, vec!["https://api.github.com/repos"]);
    }

    #[test]
    fn test_line_continuation_multiple() {
        let cmds = parse("curl \\\n  -X POST \\\n  -H 'Auth: token' \\\n  https://api.github.com/");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "curl");
        assert!(cmds[0].args.contains(&"-X".to_string()));
        assert!(cmds[0].args.contains(&"POST".to_string()));
        assert!(cmds[0].args.iter().any(|a| a.contains("api.github.com")));
    }

    #[test]
    fn test_line_continuation_not_confused_with_separator() {
        // \<newline> inside a multi-command string: only the continuation joins,
        // the separate ; still splits
        let cmds = parse("echo foo \\\n  bar; ls");
        assert_eq!(programs(&cmds), vec!["echo", "ls"]);
        assert_eq!(cmds[0].args, vec!["foo", "bar"]);
    }

    #[test]
    fn test_line_continuation_check_string_for_arg_matching() {
        // The joined command should expose the URL as an arg for rule matching
        let cmds = parse("curl \\\n  -X POST \\\n  https://evil.com");
        assert_eq!(cmds[0].program, "curl");
        assert!(cmds[0].args.iter().any(|a| a == "https://evil.com"));
    }

    // ── Background operator ───────────────────────────────────────────────────

    #[test]
    fn test_background_operator_separates_commands() {
        // `cmd &` should still emit cmd; the & is consumed as a separator
        let cmds = parse("sleep 10 & echo done");
        assert!(cmds.iter().any(|c| c.program == "sleep"));
        assert!(cmds.iter().any(|c| c.program == "echo"));
    }

    // ── Mixed complex compositions ────────────────────────────────────────────

    #[test]
    fn test_cd_then_subshell_then_more() {
        // Pattern: setup cwd, subshell diverges, outer continues at setup cwd
        let cmds = parse("cd /opt; (cd /tmp; ls); pwd");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/tmp"));
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/opt"));
    }

    #[test]
    fn test_group_then_subshell_inherits_group_result() {
        // Group moves to /opt, subshell inherits /opt but its own cd doesn't leak
        let cmds = parse("{ cd /opt; }; (cd /tmp; ls); pwd");
        assert_eq!(cmd_cwd(&cmds, "ls"), Path::new("/tmp"));
        assert_eq!(cmd_cwd(&cmds, "pwd"), Path::new("/opt"));
    }

    #[test]
    fn test_subst_in_pipeline() {
        // Commands inside $() in a pipeline stage are still extracted
        let cmds = parse("cat $(find /tmp -name '*.txt') | grep foo");
        assert!(cmds.iter().any(|c| c.program == "find"));
        assert!(cmds.iter().any(|c| c.program == "cat"));
        assert!(cmds.iter().any(|c| c.program == "grep"));
    }

    #[test]
    fn test_all_operators_in_one_line() {
        // ; && || | should all be recognised as separators
        let cmds = parse("a; b && c || d | e");
        assert_eq!(programs(&cmds), vec!["a", "b", "c", "d", "e"]);
    }
    #[test]
    fn test_fd_redirect_with_and_operator() {
        // 2>&1 && echo — second command must still be parsed
        let cmds = parse(r#"tmux source-file ~/.tmux.conf 2>&1 && echo "tmux reloaded""#);
        let names: Vec<String> = cmds.iter().map(|c| c.check_string()).collect();
        assert_eq!(cmds.len(), 2, "should parse 2 commands, got: {:?}", names);
        assert_eq!(cmds[0].program, "tmux");
        assert_eq!(cmds[0].args, vec!["source-file", "~/.tmux.conf"]);
        assert_eq!(cmds[1].program, "echo");
        assert_eq!(cmds[1].args, vec!["tmux reloaded"]);
    }
}
