use crate::config::{
    Action, AuditConfig, AuditLevel, Config, GlobalConfig, RuleConfig, TableConfig,
};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::Path;

// ── Token ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Keywords
    Let,
    Table,
    Default,
    Opts,
    Skip,
    Flag,
    Evaluate,
    Forward,
    Allow,
    Deny,
    Passthrough,
    Force,
    Entry,
    Audit,
    // Symbols
    Arrow,   // → or ->
    LBrace,  // {
    RBrace,  // }
    LBracket, // [
    RBracket, // ]
    Comma,   // ,
    Bang,    // !
    Equals,  // =
    // Literals
    Regex(String),     // /pattern/ or r"pattern"
    Str(String),       // "string"
    VarRef(String),    // $name
    Ident(String),     // bare word
    FlagLit(String),   // -c, -u, -vvv, etc.
    Number(usize),     // integer
    // Structure
    Newline,
}

#[derive(Debug, Clone)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone)]
pub struct SpannedToken {
    pub token: Token,
    pub span: Span,
}

// ── Lexer ────────────────────────────────────────────────────────────────────

pub fn lex(input: &str) -> Result<Vec<SpannedToken>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut pos = 0;
    let mut line = 1;
    let mut col = 1;

    while pos < chars.len() {
        let c = chars[pos];

        // Skip whitespace (not newlines)
        if c == ' ' || c == '\t' || c == '\r' {
            pos += 1;
            col += 1;
            continue;
        }

        // Comments
        if c == '#' {
            while pos < chars.len() && chars[pos] != '\n' {
                pos += 1;
            }
            continue;
        }

        // Newlines
        if c == '\n' {
            // Collapse consecutive newlines into one token
            if tokens.last().map_or(true, |t: &SpannedToken| t.token != Token::Newline) {
                tokens.push(SpannedToken {
                    token: Token::Newline,
                    span: Span { line, col },
                });
            }
            pos += 1;
            line += 1;
            col = 1;
            continue;
        }

        let start_col = col;

        // Arrow: → or ->
        if c == '\u{2192}' {
            tokens.push(SpannedToken {
                token: Token::Arrow,
                span: Span { line, col: start_col },
            });
            pos += 1;
            col += 1;
            continue;
        }
        if c == '-' && pos + 1 < chars.len() && chars[pos + 1] == '>' {
            tokens.push(SpannedToken {
                token: Token::Arrow,
                span: Span { line, col: start_col },
            });
            pos += 2;
            col += 2;
            continue;
        }

        // Flag literal: -[a-zA-Z0-9]+
        if c == '-' && pos + 1 < chars.len() && chars[pos + 1].is_alphanumeric() {
            let start = pos;
            pos += 1;
            col += 1;
            while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '-' || chars[pos] == '_') {
                pos += 1;
                col += 1;
            }
            let flag: String = chars[start..pos].iter().collect();
            tokens.push(SpannedToken {
                token: Token::FlagLit(flag),
                span: Span { line, col: start_col },
            });
            continue;
        }

        // Symbols
        match c {
            '{' => { tokens.push(SpannedToken { token: Token::LBrace, span: Span { line, col: start_col } }); pos += 1; col += 1; continue; }
            '}' => { tokens.push(SpannedToken { token: Token::RBrace, span: Span { line, col: start_col } }); pos += 1; col += 1; continue; }
            '[' => { tokens.push(SpannedToken { token: Token::LBracket, span: Span { line, col: start_col } }); pos += 1; col += 1; continue; }
            ']' => { tokens.push(SpannedToken { token: Token::RBracket, span: Span { line, col: start_col } }); pos += 1; col += 1; continue; }
            ',' => { tokens.push(SpannedToken { token: Token::Comma, span: Span { line, col: start_col } }); pos += 1; col += 1; continue; }
            '!' => { tokens.push(SpannedToken { token: Token::Bang, span: Span { line, col: start_col } }); pos += 1; col += 1; continue; }
            '=' => { tokens.push(SpannedToken { token: Token::Equals, span: Span { line, col: start_col } }); pos += 1; col += 1; continue; }
            _ => {}
        }

        // Regex literal: /pattern/
        if c == '/' {
            pos += 1;
            col += 1;
            let mut pattern = String::new();
            while pos < chars.len() && chars[pos] != '/' {
                if chars[pos] == '\\' && pos + 1 < chars.len() {
                    pattern.push(chars[pos]);
                    pattern.push(chars[pos + 1]);
                    pos += 2;
                    col += 2;
                } else {
                    pattern.push(chars[pos]);
                    pos += 1;
                    col += 1;
                }
            }
            if pos >= chars.len() {
                bail!("Unterminated regex at line {line}, col {start_col}");
            }
            pos += 1; // closing /
            col += 1;
            tokens.push(SpannedToken {
                token: Token::Regex(pattern),
                span: Span { line, col: start_col },
            });
            continue;
        }

        // Raw string regex: r"pattern"
        if c == 'r' && pos + 1 < chars.len() && chars[pos + 1] == '"' {
            pos += 2;
            col += 2;
            let mut pattern = String::new();
            while pos < chars.len() && chars[pos] != '"' {
                pattern.push(chars[pos]);
                pos += 1;
                col += 1;
            }
            if pos >= chars.len() {
                bail!("Unterminated raw string at line {line}, col {start_col}");
            }
            pos += 1;
            col += 1;
            tokens.push(SpannedToken {
                token: Token::Regex(pattern),
                span: Span { line, col: start_col },
            });
            continue;
        }

        // Quoted string: "string"
        if c == '"' {
            pos += 1;
            col += 1;
            let mut s = String::new();
            while pos < chars.len() && chars[pos] != '"' {
                if chars[pos] == '\\' && pos + 1 < chars.len() {
                    match chars[pos + 1] {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        other => { s.push('\\'); s.push(other); }
                    }
                    pos += 2;
                    col += 2;
                } else {
                    s.push(chars[pos]);
                    pos += 1;
                    col += 1;
                }
            }
            if pos >= chars.len() {
                bail!("Unterminated string at line {line}, col {start_col}");
            }
            pos += 1;
            col += 1;
            tokens.push(SpannedToken {
                token: Token::Str(s),
                span: Span { line, col: start_col },
            });
            continue;
        }

        // Variable reference: $name
        if c == '$' {
            pos += 1;
            col += 1;
            let start = pos;
            while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '_') {
                pos += 1;
                col += 1;
            }
            if pos == start {
                bail!("Empty variable reference at line {line}, col {start_col}");
            }
            let name: String = chars[start..pos].iter().collect();
            tokens.push(SpannedToken {
                token: Token::VarRef(name),
                span: Span { line, col: start_col },
            });
            continue;
        }

        // Number
        if c.is_ascii_digit() {
            let start = pos;
            while pos < chars.len() && chars[pos].is_ascii_digit() {
                pos += 1;
                col += 1;
            }
            let num_str: String = chars[start..pos].iter().collect();
            let num: usize = num_str.parse().map_err(|_| {
                anyhow::anyhow!("Invalid number '{}' at line {line}, col {start_col}", num_str)
            })?;
            tokens.push(SpannedToken {
                token: Token::Number(num),
                span: Span { line, col: start_col },
            });
            continue;
        }

        // Identifier or keyword
        if c.is_alphabetic() || c == '_' {
            let start = pos;
            while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '_') {
                pos += 1;
                col += 1;
            }
            let word: String = chars[start..pos].iter().collect();
            let token = match word.as_str() {
                "let" => Token::Let,
                "table" => Token::Table,
                "default" => Token::Default,
                "opts" => Token::Opts,
                "skip" => Token::Skip,
                "flag" => Token::Flag,
                "evaluate" => Token::Evaluate,
                "forward" => Token::Forward,
                "allow" => Token::Allow,
                "deny" => Token::Deny,
                "passthrough" => Token::Passthrough,
                "force" => Token::Force,
                "entry" => Token::Entry,
                "audit" => Token::Audit,
                _ => Token::Ident(word),
            };
            tokens.push(SpannedToken {
                token,
                span: Span { line, col: start_col },
            });
            continue;
        }

        bail!("Unexpected character '{}' at line {line}, col {col}", c);
    }

    Ok(tokens)
}

// ── Parser ───────────────────────────────────────────────────────────────────

pub struct Parser {
    tokens: Vec<SpannedToken>,
    pos: usize,
    variables: HashMap<String, String>,
}

impl Parser {
    pub fn new(tokens: Vec<SpannedToken>) -> Self {
        Parser {
            tokens,
            pos: 0,
            variables: HashMap::new(),
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|t| &t.token)
    }

    fn span(&self) -> Span {
        self.tokens
            .get(self.pos)
            .map(|t| t.span.clone())
            .unwrap_or(Span { line: 0, col: 0 })
    }

    fn advance(&mut self) -> Option<&Token> {
        let t = self.tokens.get(self.pos).map(|t| &t.token);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        let span = self.span();
        match self.advance() {
            Some(t) if t == expected => Ok(()),
            Some(t) => bail!(
                "Expected {:?}, got {:?} at line {}, col {}",
                expected, t, span.line, span.col
            ),
            None => bail!(
                "Expected {:?}, got end of input at line {}, col {}",
                expected, span.line, span.col
            ),
        }
    }

    fn expect_ident(&mut self) -> Result<String> {
        let span = self.span();
        match self.advance().cloned() {
            Some(Token::Ident(s)) => Ok(s),
            Some(t) => bail!("Expected identifier, got {:?} at line {}, col {}", t, span.line, span.col),
            None => bail!("Expected identifier, got end of input at line {}, col {}", span.line, span.col),
        }
    }

    fn skip_newlines(&mut self) {
        while self.peek() == Some(&Token::Newline) {
            self.advance();
        }
    }

    /// Parse a pattern: /regex/, r"regex", or $varref
    fn parse_pattern(&mut self) -> Result<String> {
        let span = self.span();
        match self.advance().cloned() {
            Some(Token::Regex(s)) => Ok(s),
            Some(Token::VarRef(name)) => {
                self.variables.get(&name).cloned().ok_or_else(|| {
                    anyhow::anyhow!("Unknown variable '${name}' at line {}, col {}", span.line, span.col)
                })
            }
            Some(t) => bail!("Expected pattern (regex or $var), got {:?} at line {}, col {}", t, span.line, span.col),
            None => bail!("Expected pattern, got end of input at line {}, col {}", span.line, span.col),
        }
    }

    /// Parse an action keyword for table defaults (allow, deny, passthrough, force passthrough)
    fn parse_default_action(&mut self) -> Result<Action> {
        let span = self.span();
        match self.advance() {
            Some(Token::Allow) => Ok(Action::Allow),
            Some(Token::Deny) => Ok(Action::Deny),
            Some(Token::Passthrough) => Ok(Action::Passthrough),
            Some(Token::Force) => {
                match self.advance() {
                    Some(Token::Passthrough) => Ok(Action::ForcePassthrough),
                    Some(t) => bail!("Expected 'passthrough' after 'force', got {:?} at line {}, col {}", t, span.line, span.col),
                    None => bail!("Expected 'passthrough' after 'force', got end of input"),
                }
            }
            Some(t) => bail!("Expected action (allow/deny/passthrough/force passthrough), got {:?} at line {}, col {}", t, span.line, span.col),
            None => bail!("Expected action, got end of input at line {}, col {}", span.line, span.col),
        }
    }

    pub fn parse(&mut self) -> Result<Config> {
        let mut config = Config {
            global: GlobalConfig::default(),
            audit: AuditConfig::default(),
            constants: HashMap::new(),
            table: HashMap::new(),
            regex_cache: Default::default(),
        };

        self.skip_newlines();

        while self.pos < self.tokens.len() {
            match self.peek() {
                Some(Token::Let) => self.parse_let()?,
                Some(Token::Table) => {
                    let (name, table) = self.parse_table()?;
                    config.table.insert(name, table);
                }
                Some(Token::Entry) => {
                    self.advance(); // entry
                    let name = self.expect_ident()?;
                    config.global.entry_table = name;
                }
                Some(Token::Audit) => {
                    self.parse_audit(&mut config.audit)?;
                }
                Some(Token::Ident(s)) if s == "local_rules" => {
                    self.advance();
                    if self.peek() == Some(&Token::Equals) {
                        self.advance();
                    }
                    let span = self.span();
                    match self.peek() {
                        Some(Token::Ident(v)) if v == "true" => {
                            self.advance();
                            config.global.local_rules = true;
                        }
                        Some(Token::Ident(v)) if v == "false" => {
                            self.advance();
                            config.global.local_rules = false;
                        }
                        Some(t) => bail!("Expected 'true' or 'false' after local_rules, got {:?} at line {}, col {}", t, span.line, span.col),
                        None => bail!("Expected 'true' or 'false' at line {}, col {}", span.line, span.col),
                    }
                }
                Some(Token::Newline) => { self.advance(); }
                Some(t) => {
                    let span = self.span();
                    bail!("Unexpected token {:?} at top level, line {}, col {}", t, span.line, span.col);
                }
                None => break,
            }
        }

        // Copy variables to constants for validation
        config.constants = self.variables.clone();

        Ok(config)
    }

    fn parse_let(&mut self) -> Result<()> {
        self.advance(); // let
        let name = self.expect_ident()?;
        self.expect(&Token::Equals)?;
        let pattern = self.parse_pattern()?;
        self.variables.insert(name, pattern);
        Ok(())
    }

    fn parse_audit(&mut self, audit: &mut AuditConfig) -> Result<()> {
        self.advance(); // audit
        let span = self.span();
        // audit file "path" level matched|all|off
        // or audit level matched|all|off
        // or audit file "path"
        loop {
            match self.peek() {
                Some(Token::Newline) | None => break,
                Some(Token::Ident(s)) if s == "file" => {
                    self.advance();
                    let span = self.span();
                    match self.advance().cloned() {
                        Some(Token::Str(path)) => audit.audit_file = Some(path),
                        Some(t) => bail!("Expected file path string, got {:?} at line {}, col {}", t, span.line, span.col),
                        None => bail!("Expected file path string at line {}, col {}", span.line, span.col),
                    }
                }
                Some(Token::Ident(s)) if s == "level" => {
                    self.advance();
                    let span = self.span();
                    match self.advance().cloned() {
                        Some(Token::Ident(s)) => {
                            audit.audit_level = match s.as_str() {
                                "off" => AuditLevel::Off,
                                "matched" => AuditLevel::Matched,
                                "all" => AuditLevel::All,
                                _ => bail!("Unknown audit level '{}' at line {}, col {}", s, span.line, span.col),
                            };
                        }
                        Some(t) => bail!("Expected audit level, got {:?} at line {}, col {}", t, span.line, span.col),
                        None => bail!("Expected audit level at line {}, col {}", span.line, span.col),
                    }
                }
                Some(t) => {
                    bail!("Unexpected token {:?} in audit at line {}, col {}", t, span.line, span.col);
                }
            }
        }
        Ok(())
    }

    fn parse_table(&mut self) -> Result<(String, TableConfig)> {
        self.advance(); // table
        let name = self.expect_ident()?;
        self.expect(&Token::Default)?;
        let default = self.parse_default_action()?;
        self.expect(&Token::LBrace)?;
        self.skip_newlines();

        let mut rules = Vec::new();

        while self.peek() != Some(&Token::RBrace) && self.pos < self.tokens.len() {
            let rule = self.parse_rule()?;
            rules.push(rule);
            self.skip_newlines();
        }

        self.expect(&Token::RBrace)?;

        Ok((name, TableConfig { default, rules }))
    }

    fn parse_rule(&mut self) -> Result<RuleConfig> {
        let mut rule = RuleConfig {
            tool: None,
            command: None,
            file_path: None,
            subagent_type: None,
            prompt: None,
            cwd: None,
            arg: None,
            arg_not: None,
            stdin: None,
            stdin_not: None,
            stdout: None,
            stdout_not: None,
            cwd_not: None,
            env: None,
            env_not: None,
            has_file: None,
            has_file_not: None,
            action: Action::Deny, // placeholder
            reason: None,
            target: None,
            flag_arg: None,
            positional: None,
            opts_with_args: Vec::new(),
        };

        // Check if first token is a tool name (bare ident that's not a condition keyword)
        if let Some(Token::Ident(word)) = self.peek() {
            if !is_condition_keyword(word) {
                let tool = word.clone();
                self.advance();
                rule.tool = Some(format!("^{}$", regex::escape(&tool)));
            }
        }

        // Parse conditions until we hit →
        loop {
            match self.peek() {
                Some(Token::Arrow) => break,
                Some(Token::Newline) | None => {
                    bail!("Expected → in rule at line {}, col {}", self.span().line, self.span().col);
                }
                Some(Token::Bang) => {
                    self.advance(); // !
                    let (field, _negated) = self.parse_condition_field()?;
                    if field == "has_file" {
                        let path = self.expect_string()?;
                        self.set_condition(&mut rule, &field, path, true)?;
                    } else {
                        let pattern = self.parse_pattern()?;
                        self.set_condition(&mut rule, &field, pattern, true)?;
                    }
                }
                _ => {
                    let (field, _negated) = self.parse_condition_field()?;
                    if field == "has_file" {
                        let path = self.expect_string()?;
                        self.set_condition(&mut rule, &field, path, false)?;
                    } else {
                        let pattern = self.parse_pattern()?;
                        self.set_condition(&mut rule, &field, pattern, false)?;
                    }
                }
            }
        }

        self.expect(&Token::Arrow)?;

        // Parse action
        let span = self.span();
        match self.peek() {
            Some(Token::Allow) => { self.advance(); rule.action = Action::Allow; }
            Some(Token::Deny) => { self.advance(); rule.action = Action::Deny; }
            Some(Token::Passthrough) => { self.advance(); rule.action = Action::Passthrough; }
            Some(Token::Forward) => {
                self.advance();
                rule.action = Action::Forward;
                rule.target = Some(self.expect_ident()?);
            }
            Some(Token::Force) => {
                self.advance();
                let span = self.span();
                match self.peek() {
                    Some(Token::Passthrough) => { self.advance(); rule.action = Action::ForcePassthrough; }
                    Some(t) => bail!("Expected 'passthrough' after 'force', got {:?} at line {}, col {}", t, span.line, span.col),
                    None => bail!("Expected 'passthrough' after 'force' at line {}, col {}", span.line, span.col),
                }
            }
            Some(Token::Evaluate) => {
                self.advance();
                rule.action = Action::Evaluate;
                // Optional target table name (ident, not a keyword like flag/skip/opts)
                if let Some(Token::Ident(name)) = self.peek() {
                    if !matches!(name.as_str(), "flag" | "skip" | "opts") {
                        rule.target = Some(name.clone());
                        self.advance();
                    }
                }
                // Parse evaluate params
                self.parse_evaluate_params(&mut rule)?;
            }
            Some(t) => bail!("Expected action, got {:?} at line {}, col {}", t, span.line, span.col),
            None => bail!("Expected action at line {}, col {}", span.line, span.col),
        }

        // Optional reason string
        if let Some(Token::Str(_)) = self.peek() {
            if let Some(Token::Str(s)) = self.advance().cloned() {
                rule.reason = Some(s);
            }
        }

        Ok(rule)
    }

    fn parse_condition_field(&mut self) -> Result<(String, bool)> {
        let span = self.span();
        match self.advance().cloned() {
            Some(Token::Ident(s)) if is_condition_keyword(&s) => Ok((s, false)),
            Some(t) => bail!("Expected condition keyword, got {:?} at line {}, col {}", t, span.line, span.col),
            None => bail!("Expected condition keyword at line {}, col {}", span.line, span.col),
        }
    }

    fn expect_string(&mut self) -> Result<String> {
        let span = self.span();
        match self.advance().cloned() {
            Some(Token::Str(s)) => Ok(s),
            Some(t) => bail!("Expected quoted string, got {:?} at line {}, col {}", t, span.line, span.col),
            None => bail!("Expected quoted string, got end of input at line {}, col {}", span.line, span.col),
        }
    }

    fn set_condition(&self, rule: &mut RuleConfig, field: &str, pattern: String, negated: bool) -> Result<()> {
        match (field, negated) {
            ("tool", false) => rule.tool = Some(pattern),
            ("command", false) => rule.command = Some(pattern),
            ("file_path", false) => rule.file_path = Some(pattern),
            ("subagent_type", false) => rule.subagent_type = Some(pattern),
            ("prompt", false) => rule.prompt = Some(pattern),
            ("cwd", false) => rule.cwd = Some(pattern),
            ("cwd", true) => rule.cwd_not = Some(pattern),
            ("arg", false) => rule.arg = Some(pattern),
            ("arg", true) => rule.arg_not = Some(pattern),
            ("stdin", false) => rule.stdin = Some(pattern),
            ("stdin", true) => rule.stdin_not = Some(pattern),
            ("stdout", false) => rule.stdout = Some(pattern),
            ("stdout", true) => rule.stdout_not = Some(pattern),
            ("env", false) => rule.env = Some(pattern),
            ("env", true) => rule.env_not = Some(pattern),
            ("has_file", false) => rule.has_file = Some(pattern),
            ("has_file", true) => rule.has_file_not = Some(pattern),
            (f, true) => bail!("Negation not supported for condition '{f}'"),
            (f, _) => bail!("Unknown condition field '{f}'"),
        }
        Ok(())
    }

    fn parse_evaluate_params(&mut self, rule: &mut RuleConfig) -> Result<()> {
        loop {
            match self.peek() {
                Some(Token::Flag) => {
                    self.advance();
                    let span = self.span();
                    match self.advance().cloned() {
                        Some(Token::FlagLit(f)) => rule.flag_arg = Some(f),
                        Some(t) => bail!("Expected flag literal after 'flag', got {:?} at line {}, col {}", t, span.line, span.col),
                        None => bail!("Expected flag literal at line {}, col {}", span.line, span.col),
                    }
                }
                Some(Token::Skip) => {
                    self.advance();
                    let span = self.span();
                    match self.advance().cloned() {
                        Some(Token::Number(n)) => rule.positional = Some(n),
                        Some(t) => bail!("Expected number after 'skip', got {:?} at line {}, col {}", t, span.line, span.col),
                        None => bail!("Expected number at line {}, col {}", span.line, span.col),
                    }
                }
                Some(Token::Opts) => {
                    self.advance();
                    self.expect(&Token::LBracket)?;
                    let mut opts = Vec::new();
                    loop {
                        match self.peek() {
                            Some(Token::RBracket) => { self.advance(); break; }
                            Some(Token::Comma) => { self.advance(); }
                            Some(Token::FlagLit(_)) => {
                                if let Some(Token::FlagLit(f)) = self.advance().cloned() {
                                    opts.push(f);
                                }
                            }
                            Some(t) => {
                                let span = self.span();
                                bail!("Expected flag or ']' in opts, got {:?} at line {}, col {}", t, span.line, span.col);
                            }
                            None => bail!("Unterminated opts list"),
                        }
                    }
                    rule.opts_with_args = opts;
                }
                _ => break,
            }
        }
        Ok(())
    }
}

fn is_condition_keyword(word: &str) -> bool {
    matches!(
        word,
        "tool" | "command" | "file_path" | "subagent_type" | "prompt"
            | "cwd" | "arg" | "stdin" | "stdout" | "env" | "has_file"
    )
}

/// Parse a DSL string into a Config.
pub fn parse_dsl(input: &str) -> Result<Config> {
    let tokens = lex(input)?;
    let mut parser = Parser::new(tokens);
    let mut config = parser.parse()?;
    config.validate()?;
    config.compile_regexes()?;
    Ok(config)
}

/// Parse a local rules file. Only flat rules allowed — no tables, no entry, no audit,
/// no forward, no evaluate, no force passthrough. Variables (let) ARE allowed.
pub fn parse_local_rules(input: &str, source: &Path) -> Result<Vec<RuleConfig>> {
    let tokens = lex(input)?;
    let mut parser = Parser::new(tokens);
    let mut rules = Vec::new();

    parser.skip_newlines();

    while parser.pos < parser.tokens.len() {
        match parser.peek() {
            Some(Token::Let) => parser.parse_let()?,
            Some(Token::Newline) => {
                parser.advance();
            }
            Some(Token::Table) | Some(Token::Entry) | Some(Token::Audit) => {
                let span = parser.span();
                let keyword = match parser.peek() {
                    Some(Token::Table) => "table",
                    Some(Token::Entry) => "entry",
                    Some(Token::Audit) => "audit",
                    _ => "unknown",
                };
                bail!(
                    "Local rules file {} cannot contain '{}' directives (line {}, col {})",
                    source.display(),
                    keyword,
                    span.line,
                    span.col
                );
            }
            None => break,
            _ => {
                let rule = parser.parse_rule()?;
                match &rule.action {
                    Action::Allow | Action::Deny | Action::Passthrough => {}
                    Action::Forward => bail!(
                        "Local rules file {} cannot use 'forward' action",
                        source.display()
                    ),
                    Action::Evaluate => bail!(
                        "Local rules file {} cannot use 'evaluate' action",
                        source.display()
                    ),
                    Action::ForcePassthrough => bail!(
                        "Local rules file {} cannot use 'force passthrough' action",
                        source.display()
                    ),
                }
                // Validate has_file paths in local rules — no absolute paths or traversal
                if let Some(path) = &rule.has_file {
                    if path.starts_with('/') || path.contains("..") {
                        bail!(
                            "Local rules file {}: has_file must be a relative path without '..', got '{}'",
                            source.display(), path
                        );
                    }
                }
                if let Some(path) = &rule.has_file_not {
                    if path.starts_with('/') || path.contains("..") {
                        bail!(
                            "Local rules file {}: has_file_not must be a relative path without '..', got '{}'",
                            source.display(), path
                        );
                    }
                }
                rules.push(rule);
                parser.skip_newlines();
            }
        }
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lex_basic() {
        let tokens = lex("let x = /^foo$/").unwrap();
        let kinds: Vec<&Token> = tokens.iter().map(|t| &t.token).collect();
        assert_eq!(kinds, vec![
            &Token::Let,
            &Token::Ident("x".into()),
            &Token::Equals,
            &Token::Regex("^foo$".into()),
        ]);
    }

    #[test]
    fn test_lex_arrow_unicode() {
        let tokens = lex("→").unwrap();
        assert_eq!(tokens[0].token, Token::Arrow);
    }

    #[test]
    fn test_lex_arrow_ascii() {
        let tokens = lex("->").unwrap();
        assert_eq!(tokens[0].token, Token::Arrow);
    }

    #[test]
    fn test_lex_flag_lit() {
        let tokens = lex("-c -vvv -p").unwrap();
        let kinds: Vec<&Token> = tokens.iter().map(|t| &t.token).collect();
        assert_eq!(kinds, vec![
            &Token::FlagLit("-c".into()),
            &Token::FlagLit("-vvv".into()),
            &Token::FlagLit("-p".into()),
        ]);
    }

    #[test]
    fn test_lex_var_ref() {
        let tokens = lex("$my_var").unwrap();
        assert_eq!(tokens[0].token, Token::VarRef("my_var".into()));
    }

    #[test]
    fn test_lex_raw_string() {
        let tokens = lex(r#"r"^foo\bbar""#).unwrap();
        assert_eq!(tokens[0].token, Token::Regex(r"^foo\bbar".into()));
    }

    #[test]
    fn test_lex_quoted_string() {
        let tokens = lex(r#""hello world""#).unwrap();
        assert_eq!(tokens[0].token, Token::Str("hello world".into()));
    }

    #[test]
    fn test_lex_comment_skipped() {
        let tokens = lex("allow # this is a comment\ndeny").unwrap();
        let kinds: Vec<&Token> = tokens.iter().map(|t| &t.token).collect();
        assert_eq!(kinds, vec![&Token::Allow, &Token::Newline, &Token::Deny]);
    }

    #[test]
    fn test_lex_opts_list() {
        let tokens = lex("[-i, -p, -o]").unwrap();
        let kinds: Vec<&Token> = tokens.iter().map(|t| &t.token).collect();
        assert_eq!(kinds, vec![
            &Token::LBracket,
            &Token::FlagLit("-i".into()),
            &Token::Comma,
            &Token::FlagLit("-p".into()),
            &Token::Comma,
            &Token::FlagLit("-o".into()),
            &Token::RBracket,
        ]);
    }

    #[test]
    fn test_parse_minimal_config() {
        let config = parse_dsl(r#"
table input default deny {
    command /^ls\b/ → allow "safe"
}
"#).unwrap();
        assert_eq!(config.global.entry_table, "input");
        assert_eq!(config.table["input"].rules.len(), 1);
        assert_eq!(config.table["input"].rules[0].command.as_deref(), Some(r"^ls\b"));
        assert_eq!(config.table["input"].rules[0].action, Action::Allow);
        assert_eq!(config.table["input"].rules[0].reason.as_deref(), Some("safe"));
    }

    #[test]
    fn test_parse_let_and_varref() {
        let config = parse_dsl(r#"
let safe = /^(ls|pwd)\b/
table input default deny {
    command $safe → allow
}
"#).unwrap();
        assert_eq!(
            config.table["input"].rules[0].command.as_deref(),
            Some(r"^(ls|pwd)\b")
        );
    }

    #[test]
    fn test_parse_tool_shorthand() {
        let config = parse_dsl(r#"
table input default deny {
    Bash command /^ls/ → allow
    Read file_path /^\/home/ → allow
}
"#).unwrap();
        assert_eq!(config.table["input"].rules[0].tool.as_deref(), Some("^Bash$"));
        assert_eq!(config.table["input"].rules[1].tool.as_deref(), Some("^Read$"));
    }

    #[test]
    fn test_parse_negation() {
        let config = parse_dsl(r#"
table input default deny {
    command /^curl\b/ !arg /evil\.com/ → allow
}
"#).unwrap();
        assert_eq!(config.table["input"].rules[0].arg_not.as_deref(), Some(r"evil\.com"));
    }

    #[test]
    fn test_parse_forward() {
        let config = parse_dsl(r#"
table input default deny {
    Bash → forward scrutiny
}
table scrutiny default deny {
    command /^ls/ → allow
}
"#).unwrap();
        assert_eq!(config.table["input"].rules[0].action, Action::Forward);
        assert_eq!(config.table["input"].rules[0].target.as_deref(), Some("scrutiny"));
    }

    #[test]
    fn test_parse_evaluate_flag() {
        let config = parse_dsl(r#"
table input default deny {
    command /^sh\b/ → evaluate flag -c
}
"#).unwrap();
        let rule = &config.table["input"].rules[0];
        assert_eq!(rule.action, Action::Evaluate);
        assert_eq!(rule.flag_arg.as_deref(), Some("-c"));
        assert!(rule.target.is_none());
    }

    #[test]
    fn test_parse_evaluate_with_target_and_opts() {
        let config = parse_dsl(r#"
table input default deny {
    command /^ssh\b/ → evaluate remote_cmds opts [-i, -p, -o] skip 1
}
table remote_cmds default deny {
    command /^ls/ → allow
}
"#).unwrap();
        let rule = &config.table["input"].rules[0];
        assert_eq!(rule.action, Action::Evaluate);
        assert_eq!(rule.target.as_deref(), Some("remote_cmds"));
        assert_eq!(rule.opts_with_args, vec!["-i", "-p", "-o"]);
        assert_eq!(rule.positional, Some(1));
    }

    #[test]
    fn test_parse_evaluate_recycle() {
        let config = parse_dsl(r#"
table input default deny {
    command /^sudo\b/ → evaluate opts [-u, -g]
}
"#).unwrap();
        let rule = &config.table["input"].rules[0];
        assert_eq!(rule.action, Action::Evaluate);
        assert!(rule.target.is_none()); // recycle = no target
        assert_eq!(rule.opts_with_args, vec!["-u", "-g"]);
    }

    #[test]
    fn test_parse_entry_directive() {
        let config = parse_dsl(r#"
entry main
table main default allow {
}
"#).unwrap();
        assert_eq!(config.global.entry_table, "main");
    }

    #[test]
    fn test_parse_audit() {
        let config = parse_dsl(r#"
audit file "/tmp/audit.json" level matched
table input default allow {
}
"#).unwrap();
        assert_eq!(config.audit.audit_file.as_deref(), Some("/tmp/audit.json"));
        assert_eq!(config.audit.audit_level, AuditLevel::Matched);
    }

    #[test]
    fn test_parse_ascii_arrow() {
        let config = parse_dsl(r#"
table input default deny {
    command /^ls/ -> allow
}
"#).unwrap();
        assert_eq!(config.table["input"].rules[0].action, Action::Allow);
    }

    #[test]
    fn test_parse_full_example() {
        let config = parse_dsl(r#"
let safe_cmds = /^(ls|pwd|echo|cat)\b/
let dev_dir = /^\/home\/user\/dev\/.*/

audit file "/tmp/permiter-audit.json" level matched

table input default deny {
    Bash command $safe_cmds → allow "Safe read-only commands"
    Bash → forward shell_scrutiny
    Read file_path $dev_dir → allow "Dev reads"
    Write file_path $dev_dir → allow "Dev writes"
}

table shell_scrutiny default deny {
    command /^rm\b/ → deny "rm not allowed"
    command /^(sudo|su)\b/ → deny "No privilege escalation"

    # Wrapper evaluate rules
    command /^(sh|bash|zsh)\b/ → evaluate flag -c
    command /^timeout\b/ → evaluate skip 1

    command /^(cargo|git)\b/ → allow "Dev tools"
}
"#).unwrap();
        assert_eq!(config.table.len(), 2);
        assert_eq!(config.table["input"].rules.len(), 4);
        assert_eq!(config.table["shell_scrutiny"].rules.len(), 5);
    }

    #[test]
    fn test_parse_raw_string_regex() {
        let config = parse_dsl(r#"
table input default deny {
    command r"^ls\b" → allow
}
"#).unwrap();
        assert_eq!(config.table["input"].rules[0].command.as_deref(), Some(r"^ls\b"));
    }

    #[test]
    fn test_parse_multiple_conditions() {
        let config = parse_dsl(r#"
table input default deny {
    command /^curl\b/ arg /^https:/ !arg /evil\.com/ cwd /^\/home/ → allow
}
"#).unwrap();
        let rule = &config.table["input"].rules[0];
        assert_eq!(rule.command.as_deref(), Some(r"^curl\b"));
        assert_eq!(rule.arg.as_deref(), Some("^https:"));
        assert_eq!(rule.arg_not.as_deref(), Some(r"evil\.com"));
        assert_eq!(rule.cwd.as_deref(), Some(r"^\/home"));
    }

    #[test]
    fn test_force_passthrough_allowed_as_default() {
        let config = parse_dsl(r#"
table input default force passthrough {
    command /^ls/ -> allow
}
"#).unwrap();
        assert_eq!(config.table["input"].default, Action::ForcePassthrough);
    }

    #[test]
    fn test_parse_force_passthrough() {
        let config = parse_dsl(r#"
table input default deny {
    Bash command /^ls\b/ -> force passthrough "safe read-only"
}
"#).unwrap();
        let rule = &config.table["input"].rules[0];
        assert_eq!(rule.action, Action::ForcePassthrough);
        assert_eq!(rule.reason.as_deref(), Some("safe read-only"));
    }

    #[test]
    fn test_unknown_variable_errors() {
        let result = parse_dsl(r#"
table input default deny {
    command $undefined → allow
}
"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_has_file_condition() {
        let input = r#"
entry input
table input default passthrough {
    Bash command /^pip\b/ has_file ".venv/bin/pip" -> allow "pip in venv"
}
"#;
        let config = parse_dsl(input).unwrap();
        let rule = &config.table["input"].rules[0];
        assert_eq!(rule.has_file.as_deref(), Some(".venv/bin/pip"));
        assert_eq!(rule.action, Action::Allow);
    }

    #[test]
    fn test_parse_has_file_not_condition() {
        let input = r#"
entry input
table input default passthrough {
    Bash command /^npm\b/ !has_file "node_modules/.bin/npm" -> deny "no local npm"
}
"#;
        let config = parse_dsl(input).unwrap();
        let rule = &config.table["input"].rules[0];
        assert_eq!(rule.has_file_not.as_deref(), Some("node_modules/.bin/npm"));
    }

    // ── parse_local_rules tests ─────────────────────────────────────────────

    #[test]
    fn test_parse_local_rules_basic() {
        let input = r#"
Bash command /^\.venv\/bin\/(pip|python)/ -> allow "venv pip/python"
Bash command /^pip\b/ has_file ".venv/bin/pip" -> allow "pip (venv exists)"
"#;
        let rules = parse_local_rules(input, Path::new(".permiter/python.perm")).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].action, Action::Allow);
        assert_eq!(rules[1].has_file.as_deref(), Some(".venv/bin/pip"));
    }

    #[test]
    fn test_parse_local_rules_rejects_table() {
        let input = r#"
table foo default deny {
    Bash -> allow
}
"#;
        assert!(parse_local_rules(input, Path::new(".permiter/bad.perm")).is_err());
    }

    #[test]
    fn test_parse_local_rules_rejects_forward() {
        let input = "Bash -> forward some_table\n";
        assert!(parse_local_rules(input, Path::new(".permiter/bad.perm")).is_err());
    }

    #[test]
    fn test_parse_local_rules_rejects_evaluate() {
        let input = "command /^sudo/ -> evaluate flag -c\n";
        assert!(parse_local_rules(input, Path::new(".permiter/bad.perm")).is_err());
    }

    #[test]
    fn test_parse_local_rules_rejects_force_passthrough() {
        let input = r#"Bash command /^rm/ -> force passthrough "nope""#;
        assert!(parse_local_rules(input, Path::new(".permiter/bad.perm")).is_err());
    }

    #[test]
    fn test_parse_local_rules_rejects_has_file_traversal() {
        let input = r#"Bash has_file "../../.ssh/id_rsa" -> allow "sneaky""#;
        assert!(parse_local_rules(input, Path::new(".permiter/bad.perm")).is_err());
    }

    #[test]
    fn test_parse_local_rules_rejects_has_file_absolute() {
        let input = r#"Bash has_file "/etc/passwd" -> allow "sneaky""#;
        assert!(parse_local_rules(input, Path::new(".permiter/bad.perm")).is_err());
    }

    #[test]
    fn test_parse_local_rules_allows_deny() {
        let input = r#"Bash command /^rm/ -> deny "no rm in this project""#;
        let rules = parse_local_rules(input, Path::new(".permiter/strict.perm")).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, Action::Deny);
    }

    #[test]
    fn test_parse_local_rules_allows_let() {
        let input = r#"
let venv = /^\.venv\/bin\//
Bash command $venv -> allow "venv commands"
"#;
        let rules = parse_local_rules(input, Path::new(".permiter/python.perm")).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_parse_local_rules_directive() {
        let input = r#"
local_rules = true
entry input
table input default deny {
    Bash -> allow
}
"#;
        let config = parse_dsl(input).unwrap();
        assert!(config.global.local_rules);
    }

    #[test]
    fn test_local_rules_default_false() {
        let input = r#"
entry input
table input default deny {
    Bash -> allow
}
"#;
        let config = parse_dsl(input).unwrap();
        assert!(!config.global.local_rules);
    }
}
