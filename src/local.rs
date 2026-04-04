use crate::config::{RegexCache, RuleConfig};
use anyhow::Result;
use regex::Regex;
use std::path::{Path, PathBuf};

/// A set of local rules loaded from a .permiter directory.
#[derive(Debug, Clone)]
pub struct LocalRuleSet {
    /// The .permiter directory these rules were loaded from.
    pub source_dir: PathBuf,
    /// Flat list of rules (allow/deny/passthrough only).
    pub rules: Vec<RuleConfig>,
    /// Pre-compiled regex cache for these rules.
    pub regex_cache: RegexCache,
}

/// Walk from `start_dir` up to the nearest git root, looking for `.permiter/` directories.
/// Returns the first one found (closest to cwd), or None.
pub fn discover_local_dir(start_dir: &Path) -> Option<PathBuf> {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join(".permiter");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if dir.join(".git").exists() {
            return None;
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Load all *.perm files from a .permiter directory, returning a LocalRuleSet.
/// Rules are parsed with restrictions: no tables, no forward, no evaluate, no force passthrough.
pub fn load_local_rules(permiter_dir: &Path) -> Result<LocalRuleSet> {
    let mut perm_files: Vec<PathBuf> = std::fs::read_dir(permiter_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("perm"))
        .collect();
    perm_files.sort();

    let mut all_rules = Vec::new();
    for file in &perm_files {
        let content = std::fs::read_to_string(file)?;
        let rules = crate::dsl::parse_local_rules(&content, file)?;
        all_rules.extend(rules);
    }

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
    for rule in &all_rules {
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

    Ok(LocalRuleSet {
        source_dir: permiter_dir.to_path_buf(),
        rules: all_rules,
        regex_cache: cache,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_discover_local_dir_found() {
        let tmp = std::env::temp_dir().join("permiter_test_discover");
        let project = tmp.join("myproject");
        let permiter_dir = project.join(".permiter");
        fs::create_dir_all(&permiter_dir).unwrap();
        fs::create_dir_all(project.join(".git")).unwrap();
        let result = discover_local_dir(&project);
        assert_eq!(result, Some(permiter_dir));
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_discover_local_dir_stops_at_git_root() {
        let tmp = std::env::temp_dir().join("permiter_test_git_root");
        let project = tmp.join("myproject");
        let subdir = project.join("src/deep");
        fs::create_dir_all(&subdir).unwrap();
        fs::create_dir_all(project.join(".git")).unwrap();
        fs::create_dir_all(tmp.join(".permiter")).unwrap();
        let result = discover_local_dir(&subdir);
        assert_eq!(result, None);
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_discover_local_dir_none() {
        let result = discover_local_dir(Path::new("/tmp/nonexistent_permiter_test_dir"));
        assert_eq!(result, None);
    }

    // ── load_local_rules tests (Task 10) ────────────────────────────────────

    #[test]
    fn test_load_local_rules() {
        let tmp = std::env::temp_dir().join("permiter_test_load");
        let permiter_dir = tmp.join(".permiter");
        fs::create_dir_all(&permiter_dir).unwrap();

        fs::write(
            permiter_dir.join("python.perm"),
            r#"Bash command /^pip\b/ -> allow "pip allowed""#,
        )
        .unwrap();
        fs::write(
            permiter_dir.join("node.perm"),
            r#"Bash command /^npm\b/ -> allow "npm allowed""#,
        )
        .unwrap();

        let ruleset = load_local_rules(&permiter_dir).unwrap();
        assert_eq!(ruleset.rules.len(), 2); // node.perm sorts before python.perm
        assert_eq!(ruleset.source_dir, permiter_dir);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_load_local_rules_rejects_bad_file() {
        let tmp = std::env::temp_dir().join("permiter_test_load_bad");
        let permiter_dir = tmp.join(".permiter");
        fs::create_dir_all(&permiter_dir).unwrap();
        fs::write(
            permiter_dir.join("evil.perm"),
            "table sneaky default allow {\n    Bash -> allow\n}\n",
        )
        .unwrap();
        assert!(load_local_rules(&permiter_dir).is_err());
        fs::remove_dir_all(&tmp).unwrap();
    }
}
