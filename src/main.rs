use anyhow::Result;
use clap::{Parser, Subcommand};
use permiter::config::Config;
use permiter::engine::{evaluate_with_local, Decision};
use permiter::hook_io::{HookInput, HookOutput};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "permiter", version, about = "iptables-style Claude PreToolUse hook")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Hook mode: read HookInput from stdin, write HookOutput to stdout
    Run {
        /// Path to config file
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Validate config and print table/rule counts
    Validate {
        /// Path to config file
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Test a specific tool input against the config
    Check {
        /// Path to config file
        #[arg(short, long)]
        config: PathBuf,
        /// Tool name (e.g. Bash, Read, Write)
        #[arg(long)]
        tool: String,
        /// Command string (for Bash tool)
        #[arg(long)]
        command: Option<String>,
        /// File path (for Read/Write/Edit/Glob tools)
        #[arg(long)]
        file_path: Option<String>,
        /// Working directory for path resolution
        #[arg(long, default_value = ".")]
        cwd: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Command::Run { config } => {
            let config = Config::load(&config)?;
            let input = HookInput::read_from_stdin()?;
            let cwd = std::path::Path::new(&input.cwd);

            let local_rules = if config.global.local_rules {
                permiter::local::discover_local_dir(cwd).and_then(|dir| {
                    match permiter::local::load_local_rules(&dir) {
                        Ok(rules) => Some(rules),
                        Err(e) => {
                            eprintln!("permiter: warning: failed to load local rules from {}: {e}", dir.display());
                            None
                        }
                    }
                })
            } else {
                None
            };

            let result = evaluate_with_local(
                &config, &input.tool_name, &input.tool_input, cwd, local_rules.as_ref(),
            )?;

            match result.decision {
                Decision::Allow => {
                    let reason = result.reason.unwrap_or_else(|| "Allowed".to_string());
                    HookOutput::allow(reason).write_to_stdout()?;
                }
                Decision::Deny => {
                    let reason = result.reason.unwrap_or_else(|| "Denied".to_string());
                    HookOutput::deny(reason).write_to_stdout()?;
                }
                Decision::Passthrough | Decision::ForcePassthrough => {
                    // Write nothing — exit 0, Claude decides
                }
            }
        }

        Command::Validate { config } => {
            let config = Config::load(&config)?;
            println!("Config valid.");
            if config.global.local_rules {
                println!("Local rules: enabled");
            } else {
                println!("Local rules: disabled");
            }
            println!("{}", config.summary());
        }

        Command::Check {
            config,
            tool,
            command,
            file_path,
            cwd,
        } => {
            let config = Config::load(&config)?;

            let tool_input = match tool.as_str() {
                "Bash" => serde_json::json!({
                    "command": command.unwrap_or_default()
                }),
                "Read" | "Write" | "Edit" | "MultiEdit" | "Glob" => serde_json::json!({
                    "file_path": file_path.unwrap_or_default()
                }),
                _ => serde_json::Value::Object(serde_json::Map::new()),
            };

            let cwd = if cwd == PathBuf::from(".") {
                std::env::current_dir()?
            } else {
                cwd
            };

            let local_rules = if config.global.local_rules {
                permiter::local::discover_local_dir(&cwd).and_then(|dir| {
                    match permiter::local::load_local_rules(&dir) {
                        Ok(rules) => Some(rules),
                        Err(e) => {
                            eprintln!("permiter: warning: failed to load local rules from {}: {e}", dir.display());
                            None
                        }
                    }
                })
            } else {
                None
            };

            let result = evaluate_with_local(&config, &tool, &tool_input, &cwd, local_rules.as_ref())?;

            let decision_str = match &result.decision {
                Decision::Allow => "ALLOW",
                Decision::Deny => "DENY",
                Decision::Passthrough => "PASSTHROUGH",
                Decision::ForcePassthrough => "FORCE PASSTHROUGH",
            };

            println!("Decision: {}", decision_str);
            if let Some(reason) = &result.reason {
                println!("Reason: {}", reason);
            }
            if let Some(table) = &result.table {
                print!("Table: {}", table);
                if let Some(idx) = result.rule_index {
                    print!(", Rule: {}", idx);
                }
                println!();
            }
            println!("Source: {}", result.source);

            // Exit with non-zero if denied, for scripting convenience
            if result.decision == Decision::Deny {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
