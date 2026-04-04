use permiter::config::Config;
use permiter::engine::evaluate;
use std::path::Path;
use std::time::Instant;

fn main() {
    let perm = include_str!("../example.perm");
    let config = permiter::dsl::parse_dsl(perm).expect("example.perm must parse");
    let cwd = Path::new("/home/user/dev/project");

    let cases: Vec<(&str, serde_json::Value)> = vec![
        // Fast path: safe command, matches first rule
        ("safe_cmd", serde_json::json!({"command": "ls -la"})),
        // Medium: forwarded to shell_scrutiny, allowed by git rule
        ("git_cmd", serde_json::json!({"command": "git status"})),
        // Medium: forwarded, denied by rm rule
        ("rm_cmd", serde_json::json!({"command": "rm -rf /tmp/test"})),
        // Slow: compound command with cd tracking
        ("compound", serde_json::json!({"command": "cd /tmp && git status && ls -la | grep foo"})),
        // Slow: evaluate rule — sh -c wrapping
        ("sh_c", serde_json::json!({"command": "sh -c 'git status'"})),
        // Non-bash: file path check
        ("read", serde_json::json!({"file_path": "/home/user/dev/project/src/main.rs"})),
        // Fall-through: unknown tool, hits every rule then default
        ("unknown", serde_json::json!({})),
    ];

    let warmup = 100;
    let iterations = 10_000;

    println!("{:<15} {:>10} {:>10} {:>10}", "case", "total_ms", "avg_us", "ops/sec");
    println!("{}", "-".repeat(50));

    for (name, input) in &cases {
        let tool = match *name {
            "read" => "Read",
            "unknown" => "UnknownTool",
            _ => "Bash",
        };

        // Warmup
        for _ in 0..warmup {
            let _ = evaluate(&config, tool, input, cwd);
        }

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = evaluate(&config, tool, input, cwd);
        }
        let elapsed = start.elapsed();
        let total_ms = elapsed.as_secs_f64() * 1000.0;
        let avg_us = total_ms * 1000.0 / iterations as f64;
        let ops_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("{:<15} {:>10.1} {:>10.1} {:>10.0}", name, total_ms, avg_us, ops_sec);
    }

    // Also measure just regex compilation cost
    println!("\n--- Regex compilation overhead ---");
    let pattern = r"^(ls|pwd|echo|cat|grep|find|which|whoami|wc|head|tail|sort|uniq|date|uname|df|du|ps|env|printenv|diff|file|stat|true|false|test|\[)\b";
    let iters = 100_000;

    let start = Instant::now();
    for _ in 0..iters {
        let re = regex::Regex::new(pattern).unwrap();
        let _ = re.is_match("ls -la");
    }
    let compile_each = start.elapsed();

    let re = regex::Regex::new(pattern).unwrap();
    let start = Instant::now();
    for _ in 0..iters {
        let _ = re.is_match("ls -la");
    }
    let match_only = start.elapsed();

    let compile_us = compile_each.as_secs_f64() * 1_000_000.0 / iters as f64;
    let match_us = match_only.as_secs_f64() * 1_000_000.0 / iters as f64;
    println!("compile+match:  {:.2} us/op", compile_us);
    println!("match only:     {:.2} us/op", match_us);
    println!("compile cost:   {:.2} us/op ({:.0}x overhead)", compile_us - match_us, compile_us / match_us);
}
