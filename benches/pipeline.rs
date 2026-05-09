//! Permiter pipeline benchmarks.
//!
//! Workflow:
//!
//!     # Establish a baseline before changes
//!     cargo bench --bench pipeline -- --save-baseline pre
//!
//!     # After changes, compare against it
//!     cargo bench --bench pipeline -- --baseline pre
//!
//!     # Smoke-test (one iteration each, no sampling)
//!     cargo bench --bench pipeline -- --test
//!
//! Two groups:
//!   * `load_phases` — lex / parse / validate / compile_regexes / parse_dsl_full,
//!     each measured against `example.perm`.
//!   * `evaluate`    — the seven hot-path engine cases.

use std::hint::black_box;
use std::path::Path;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use permiter::dsl;
use permiter::engine::evaluate;

const EXAMPLE_PERM: &str = include_str!("../example.perm");

fn bench_load_phases(c: &mut Criterion) {
    // Pre-compute shared inputs outside the timed loops.
    let tokens = dsl::lex(EXAMPLE_PERM).expect("lex must succeed");
    let parsed = dsl::parse_dsl(EXAMPLE_PERM).expect("parse_dsl must succeed");

    let mut group = c.benchmark_group("load_phases");

    // NOTE: Criterion's `BenchmarkGroup::throughput` setting is sticky — once
    // set, it carries over to subsequent benches in the same group. We have no
    // way to "unset" it, so we order the benches that don't need throughput
    // first, then set bytes throughput once for the two that do.

    // parse — clone tokens per-iter (Parser::parse advances state).
    group.bench_function("parse", |b| {
        b.iter(|| {
            let mut parser = dsl::Parser::new(black_box(tokens.clone()));
            let cfg = parser.parse().expect("parse must succeed");
            black_box(cfg);
        });
    });

    // validate — clone the Config so validate sees a fresh value each iter.
    group.bench_function("validate", |b| {
        b.iter(|| {
            let cfg = black_box(parsed.clone());
            cfg.validate().expect("validate must succeed");
            black_box(cfg);
        });
    });

    // compile_regexes — clone, clear cache, recompile. Measures the work
    // that happens once per process startup (the dominant Config::load cost).
    group.bench_function("compile_regexes", |b| {
        b.iter(|| {
            let mut cfg = black_box(parsed.clone());
            cfg.regex_cache.clear();
            cfg.compile_regexes().expect("compile_regexes must succeed");
            black_box(cfg);
        });
    });

    // From here on, throughput is bytes-of-input (reports show MB/s).
    group.throughput(Throughput::Bytes(EXAMPLE_PERM.len() as u64));

    // lex — measured against the raw config text.
    group.bench_function("lex", |b| {
        b.iter(|| {
            let tokens = dsl::lex(black_box(EXAMPLE_PERM)).expect("lex must succeed");
            black_box(tokens);
        });
    });

    // parse_dsl_full — end-to-end; sum of the parts should approximate this.
    group.bench_function("parse_dsl_full", |b| {
        b.iter(|| {
            let cfg = dsl::parse_dsl(black_box(EXAMPLE_PERM)).expect("parse_dsl must succeed");
            black_box(cfg);
        });
    });

    group.finish();
}

fn bench_evaluate(c: &mut Criterion) {
    let config = dsl::parse_dsl(EXAMPLE_PERM).expect("example.perm must parse");
    let cwd = Path::new("/home/user/dev/project");

    // (case_name, tool, tool_input) — identical inputs to the prior benches/eval.rs.
    let cases: Vec<(&str, &str, serde_json::Value)> = vec![
        ("safe_cmd", "Bash", serde_json::json!({"command": "ls -la"})),
        ("git_cmd", "Bash", serde_json::json!({"command": "git status"})),
        ("rm_cmd", "Bash", serde_json::json!({"command": "rm -rf /tmp/test"})),
        (
            "compound",
            "Bash",
            serde_json::json!({"command": "cd /tmp && git status && ls -la | grep foo"}),
        ),
        ("sh_c", "Bash", serde_json::json!({"command": "sh -c 'git status'"})),
        (
            "read",
            "Read",
            serde_json::json!({"file_path": "/home/user/dev/project/src/main.rs"}),
        ),
        ("unknown", "UnknownTool", serde_json::json!({})),
    ];

    let mut group = c.benchmark_group("evaluate");

    for (name, tool, input) in &cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), input, |b, input| {
            b.iter(|| {
                let result = evaluate(
                    black_box(&config),
                    black_box(tool),
                    black_box(input),
                    black_box(cwd),
                );
                black_box(result.expect("evaluate must succeed"));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_load_phases, bench_evaluate);
criterion_main!(benches);
