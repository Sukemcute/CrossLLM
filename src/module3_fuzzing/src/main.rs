//! BridgeSentry Dual-Chain Fuzzing Engine
//!
//! Synchronized dual-EVM fuzzer for cross-chain bridge vulnerability discovery.
//! Maintains paired EVM instances (source + destination) connected through a mock relay.

pub mod types;
pub mod config;
mod dual_evm;
mod fuzz_loop;
mod mock_relay;
mod snapshot;
mod mutator;
mod checker;
mod scenario_sim;

use eyre::Context;

fn main() {
    let ctx = match config::parse_and_load() {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("ERROR: Failed to initialize fuzzer: {:#}", e);
            std::process::exit(1);
        }
    };

    ctx.print_summary();

    let results = match fuzz_loop::run(&ctx) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: Fuzz loop failed: {:#}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = write_results(&ctx.config.output_path, &results) {
        eprintln!("ERROR: Failed to write results JSON: {e:#}");
        std::process::exit(2);
    }

    println!(
        "\nFuzzer loop completed. Iterations={} Violations={} Corpus={} PoolPeak={} Output={}",
        results.stats.total_iterations,
        results.violations.len(),
        results.stats.corpus_size,
        results.stats.snapshot_pool_peak,
        ctx.config.output_path
    );
}

fn write_results(path: &str, results: &types::FuzzingResults) -> eyre::Result<()> {
    let output_path = std::path::Path::new(path);
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("Failed to create output dir: {}", parent.display()))?;
        }
    }

    let content = serde_json::to_string_pretty(results)
        .wrap_err("Failed to serialize results to JSON")?;
    std::fs::write(output_path, content)
        .wrap_err_with(|| format!("Failed to write output file: {}", output_path.display()))?;
    Ok(())
}
