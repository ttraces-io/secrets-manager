//! `traces-sm` DevTest CLI Diagnostic Runner.

use colored::Colorize;
use std::env;
use std::fs;
use std::process;
use traces_sm_devtest::DevTestRunner;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let is_json = args.iter().any(|a| a == "--json");
    let report_file = args
        .iter()
        .position(|a| a == "--report")
        .and_then(|idx| args.get(idx + 1).cloned());

    let runner = DevTestRunner::new();

    if !is_json {
        println!(
            "{}",
            "╔════════════════════════════════════════════════════════════════════════════════╗"
                .bright_cyan()
        );
        println!(
            "{}",
            "║              🔒 traces-sm Enterprise Testing & Verification Module             ║"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "╚════════════════════════════════════════════════════════════════════════════════╝"
                .bright_cyan()
        );
        println!();
        println!(
            "  {} {}",
            "Operating System:".bright_yellow().bold(),
            runner.env_info.os
        );
        println!(
            "  {} {}",
            "Architecture:    ".bright_yellow().bold(),
            runner.env_info.arch
        );
        println!(
            "  {} {}",
            "SGX Mode:        ".bright_yellow().bold(),
            runner.env_info.sgx_mode
        );
        println!(
            "  {} {}",
            "Simulation Mode: ".bright_yellow().bold(),
            runner.env_info.is_simulation
        );
        println!(
            "  {} {}",
            "Temp Directory:  ".bright_yellow().bold(),
            runner.env_info.temp_dir
        );
        println!();
        println!(
            "{}",
            "── Executing Comprehensive Subsystem Test Suites ──────────────────────────────"
                .dimmed()
        );
    }

    let report = runner.run_all().await;

    if is_json {
        let json = serde_json::to_string_pretty(&report).unwrap();
        println!("{}", json);
    } else {
        println!();
        for (idx, suite) in report.suites.iter().enumerate() {
            let status_badge = if suite.passed {
                " PASS ".black().on_green().bold()
            } else {
                " FAIL ".white().on_red().bold()
            };

            let name_colored = if suite.passed {
                suite.name.bright_white().bold()
            } else {
                suite.name.bright_red().bold()
            };

            println!(
                "  [{:02}] {} {:<65} {:>6} ms",
                idx + 1,
                status_badge,
                name_colored,
                suite.duration_ms
            );

            for test in &suite.tests {
                if let Some(ref err) = test.error {
                    println!("       {} {}", "└─ Error:".bright_red(), err.red());
                }
            }
        }

        println!();
        println!(
            "{}",
            "════════════════════════════════════════════════════════════════════════════════"
                .bright_cyan()
        );
        if report.failed_suites == 0 {
            println!(
                "  {} All {} test suites passed successfully in {} ms!",
                "✨ SUCCESS:".bright_green().bold(),
                report.total_suites,
                report.total_duration_ms
            );
        } else {
            println!(
                "  {} {}/{} test suites failed! (Duration: {} ms)",
                "💥 FAILURE:".bright_red().bold(),
                report.failed_suites,
                report.total_suites,
                report.total_duration_ms
            );
        }
        println!(
            "{}",
            "════════════════════════════════════════════════════════════════════════════════"
                .bright_cyan()
        );
        println!();
    }

    if let Some(path) = report_file {
        let markdown = DevTestRunner::render_markdown_report(&report);
        if let Err(e) = fs::write(&path, markdown) {
            eprintln!("Failed to write report to {}: {}", path, e);
        } else if !is_json {
            println!(
                "  {} Audit report generated at: {}",
                "📄 Report:".bright_cyan().bold(),
                path
            );
        }
    }

    if report.failed_suites > 0 {
        process::exit(1);
    }
}
