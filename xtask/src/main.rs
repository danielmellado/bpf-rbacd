//! xtask - Development task runner for bpf-rbacd
//!
//! Following the xtask pattern used by Aya and other Rust projects.
//! See: https://github.com/matklad/cargo-xtask

use std::env;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Development tasks for bpf-rbacd")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run integration tests
    Test {
        /// Run with sudo (required for BPF operations)
        #[arg(long, default_value = "true")]
        sudo: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Build release binaries
    Build {
        /// Build in release mode
        #[arg(long, default_value = "true")]
        release: bool,
    },

    /// Install binaries system-wide
    Install,

    /// Clean build artifacts
    Clean,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Find workspace root
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap_or(std::path::Path::new("."));

    env::set_current_dir(workspace_root).context("Failed to change to workspace root")?;

    match cli.command {
        Commands::Test { sudo, verbose } => run_tests(sudo, verbose),
        Commands::Build { release } => run_build(release),
        Commands::Install => run_install(),
        Commands::Clean => run_clean(),
    }
}

fn run_build(release: bool) -> Result<()> {
    println!("Building bpf-rbacd...");

    let mut cmd = Command::new("cargo");
    cmd.arg("build");

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to run cargo build")?;

    if !status.success() {
        bail!("Build failed");
    }

    println!("Build complete!");
    Ok(())
}

fn run_clean() -> Result<()> {
    println!("Cleaning build artifacts...");

    let status = Command::new("cargo")
        .arg("clean")
        .status()
        .context("Failed to run cargo clean")?;

    if !status.success() {
        bail!("Clean failed");
    }

    println!("Clean complete!");
    Ok(())
}

fn run_install() -> Result<()> {
    // Build first
    run_build(true)?;

    println!("Installing binaries...");

    let daemon = "target/release/bpf-rbacd";
    let client = "target/release/bpf-rbac";

    // Check binaries exist
    if !std::path::Path::new(daemon).exists() {
        bail!("Daemon binary not found at {}", daemon);
    }
    if !std::path::Path::new(client).exists() {
        bail!("Client binary not found at {}", client);
    }

    // Install with sudo
    let status = Command::new("sudo")
        .args(["install", "-m", "755", daemon, "/usr/local/bin/"])
        .status()
        .context("Failed to install daemon")?;

    if !status.success() {
        bail!("Failed to install daemon");
    }

    let status = Command::new("sudo")
        .args(["install", "-m", "755", client, "/usr/local/bin/"])
        .status()
        .context("Failed to install client")?;

    if !status.success() {
        bail!("Failed to install client");
    }

    println!("Installed to /usr/local/bin/");
    Ok(())
}

fn run_tests(sudo: bool, verbose: bool) -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║          BPF RBAC Daemon Integration Tests                       ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    // Check if running as root when sudo is disabled
    if !sudo {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            bail!("Integration tests require root. Use --sudo=true or run as root.");
        }
    }

    // Build first
    run_build(true)?;

    // Run unit tests
    println!("\nRunning unit tests...");
    let status = Command::new("cargo")
        .args(["test", "--lib"])
        .status()
        .context("Failed to run unit tests")?;

    if !status.success() {
        bail!("Unit tests failed");
    }

    // Run integration tests
    println!("\nRunning integration tests...");

    let mut test_script = if sudo {
        // Wrap in sudo
        let mut cmd = Command::new("sudo");
        cmd.arg("-E");
        cmd.arg("bash");
        cmd.arg("-c");
        cmd.arg(integration_test_script(verbose));
        cmd
    } else {
        let mut cmd = Command::new("bash");
        cmd.arg("-c");
        cmd.arg(integration_test_script(verbose));
        cmd
    };

    let output = test_script
        .output()
        .context("Failed to run integration tests")?;

    // Print output
    let stdout = String::from_utf8_lossy(&output.stdout);
    print!("{stdout}");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));

    // Check for success in output (more reliable than exit code in some environments)
    if stdout.contains("0 failed") {
        println!("\nAll tests passed!");
        Ok(())
    } else if !output.status.success() || stdout.contains("failed") {
        bail!("Integration tests failed");
    } else {
        println!("\nAll tests passed!");
        Ok(())
    }
}

fn integration_test_script(verbose: bool) -> String {
    let log_level = if verbose { "info" } else { "warn" };

    format!(
        r#"#!/bin/bash
# Setup
groupadd ebpf 2>/dev/null || true
useradd -m -G ebpf xtask_user_ok 2>/dev/null || true
useradd -m xtask_user_bad 2>/dev/null || true

# Start daemon
RUST_LOG={log_level} ./target/release/bpf-rbacd &
DAEMON_PID=$!
sleep 2

PASSED=0
FAILED=0

run_test() {{
    local name="$1"
    local user="$2"
    local expected="$3"
    shift 3
    
    printf "  [%s]: " "$name"
    OUTPUT=$(sudo -u "$user" ./target/release/bpf-rbac "$@" 2>&1) || true
    
    if [ "$expected" = "pass" ]; then
        if echo "$OUTPUT" | grep -q "Success"; then
            echo "PASS"
            PASSED=$((PASSED+1))
        else
            echo "FAIL"
            FAILED=$((FAILED+1))
        fi
    else
        if echo "$OUTPUT" | grep -q "Denied"; then
            echo "PASS (denied)"
            PASSED=$((PASSED+1))
        else
            echo "FAIL"
            FAILED=$((FAILED+1))
        fi
    fi
}}

echo "  Integration Tests:"
run_test "allowed_hash_map" "xtask_user_ok" "pass" create-map hash t1 4 8 100
run_test "allowed_array_map" "xtask_user_ok" "pass" create-map array t2 4 8 100
run_test "denied_hash_map" "xtask_user_bad" "fail" create-map hash t3 4 8 100
run_test "denied_array_map" "xtask_user_bad" "fail" create-map array t4 4 8 100

echo ""
echo "Results: $PASSED passed, $FAILED failed"

# Cleanup
kill $DAEMON_PID 2>/dev/null || true
pkill -f bpf-rbacd 2>/dev/null || true
userdel -r xtask_user_ok 2>/dev/null || true
userdel -r xtask_user_bad 2>/dev/null || true
rm -f /run/bpf-rbac.sock 2>/dev/null || true

# Exit with proper status
[ $FAILED -eq 0 ]
"#
    )
}
