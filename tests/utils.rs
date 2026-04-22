//! Test utilities for bpf-rbacd integration tests
//!
//! Provides RAII guards for test resources like users and groups.

use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

/// Guard that creates a test user and removes it on drop
pub struct TestUserGuard {
    username: String,
}

impl TestUserGuard {
    /// Create a new test user, optionally adding to a group
    ///
    /// # Arguments
    /// * `username` - The username to create
    /// * `group` - Optional group to add the user to (must already exist)
    pub fn new(username: &str, group: Option<&str>) -> Self {
        // Ensure ebpf group exists if needed
        if let Some(g) = group {
            let _ = Command::new("groupadd").arg(g).output();
        }

        // Remove user if exists from previous failed test
        let _ = Command::new("userdel").args(["-r", username]).output();

        // Create user
        let mut cmd = Command::new("useradd");
        cmd.args(["-m", username]);

        if let Some(g) = group {
            cmd.args(["-G", g]);
        }

        let output = cmd.output().expect("Failed to create test user");

        if !output.status.success() {
            panic!(
                "Failed to create user {}: {}",
                username,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Self {
            username: username.to_string(),
        }
    }
}

impl Drop for TestUserGuard {
    fn drop(&mut self) {
        // Remove the test user
        let output = Command::new("userdel")
            .args(["-r", &self.username])
            .output();

        if let Err(e) = output {
            eprintln!(
                "Warning: Failed to remove test user {}: {}",
                self.username, e
            );
        }
    }
}

/// Wait for a Unix socket to appear
pub fn wait_for_socket(path: &str, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let path = Path::new(path);

    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "Socket {} did not appear within {:?}",
        path.display(),
        timeout
    ))
}
