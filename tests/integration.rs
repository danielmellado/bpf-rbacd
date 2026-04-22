//! Integration tests for bpf-rbacd
//!
//! These tests verify the RBAC daemon works correctly:
//! - Users in 'ebpf' group can create BPF maps
//! - Users NOT in 'ebpf' group are denied
//! - Policy enforcement works correctly
//!
//! Run with: sudo cargo test --test integration

use std::fs;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

mod utils;
use utils::{wait_for_socket, TestUserGuard};

const DAEMON_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Guard that manages the daemon process lifecycle
struct DaemonGuard {
    child: Child,
    socket_path: String,
}

impl DaemonGuard {
    fn start(socket_path: &str) -> Self {
        // Clean up any existing socket
        let _ = fs::remove_file(socket_path);

        // Start daemon
        let child = Command::new(env!("CARGO_BIN_EXE_bpf-rbacd"))
            .env("RUST_LOG", "warn")
            .env("BPF_RBAC_SOCKET", socket_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start daemon");

        // Wait for socket to appear
        wait_for_socket(socket_path, DAEMON_STARTUP_TIMEOUT).expect("Daemon socket did not appear");

        Self {
            child,
            socket_path: socket_path.to_string(),
        }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        // Kill the daemon
        let _ = self.child.kill();
        let _ = self.child.wait();

        // Clean up socket
        let _ = fs::remove_file(&self.socket_path);
    }
}

/// Generate unique socket path for parallel tests
fn unique_socket_path() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("/run/bpf-rbac-test-{}-{}.sock", std::process::id(), id)
}

#[test]
#[ignore = "requires root and ebpf group setup"]
fn test_allowed_user_can_create_map() {
    let socket_path = unique_socket_path();
    let _daemon = DaemonGuard::start(&socket_path);

    // Create test user in ebpf group
    let _user = TestUserGuard::new("test_allowed", Some("ebpf"));

    // Run client as test user
    let output = Command::new("sudo")
        .args(["-u", "test_allowed", env!("CARGO_BIN_EXE_bpf-rbac")])
        .args(["create-map", "hash", "test_map", "4", "8", "100"])
        .env("BPF_RBAC_SOCKET", &socket_path)
        .output()
        .expect("Failed to run client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Success"),
        "Expected success for allowed user, got: {}",
        stdout
    );
}

#[test]
#[ignore = "requires root and ebpf group setup"]
fn test_denied_user_cannot_create_map() {
    let socket_path = unique_socket_path();
    let _daemon = DaemonGuard::start(&socket_path);

    // Create test user NOT in ebpf group
    let _user = TestUserGuard::new("test_denied", None);

    // Run client as test user
    let output = Command::new("sudo")
        .args(["-u", "test_denied", env!("CARGO_BIN_EXE_bpf-rbac")])
        .args(["create-map", "hash", "test_map", "4", "8", "100"])
        .env("BPF_RBAC_SOCKET", &socket_path)
        .output()
        .expect("Failed to run client");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("Denied"),
        "Expected denial for unauthorized user, got: {}",
        combined
    );
}

#[test]
#[ignore = "requires root"]
fn test_daemon_status_check() {
    let socket_path = unique_socket_path();
    let _daemon = DaemonGuard::start(&socket_path);

    // Status should work for any user
    let output = Command::new(env!("CARGO_BIN_EXE_bpf-rbac"))
        .arg("status")
        .env("BPF_RBAC_SOCKET", &socket_path)
        .output()
        .expect("Failed to run client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("running"),
        "Expected daemon to be running, got: {}",
        stdout
    );
}

#[test]
#[ignore = "requires root and ebpf group setup"]
fn test_multiple_map_types() {
    let socket_path = unique_socket_path();
    let _daemon = DaemonGuard::start(&socket_path);
    let _user = TestUserGuard::new("test_maps", Some("ebpf"));

    // Test hash map
    let output = Command::new("sudo")
        .args(["-u", "test_maps", env!("CARGO_BIN_EXE_bpf-rbac")])
        .args(["create-map", "hash", "hash_map", "4", "8", "100"])
        .env("BPF_RBAC_SOCKET", &socket_path)
        .output()
        .expect("Failed to create hash map");

    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Success"),
        "Hash map creation should succeed"
    );

    // Test array map
    let output = Command::new("sudo")
        .args(["-u", "test_maps", env!("CARGO_BIN_EXE_bpf-rbac")])
        .args(["create-map", "array", "array_map", "4", "8", "100"])
        .env("BPF_RBAC_SOCKET", &socket_path)
        .output()
        .expect("Failed to create array map");

    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Success"),
        "Array map creation should succeed"
    );
}

/// Unit tests that don't require root
#[cfg(test)]
mod unit_tests {
    use bpf_rbacd::policy::Policy;
    use bpf_rbacd::protocol::Request;

    #[test]
    fn test_default_policy_has_roles() {
        let policy = Policy::default();
        assert!(
            policy.roles.len() >= 3,
            "Default policy should have ebpf, ebpf-net, ebpf-admin roles"
        );
        assert!(policy.roles.contains_key("ebpf"));
        assert!(policy.roles.contains_key("ebpf-net"));
        assert!(policy.roles.contains_key("ebpf-admin"));
    }

    #[test]
    fn test_policy_role_assignment() {
        let policy = Policy::default();

        // User in ebpf group should get ebpf role
        let groups = vec!["someuser".to_string(), "ebpf".to_string()];
        let role = policy.get_role_for_groups(&groups);
        assert_eq!(role, Some("ebpf".to_string()));

        // User not in any bpf group should get no role
        let groups = vec!["randomuser".to_string()];
        let role = policy.get_role_for_groups(&groups);
        assert_eq!(role, None);
    }

    #[test]
    fn test_policy_allows_hash_map_for_ebpf_role() {
        let policy = Policy::default();

        let request = Request::CreateMap {
            map_type: "hash".to_string(),
            name: "test".to_string(),
            key_size: 4,
            value_size: 8,
            max_entries: 100,
        };

        assert!(policy.is_allowed("ebpf", &request));
    }

    #[test]
    fn test_policy_allows_array_map_for_ebpf_role() {
        let policy = Policy::default();

        let request = Request::CreateMap {
            map_type: "array".to_string(),
            name: "test".to_string(),
            key_size: 4,
            value_size: 8,
            max_entries: 100,
        };

        assert!(policy.is_allowed("ebpf", &request));
    }
}
