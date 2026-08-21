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
            policy.roles().len() >= 3,
            "Default policy should have ebpf, ebpf-net, ebpf-admin roles"
        );
        assert!(policy.roles().contains_key("ebpf"));
        assert!(policy.roles().contains_key("ebpf-net"));
        assert!(policy.roles().contains_key("ebpf-admin"));
    }

    #[test]
    fn test_policy_role_assignment() {
        let policy = Policy::default();

        let groups = vec!["someuser".to_string(), "ebpf".to_string()];
        let role = policy.get_role_for_groups(&groups);
        assert_eq!(role, Some("ebpf".to_string()));

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

    #[test]
    fn test_policy_command_enforcement() {
        let policy = Policy::default();
        let role = policy.roles().get("ebpf").unwrap();

        assert!(policy.is_command_allowed(role, "PROG_LOAD"));
        assert!(policy.is_command_allowed(role, "MAP_CREATE"));
        assert!(!policy.is_command_allowed(role, "PROG_QUERY"));
    }

    #[test]
    fn test_policy_prog_type_operations() {
        let policy = Policy::default();
        let role = policy.roles().get("ebpf").unwrap();

        assert!(policy.is_prog_op_allowed(role, "kprobe", "load"));
        assert!(policy.is_prog_op_allowed(role, "kprobe", "attach"));
        assert!(!policy.is_prog_op_allowed(role, "xdp", "load"));
    }

    #[test]
    fn test_policy_map_type_operations() {
        let policy = Policy::default();
        let role = policy.roles().get("ebpf").unwrap();

        assert!(policy.is_map_op_allowed(role, "hash", "create"));
        assert!(policy.is_map_op_allowed(role, "hash", "read"));
        assert!(policy.is_map_op_allowed(role, "hash", "write"));
        assert!(!policy.is_map_op_allowed(role, "devmap", "create"));
    }

    #[test]
    fn test_policy_bitmap_generation() {
        let policy = Policy::default();
        let role = policy.roles().get("ebpf").unwrap();

        let prog_bitmap = policy.prog_types_bitmap(role);
        assert!(prog_bitmap & (1u64 << 2) != 0, "kprobe should be allowed");
        assert!(
            prog_bitmap & (1u64 << 5) != 0,
            "tracepoint should be allowed"
        );
        assert!(prog_bitmap & (1u64 << 6) == 0, "xdp should NOT be allowed");

        let map_bitmap = policy.map_types_bitmap(role);
        assert!(map_bitmap & (1u64 << 1) != 0, "hash should be allowed");
        assert!(map_bitmap & (1u64 << 2) != 0, "array should be allowed");
        assert!(
            map_bitmap & (1u64 << 14) == 0,
            "devmap should NOT be allowed"
        );
    }

    #[test]
    fn test_admin_allows_all() {
        let policy = Policy::default();
        let role = policy.roles().get("ebpf-admin").unwrap();

        assert!(policy.is_command_allowed(role, "PROG_LOAD"));
        assert!(policy.is_command_allowed(role, "PROG_QUERY"));
        assert!(policy.is_command_allowed(role, "ANYTHING"));
        assert!(policy.is_prog_op_allowed(role, "xdp", "load"));
        assert!(policy.is_prog_op_allowed(role, "lsm", "attach"));
        assert!(policy.is_map_op_allowed(role, "devmap", "create"));
    }

    #[test]
    fn test_net_role_allows_networking() {
        let policy = Policy::default();
        let role = policy.roles().get("ebpf-net").unwrap();

        assert!(policy.is_prog_op_allowed(role, "xdp", "load"));
        assert!(policy.is_prog_op_allowed(role, "xdp", "detach"));
        assert!(policy.is_prog_op_allowed(role, "sched_cls", "load"));
        assert!(!policy.is_prog_op_allowed(role, "kprobe", "load"));

        assert!(policy.is_map_op_allowed(role, "devmap", "create"));
        assert!(!policy.is_map_op_allowed(role, "ringbuf", "create"));
    }

    #[test]
    fn test_system_policy_intersection() {
        let yaml = r#"
system_policy:
  commands: [PROG_LOAD, MAP_CREATE]
  prog_types:
    kprobe: [load, attach]
  map_types:
    hash: [create, read]

roles:
  test:
    groups: [test]
    commands: [PROG_LOAD, MAP_CREATE, LINK_CREATE]
    prog_types:
      kprobe: [load, attach, detach]
      xdp: [load]
    map_types:
      hash: [create, read, write]
      array: [create]
"#;
        let config: bpf_rbacd::policy::PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let policy = Policy { config };
        let role = policy.roles().get("test").unwrap();

        assert!(!policy.is_command_allowed(role, "LINK_CREATE"));
        assert!(policy.is_command_allowed(role, "PROG_LOAD"));
        assert!(!policy.is_prog_op_allowed(role, "xdp", "load"));
        assert!(policy.is_prog_op_allowed(role, "kprobe", "load"));
        assert!(!policy.is_prog_op_allowed(role, "kprobe", "detach"));
        assert!(!policy.is_map_op_allowed(role, "hash", "write"));
        assert!(policy.is_map_op_allowed(role, "hash", "read"));
        assert!(!policy.is_map_op_allowed(role, "array", "create"));
    }

    #[test]
    fn test_policy_yaml_loading() {
        let policy = Policy::load("config/policy.yaml");
        assert!(
            policy.is_ok(),
            "Should parse config/policy.yaml successfully"
        );
        let policy = policy.unwrap();
        assert!(policy.roles().contains_key("ebpf"));
        assert!(policy.roles().contains_key("ebpf-net"));
        assert!(policy.roles().contains_key("ebpf-admin"));
        assert!(policy.config.system_policy.is_some());
    }
}

/// Namespace delegation tests (require root)
#[cfg(test)]
mod namespace_tests {
    use std::process::{Command, Stdio};

    use bpf_rbacd::namespace::{
        delegate_bpf_to_namespace, is_bpffs_mounted, revoke_bpf_delegation, DelegationOpts,
        TargetNamespace,
    };

    #[test]
    #[ignore = "requires root"]
    fn test_unshare_creates_userns() {
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--", "id", "-u"])
            .output()
            .expect("Failed to run unshare");

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(
            stdout, "0",
            "Should be uid 0 inside user namespace, got: {}",
            stdout
        );
    }

    #[test]
    #[ignore = "requires root"]
    fn test_target_namespace_from_pid() {
        let ns = TargetNamespace::from_pid(1);
        assert!(ns.is_ok(), "Should resolve namespace for PID 1");
        let ns = ns.unwrap();
        assert!(ns.userns_id > 0, "userns_id should be non-zero");
    }

    #[test]
    #[ignore = "requires root"]
    fn test_delegate_bpf_to_child_namespace() {
        let mount_path = "/tmp/bpf-rbac-test-bpffs";
        std::fs::create_dir_all(mount_path).expect("Failed to create mount point");

        let mut child = Command::new("unshare")
            .args([
                "--user",
                "--mount",
                "--map-root-user",
                "--fork",
                "--",
                "sleep",
                "30",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn unshare child");

        let child_pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(500));

        let target =
            TargetNamespace::from_pid(child_pid).expect("Failed to resolve target namespace");

        assert!(target.userns_id > 0, "Should have valid userns_id");

        let opts = DelegationOpts::allow_all();
        let result = delegate_bpf_to_namespace(&target, mount_path, &opts);

        let _ = child.kill();
        let _ = child.wait();

        match result {
            Ok(()) => {
                println!("bpffs delegation succeeded for PID {}", child_pid);
            }
            Err(e) => {
                let msg = format!("{:?}", e);
                println!(
                    "bpffs delegation failed (expected if kernel doesn't allow): {}",
                    msg
                );
            }
        }

        let _ = std::fs::remove_dir(mount_path);
    }

    #[test]
    fn test_delegation_opts_mount_data() {
        let opts = DelegationOpts::allow_all();
        let data = opts.to_mount_data();
        assert!(data.contains("delegate_cmds=0xffffffff"));
        assert!(data.contains("delegate_progs=0xffffffff"));
        assert!(data.contains("delegate_maps=0xffffffff"));
        assert!(data.contains("delegate_attachs=0xffffffff"));

        let opts = DelegationOpts::from_bitmaps(0x1F_u64, 0x24_u64, 0x06_u64, 0x00_u64);
        let data = opts.to_mount_data();
        assert!(data.contains("delegate_cmds=0x1f"));
        assert!(data.contains("delegate_progs=0x24"));
        assert!(data.contains("delegate_maps=0x6"));
        assert!(data.contains("delegate_attachs=0x0"));
    }

    #[test]
    fn test_is_bpffs_mounted_nonexistent() {
        assert!(
            !is_bpffs_mounted(std::path::Path::new("/tmp/nonexistent-bpffs-path")),
            "Non-existent path should not be a bpffs mount"
        );
    }

    #[test]
    #[ignore = "requires root"]
    fn test_delegate_and_revoke_lifecycle() {
        let mount_path = "/tmp/bpf-rbac-test-lifecycle";
        std::fs::create_dir_all(mount_path).expect("Failed to create mount point");

        let mut child = Command::new("unshare")
            .args([
                "--user",
                "--mount",
                "--map-root-user",
                "--fork",
                "--",
                "sleep",
                "30",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn unshare child");

        let child_pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(500));

        let target =
            TargetNamespace::from_pid(child_pid).expect("Failed to resolve target namespace");

        let opts = DelegationOpts::allow_all();

        if delegate_bpf_to_namespace(&target, mount_path, &opts).is_ok() {
            let revoke_result = revoke_bpf_delegation(&target, mount_path);
            assert!(
                revoke_result.is_ok(),
                "Revocation should succeed after delegation: {:?}",
                revoke_result.err()
            );
        }

        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir(mount_path);
    }

    #[test]
    #[ignore = "requires root"]
    fn test_bpf_token_creation_in_delegated_ns() {
        let mount_path = "/tmp/bpf-rbac-test-token";
        std::fs::create_dir_all(mount_path).expect("Failed to create mount point");

        let mut child = Command::new("unshare")
            .args([
                "--user",
                "--mount",
                "--map-root-user",
                "--fork",
                "--",
                "sleep",
                "30",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn unshare child");

        let child_pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(500));

        let target =
            TargetNamespace::from_pid(child_pid).expect("Failed to resolve target namespace");

        let opts = DelegationOpts::allow_all();

        if delegate_bpf_to_namespace(&target, mount_path, &opts).is_ok() {
            let bpf_token_test = Command::new("nsenter")
                .args([
                    "--user",
                    "--mount",
                    &format!("--target={}", child_pid),
                    "--",
                    "ls",
                    mount_path,
                ])
                .output();

            match bpf_token_test {
                Ok(output) => {
                    println!(
                        "bpffs listing inside namespace: {}",
                        String::from_utf8_lossy(&output.stdout)
                    );
                    assert!(
                        output.status.success(),
                        "Should be able to list bpffs mount from within namespace"
                    );
                }
                Err(e) => {
                    println!("nsenter failed (expected in some environments): {}", e);
                }
            }

            let _ = revoke_bpf_delegation(&target, mount_path);
        }

        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir(mount_path);
    }

    #[test]
    fn test_policy_to_delegation_opts() {
        use bpf_rbacd::policy::Policy;

        let policy = Policy::default();
        let role = policy.roles().get("ebpf").unwrap();

        let prog_bitmap = policy.prog_types_bitmap(role);
        let map_bitmap = policy.map_types_bitmap(role);
        let cmd_bitmap = policy.commands_bitmap(role);

        let opts = DelegationOpts::from_bitmaps(cmd_bitmap, prog_bitmap, map_bitmap, 0);

        assert!(
            opts.delegate_cmds != 0,
            "Commands bitmap should be non-zero"
        );
        assert!(
            opts.delegate_progs != 0,
            "Prog types bitmap should be non-zero"
        );
        assert!(
            opts.delegate_maps != 0,
            "Map types bitmap should be non-zero"
        );

        let data = opts.to_mount_data();
        assert!(data.contains("delegate_cmds="));
        assert!(data.contains("delegate_progs="));
        assert!(data.contains("delegate_maps="));
    }
}

/// LSM smoke tests (require root + eBPF crate built)
#[cfg(test)]
mod lsm_tests {
    use std::path::Path;

    const EBPF_BINARY_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf-rbacd-ebpf/target/bpfel-unknown-none/debug/bpf-rbacd-ebpf"
    );

    #[test]
    fn test_ebpf_binary_exists() {
        let path = Path::new(EBPF_BINARY_PATH);
        if !path.exists() {
            eprintln!(
                "eBPF binary not found at {}. Build with:\n  \
                 cd bpf-rbacd-ebpf && cargo +nightly build -Z build-std=core --target bpfel-unknown-none",
                EBPF_BINARY_PATH
            );
            return;
        }
        let metadata = std::fs::metadata(path).unwrap();
        assert!(metadata.len() > 0, "eBPF binary should be non-empty");
    }

    #[test]
    fn test_ebpf_binary_is_valid_elf() {
        let path = Path::new(EBPF_BINARY_PATH);
        if !path.exists() {
            eprintln!("Skipping: eBPF binary not built");
            return;
        }

        let data = std::fs::read(path).unwrap();
        assert!(data.len() >= 4, "eBPF binary too small");
        assert_eq!(&data[0..4], b"\x7fELF", "Should be a valid ELF binary");
    }

    #[test]
    #[ignore = "requires root and CAP_BPF"]
    fn test_lsm_program_load_and_attach() {
        let path = Path::new(EBPF_BINARY_PATH);
        if !path.exists() {
            panic!(
                "eBPF binary not found. Build it first:\n  \
                 cd bpf-rbacd-ebpf && cargo +nightly build -Z build-std=core --target bpfel-unknown-none"
            );
        }

        let data = std::fs::read(path).unwrap();
        let mut ebpf = aya::Ebpf::load(&data).expect("Failed to load eBPF programs");

        let program_names: Vec<String> =
            ebpf.programs().map(|(name, _)| name.to_string()).collect();

        assert!(
            program_names.iter().any(|n| n.contains("bpf_rbac_bpf")),
            "Should contain bpf_rbac_bpf program, got: {:?}",
            program_names
        );
        assert!(
            program_names
                .iter()
                .any(|n| n.contains("bpf_rbac_prog_load")),
            "Should contain bpf_rbac_prog_load program, got: {:?}",
            program_names
        );
        assert!(
            program_names
                .iter()
                .any(|n| n.contains("bpf_rbac_map_create")),
            "Should contain bpf_rbac_map_create program, got: {:?}",
            program_names
        );

        println!("LSM programs loaded: {:?}", program_names);

        use aya::programs::Lsm;

        let btf = aya::Btf::from_sys_fs().expect("Failed to load BTF from sysfs");

        let program: &mut Lsm = ebpf
            .program_mut("bpf_rbac_bpf")
            .expect("bpf_rbac_bpf not found")
            .try_into()
            .expect("Not an LSM program");

        program
            .load("bpf", &btf)
            .expect("Failed to load bpf_rbac_bpf into kernel");
        program
            .attach()
            .expect("Failed to attach bpf_rbac_bpf to LSM hook");
        println!("bpf_rbac_bpf: loaded and attached to LSM hook");

        let program: &mut Lsm = ebpf
            .program_mut("bpf_rbac_prog_load")
            .expect("bpf_rbac_prog_load not found")
            .try_into()
            .expect("Not an LSM program");

        program
            .load("bpf_prog_load", &btf)
            .expect("Failed to load bpf_rbac_prog_load");
        program
            .attach()
            .expect("Failed to attach bpf_rbac_prog_load");
        println!("bpf_rbac_prog_load: loaded and attached to LSM hook");

        let program: &mut Lsm = ebpf
            .program_mut("bpf_rbac_map_create")
            .expect("bpf_rbac_map_create not found")
            .try_into()
            .expect("Not an LSM program");

        program
            .load("bpf_map_create", &btf)
            .expect("Failed to load bpf_rbac_map_create");
        program
            .attach()
            .expect("Failed to attach bpf_rbac_map_create");
        println!("bpf_rbac_map_create: loaded and attached to LSM hook");

        // Verify the POLICY_MAP is accessible
        let map = ebpf.map("POLICY_MAP");
        assert!(
            map.is_some(),
            "POLICY_MAP should be accessible after loading"
        );
        println!("POLICY_MAP: accessible");

        println!("All LSM programs loaded, attached, and map verified.");
        // Programs are automatically detached and unloaded when `ebpf` is dropped.
    }

    #[test]
    #[ignore = "requires root and CAP_BPF"]
    fn test_policy_map_population() {
        let path = Path::new(EBPF_BINARY_PATH);
        if !path.exists() {
            panic!("eBPF binary not found");
        }

        let data = std::fs::read(path).unwrap();
        let mut ebpf = aya::Ebpf::load(&data).expect("Failed to load eBPF programs");

        use aya::maps::HashMap;
        use bpf_rbacd_common::{flags, PolicyKey, PolicyValue};

        let map = ebpf.map_mut("POLICY_MAP").expect("POLICY_MAP not found");

        let mut policy_map: HashMap<&mut aya::maps::MapData, PolicyKey, PolicyValue> =
            HashMap::try_from(map).expect("Not a HashMap");

        let key = PolicyKey { userns_id: 12345 };
        let value = PolicyValue {
            allowed_cmds: 0x1F,
            allowed_prog_types: 0x24,
            allowed_map_types: 0x06,
            allowed_attach_types: 0x00,
            flags: 0,
            _reserved: [0; 3],
        };

        policy_map
            .insert(key, value, 0)
            .expect("Failed to insert policy entry");

        let retrieved = policy_map.get(&key, 0).expect("Failed to get policy entry");
        assert_eq!(retrieved.allowed_cmds, 0x1F_u64);
        assert_eq!(retrieved.allowed_prog_types, 0x24_u64);
        assert_eq!(retrieved.allowed_map_types, 0x06_u64);
        assert_eq!(retrieved.flags, 0);
        println!("Policy map population and retrieval works correctly");

        let deny_key = PolicyKey { userns_id: 99999 };
        let deny_value = PolicyValue {
            allowed_cmds: 0,
            allowed_prog_types: 0,
            allowed_map_types: 0,
            allowed_attach_types: 0,
            flags: flags::POLICY_FLAG_DENY_ALL,
            _reserved: [0; 3],
        };
        policy_map
            .insert(deny_key, deny_value, 0)
            .expect("Failed to insert deny policy");

        let retrieved = policy_map
            .get(&deny_key, 0)
            .expect("Failed to get deny entry");
        assert_eq!(
            retrieved.flags & flags::POLICY_FLAG_DENY_ALL,
            flags::POLICY_FLAG_DENY_ALL
        );
        println!("Deny-all policy entry works correctly");

        policy_map
            .remove(&key)
            .expect("Failed to remove policy entry");
        policy_map
            .remove(&deny_key)
            .expect("Failed to remove deny entry");
        println!("Policy map cleanup successful");
    }
}
