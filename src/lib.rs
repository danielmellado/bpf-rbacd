//! # bpf-rbacd
//!
//! Role-Based Access Control for eBPF operations on Linux.
//!
//! `bpf-rbacd` enables unprivileged users and containers to safely use eBPF
//! through policy-controlled access. It supports two complementary modes:
//!
//! - **Capability granting** — for containers and services running in their own
//!   user namespace. The daemon delegates BPF privileges via
//!   [BPF tokens](https://docs.kernel.org/bpf/bpf_token.html) and enforces
//!   granular policies through an eBPF LSM.
//!
//! - **Proxy execution** — for desktop users in the initial user namespace
//!   (where BPF tokens are not supported). The daemon executes `bpf()` syscalls
//!   on behalf of clients and passes back file descriptors via `SCM_RIGHTS`.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │              bpf-rbacd (privileged daemon)            │
//! │                                                      │
//! │  ┌────────────┐  ┌──────────────┐  ┌──────────────┐ │
//! │  │   Policy    │  │  Namespace   │  │    Proxy     │ │
//! │  │   Engine    │  │  Delegation  │  │   Handler    │ │
//! │  └─────┬──────┘  └──────┬───────┘  └──────┬───────┘ │
//! │        │                │                  │         │
//! │        ▼                ▼                  ▼         │
//! │  ┌──────────┐    ┌───────────┐    ┌──────────────┐  │
//! │  │ eBPF Map │    │  bpffs +  │    │  Unix Socket │  │
//! │  │ (policy) │    │  tokens   │    │  SCM_RIGHTS  │  │
//! │  └────┬─────┘    └───────────┘    └──────────────┘  │
//! │       │                                              │
//! │       ▼                                              │
//! │  ┌──────────┐                                        │
//! │  │ eBPF LSM │  (security_bpf, security_bpf_prog_    │
//! │  │  hooks   │   load, security_bpf_map_create)       │
//! │  └──────────┘                                        │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Crates
//!
//! | Crate | Description |
//! |-------|-------------|
//! | `bpf-rbacd` | Daemon, policy engine, namespace delegation, proxy handler |
//! | `bpf-rbacd-common` | Shared `#[repr(C)]` types for the eBPF map boundary |
//! | `bpf-rbacd-ebpf` | eBPF LSM programs (built with `bpfel-unknown-none` target) |
//!
//! ## Modules
//!
//! - [`policy`] — YAML policy parsing, role resolution, system-policy intersection,
//!   and bitmap generation for the eBPF map.
//! - [`namespace`] — User namespace delegation via the "nsenter dance": entering a
//!   target namespace to mount bpffs with delegation options.
//! - [`protocol`] — Wire protocol and client library for the proxy execution mode.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use bpf_rbacd::policy::Policy;
//!
//! // Load policy from YAML
//! let policy = Policy::load("/etc/bpf-rbac/policy.yaml").unwrap();
//!
//! // Resolve a user's role from their Unix groups
//! let groups = vec!["alice".into(), "ebpf".into()];
//! let role_name = policy.get_role_for_groups(&groups);
//! assert_eq!(role_name, Some("ebpf".to_string()));
//!
//! // Check what operations the role permits
//! let role = policy.roles().get("ebpf").unwrap();
//! assert!(policy.is_prog_op_allowed(role, "kprobe", "load"));
//! assert!(!policy.is_prog_op_allowed(role, "xdp", "load"));
//!
//! // Generate u64 bitmaps for the eBPF policy map
//! let cmd_bitmap: u64 = policy.commands_bitmap(role);
//! let prog_bitmap: u64 = policy.prog_types_bitmap(role);
//! let map_bitmap: u64 = policy.map_types_bitmap(role);
//! ```
//!
//! ## Kernel requirements
//!
//! - Linux 6.1+ with `CONFIG_BPF_SYSCALL=y`
//! - `CONFIG_BPF_LSM=y` and `bpf` in the active LSM list (for capability-granting mode)
//! - `CONFIG_DEBUG_INFO_BTF=y` (for CO-RE and BTF support)
//! - `CONFIG_USER_NS=y` (for namespace delegation)

pub mod namespace;
pub mod policy;
pub mod protocol;
