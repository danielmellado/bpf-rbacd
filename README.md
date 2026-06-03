# bpf-rbacd

[![CI](https://github.com/danielmellado/bpf-rbacd/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/danielmellado/bpf-rbacd/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Linux](https://img.shields.io/badge/linux-6.1%2B-yellow.svg)](https://kernel.org/)

**Role-Based Access Control for eBPF** — A daemon that enables unprivileged users and containers to safely use eBPF through policy-controlled access.

## Overview

eBPF is a powerful kernel technology, but access typically requires `CAP_BPF` or root privileges. `bpf-rbacd` provides a secure way to grant controlled eBPF access through two complementary modes:

- **Capability granting** — For containers and services in user namespaces. Delegates BPF privileges via [BPF tokens](https://docs.kernel.org/bpf/bpf_token.html) and enforces granular policies through an eBPF LSM.
- **Proxy execution** — For desktop users in the initial user namespace (where BPF tokens are not supported). Executes `bpf()` syscalls on behalf of clients and passes back file descriptors via `SCM_RIGHTS`.

### Key Features

- **Granular policy engine** — Control which syscall commands, program types, and map types each role can use, with per-type operation granularity (load/attach/detach, create/read/write)
- **System-policy intersection** — A system-wide policy caps all roles, ensuring no role can exceed administrator-defined limits
- **eBPF LSM enforcement** — Three LSM hooks (`security_bpf`, `security_bpf_prog_load`, `security_bpf_map_create`) enforce policy in-kernel per user namespace
- **Namespace delegation** — "nsenter dance" mounts bpffs from within target namespaces so `BPF_TOKEN_CREATE` works correctly
- **Group-based access control** — Map Unix groups to BPF permission roles
- **Kernel-verified authentication** — Uses `SO_PEERCRED` for tamper-proof client identification in proxy mode
- **Dual-mode operation** — Serves both container and desktop use cases from a single daemon

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│              bpf-rbacd (privileged daemon)               │
│                                                          │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Policy   │  │  Namespace   │  │  Proxy Handler   │  │
│  │   Engine   │  │  Delegation  │  │  (SCM_RIGHTS)    │  │
│  └─────┬──────┘  └──────┬───────┘  └──────┬───────────┘  │
│        │                │                 │              │
│        ▼                ▼                 ▼              │
│  ┌──────────┐    ┌───────────┐    ┌──────────────────┐   │
│  │ eBPF Map │    │  bpffs +  │    │   Unix Socket    │   │
│  │ (policy) │    │  tokens   │    │  /run/bpf-rbac   │   │
│  └────┬─────┘    └───────────┘    └──────────────────┘   │
│       │                                                  │
│       ▼                                                  │
│  ┌──────────────────────────────────────────────────┐    │
│  │              eBPF LSM Programs                   │    │
│  │  security_bpf · security_bpf_prog_load ·         │    │
│  │  security_bpf_map_create                         │    │
│  └──────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
┌──────────────────┐    ┌──────────────────────────────┐
│  Container /     │    │  Desktop user                │
│  Service in      │    │  (init_user_ns)              │
│  user namespace  │    │                              │
│                  │    │  Connects via Unix socket,   │
│  Uses BPF token  │    │  receives FDs via SCM_RIGHTS │
│  from bpffs      │    │                              │
└──────────────────┘    └──────────────────────────────┘
```

## Quick Start

### Prerequisites

- Linux kernel 6.1+ with `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_LSM=y` with `bpf` in the active LSM list (for capability-granting mode)
- `CONFIG_DEBUG_INFO_BTF=y` (for BTF/CO-RE support)
- Rust 1.85+ (stable) and nightly (for eBPF crate)

### Building

```bash
git clone https://github.com/danielmellado/bpf-rbacd.git
cd bpf-rbacd

# Build the userspace daemon and client
cargo build --release

# Build the eBPF LSM programs (requires nightly + rust-src)
cd bpf-rbacd-ebpf
cargo +nightly build -Z build-std=core --target bpfel-unknown-none
cd ..
```

### Installation

```bash
# Install binaries
sudo install -m 755 target/release/bpf-rbacd /usr/libexec/
sudo install -m 755 target/release/bpf-rbac /usr/bin/

# Install configuration
sudo mkdir -p /etc/bpf-rbac
sudo install -m 644 config/policy.yaml /etc/bpf-rbac/

# Install systemd service
sudo install -m 644 config/bpf-rbacd.service /etc/systemd/system/
sudo systemctl daemon-reload

# Create RBAC groups
sudo groupadd -r ebpf        # Tracing workloads
sudo groupadd -r ebpf-net    # Networking workloads
sudo groupadd -r ebpf-admin  # Full BPF access

# Enable and start the daemon
sudo systemctl enable --now bpf-rbacd
```

### Granting Access

```bash
# Add a user to the tracing role
sudo usermod -aG ebpf alice

# User must log out/in or run:
newgrp ebpf
```

### Using BPF as an Unprivileged User (Proxy Mode)

```bash
# Check your access level
$ bpf-rbac status
Connected to: /run/bpf-rbac.sock
Your roles: ebpf
Allowed operations:
  Maps: hash, array, percpu_hash, percpu_array, ringbuf
  Programs: kprobe, uprobe, tracepoint, perf_event

# Create a BPF map (no sudo required)
$ bpf-rbac create-map --type hash --name my_counters \
    --key-size 4 --value-size 8 --max-entries 1024
```

## Policy Configuration

Policies are defined in YAML and support three layers of control:

```yaml
# /etc/bpf-rbac/policy.yaml

# System-wide ceiling — no role can exceed this
system_policy:
  commands:
    [
      PROG_LOAD,
      MAP_CREATE,
      MAP_LOOKUP_ELEM,
      MAP_UPDATE_ELEM,
      LINK_CREATE,
      OBJ_PIN,
      OBJ_GET,
      BTF_LOAD,
    ]
  prog_types:
    kprobe: [load, attach, detach]
    tracepoint: [load, attach, detach]
    xdp: [load, attach, detach]
  map_types:
    hash: [create, read, write]
    array: [create, read, write]
    ringbuf: [create, read]

roles:
  # Tracing role — effective policy = intersection with system_policy
  ebpf:
    groups: [ebpf]
    commands:
      [
        PROG_LOAD,
        MAP_CREATE,
        MAP_LOOKUP_ELEM,
        MAP_UPDATE_ELEM,
        LINK_CREATE,
        BTF_LOAD,
      ]
    prog_types:
      kprobe: [load, attach]
      tracepoint: [load, attach]
    map_types:
      hash: [create, read, write]
      array: [create, read, write]
      ringbuf: [create, read]

  # Networking role
  ebpf-net:
    groups: [ebpf-net]
    commands:
      [
        PROG_LOAD,
        MAP_CREATE,
        MAP_LOOKUP_ELEM,
        MAP_UPDATE_ELEM,
        LINK_CREATE,
        PROG_ATTACH,
        BTF_LOAD,
      ]
    prog_types:
      xdp: [load, attach, detach]
      sched_cls: [load, attach, detach]
    map_types:
      hash: [create, read, write]
      devmap: [create, read, write]

  # Admin — unrestricted
  ebpf-admin:
    groups: [ebpf-admin, wheel]
    commands: [any]
    prog_types: { any: [any] }
    map_types: { any: [any] }
```

### Policy Model

- **Allow-list only** — anything not explicitly permitted is denied
- **Fails closed** — missing policy or parse errors result in denial
- **Intersection model** — effective policy = role policy AND system policy
- The special value `any` acts as a wildcard

## API Documentation

Generate and view the rustdoc-style API documentation locally:

```bash
cargo doc --no-deps --open
```

This produces documentation for all public types and functions, including:

| Module      | Description                                                                         |
| ----------- | ----------------------------------------------------------------------------------- |
| `policy`    | YAML policy parsing, role resolution, system-policy intersection, bitmap generation |
| `namespace` | User namespace delegation via the "nsenter dance"                                   |
| `protocol`  | Wire protocol and client library for proxy mode                                     |

The shared types crate (`bpf-rbacd-common`) is also documented:

```bash
cargo doc --no-deps -p bpf-rbacd-common --open
```

## Project Structure

```
bpf-rbacd/
├── src/
│   ├── main.rs              # Daemon entry point
│   ├── lib.rs               # Library root with crate-level docs
│   ├── policy.rs            # Policy engine (YAML → bitmaps)
│   ├── protocol.rs          # Proxy-mode wire protocol + client
│   ├── namespace.rs          # Namespace delegation (nsenter dance)
│   └── bin/
│       └── bpf-rbac.rs      # CLI client
├── bpf-rbacd-common/         # Shared #[repr(C)] types
│   ├── Cargo.toml
│   └── src/lib.rs            # PolicyKey, PolicyValue, constants
├── bpf-rbacd-ebpf/           # eBPF LSM programs (Aya)
│   ├── Cargo.toml
│   └── src/main.rs           # LSM hooks: bpf, bpf_prog_load, bpf_map_create
├── docs/
│   └── DESIGN.md             # Design proposal document
├── tests/
│   ├── integration.rs        # Integration + unit tests
│   └── utils.rs              # Test utilities (RAII guards)
├── xtask/                     # Task runner (Aya-style)
│   └── src/main.rs
├── config/
│   ├── policy.yaml           # Example RBAC policy
│   └── bpf-rbacd.service     # Systemd unit file
├── LICENSE-MIT
├── LICENSE-APACHE
└── README.md
```

### Crate Dependency Graph

```
bpf-rbacd (daemon + library)
    └── bpf-rbacd-common (shared types, feature = "user")
            ↑
bpf-rbacd-ebpf (eBPF LSM, target = bpfel-unknown-none)
    └── bpf-rbacd-common (no_std, no features)
```

## Security Model

| Property            | Implementation                                                              |
| ------------------- | --------------------------------------------------------------------------- |
| **Authentication**  | Kernel-verified `SO_PEERCRED` (proxy), user namespace ID (LSM)              |
| **Authorization**   | Group membership + YAML policy + system-policy intersection                 |
| **Enforcement**     | eBPF LSM hooks in kernel (capability mode), daemon-side checks (proxy mode) |
| **Least privilege** | Per-role control over commands, program types, map types, and operations    |
| **Fail closed**     | Unknown operations and missing policy entries are denied                    |
| **Audit trail**     | All operations logged via journald                                          |

## Testing

### Unit Tests (no root required)

```bash
# Run library unit tests
cargo test --lib

# Run all non-root tests from the integration test file
cargo test --test integration
```

### Integration Tests (root required)

```bash
# Run proxy-mode integration tests
cargo xtask test

# Run namespace delegation tests
sudo cargo test --test integration namespace_tests -- --include-ignored

# Run LSM smoke tests (requires eBPF crate built)
sudo cargo test --test integration lsm_tests -- --include-ignored
```

### Building the eBPF Crate

```bash
# Install prerequisites
rustup component add rust-src --toolchain nightly

# Build
cd bpf-rbacd-ebpf
cargo +nightly build -Z build-std=core --target bpfel-unknown-none
```

### Test Coverage

| Test Category                                          | Count  | Root Required |
| ------------------------------------------------------ | ------ | ------------- |
| Policy engine (commands, types, bitmaps, intersection) | 12     | No            |
| Namespace delegation (opts, bpffs mount, lifecycle)    | 8      | Partial       |
| LSM loading (ELF validation, attach, map population)   | 4      | Yes           |
| Proxy mode (allowed/denied map creation)               | 4      | Yes           |
| **Total**                                              | **28** |               |

## Related Projects

- [Aya](https://github.com/aya-rs/aya) — eBPF library for Rust (used for LSM programs)
- [bpfman](https://github.com/bpfman/bpfman) — BPF program manager
- [libbpf](https://github.com/libbpf/libbpf) — BPF library for C (automatic token support)

## License

bpf-rbacd is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
