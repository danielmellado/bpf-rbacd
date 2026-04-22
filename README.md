# bpf-rbacd

[![CI](https://github.com/danielmellado/bpf-rbacd/actions/workflows/ci.yml/badge.svg)](https://github.com/danielmellado/bpf-rbacd/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Linux](https://img.shields.io/badge/linux-6.1%2B-yellow.svg)](https://kernel.org/)

**Role-Based Access Control for eBPF** - A daemon that enables unprivileged users to safely use eBPF through policy-controlled access.

## Overview

eBPF is a powerful kernel technology, but access typically requires `CAP_BPF` or root privileges. `bpf-rbacd` provides a secure way to grant controlled eBPF access to unprivileged users through Unix group membership and a policy-based proxy daemon.

### Key Features

- **Group-based access control** - Map Unix groups to BPF permissions
- **Fine-grained policies** - Control which program types, map types, and attach points are allowed
- **Kernel-verified authentication** - Uses `SO_PEERCRED` for tamper-proof client identification
- **Secure FD passing** - BPF objects are passed via `SCM_RIGHTS`, not recreated
- **No kernel modifications** - Works with stock Linux kernels (6.1+)
- **Systemd integration** - Runs as a system service with socket activation support

## Why a Daemon?

Due to [kernel limitations](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/token.c#n149), BPF tokens cannot be created in the initial user namespace where desktop/server users operate. The daemon model provides RBAC without requiring:

- Container orchestration
- File capabilities (`setcap`)
- Modifications to user namespaces
- Kernel patches

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     /etc/bpf-rbac/policy.yaml                   │
│   Defines roles: ebpf (tracing), ebpf-net (networking), etc.    │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    bpf-rbacd (privileged daemon)                │
│                                                                 │
│  1. Listens on /run/bpf-rbac.sock                               │
│  2. Authenticates client via SO_PEERCRED (kernel-verified)      │
│  3. Resolves UID → username → groups                            │
│  4. Checks policy: is this operation allowed for this role?     │
│  5. Executes BPF syscall on behalf of client                    │
│  6. Passes resulting FD back via SCM_RIGHTS                     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              Unprivileged Client (bpf-rbac CLI / library)       │
│                                                                 │
│  • Receives map/program FDs from daemon                         │
│  • Interacts with BPF objects directly via received FDs         │
│  • No CAP_BPF or root privileges required                       │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Linux kernel 6.1+ (with BPF support)
- Rust 1.85+ (for building)
- systemd (for service management)

### Building

```bash
# Clone the repository
git clone https://github.com/danielmellado/bpf-rbacd.git
cd bpf-rbacd

# Build release binaries
cargo build --release

# Binaries are in target/release/
ls target/release/bpf-rbac*
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
sudo groupadd -r ebpf-admin  # Full BPF access (optional)

# Enable and start the daemon
sudo systemctl enable --now bpf-rbacd
```

### Granting Access

```bash
# Add a user to the ebpf group (for tracing)
sudo usermod -aG ebpf alice

# User must log out/in or run:
newgrp ebpf
```

### Using BPF as an Unprivileged User

```bash
# Check your access level
$ bpf-rbac status
Connected to: /run/bpf-rbac.sock
Your roles: ebpf
Allowed operations:
  Maps: hash, array, percpu_hash, percpu_array, ringbuf
  Programs: kprobe, uprobe, tracepoint, perf_event

# Create a BPF map (no sudo required!)
$ bpf-rbac create-map --type hash --name my_counters \
    --key-size 4 --value-size 8 --max-entries 1024
✓ Created map 'my_counters' (fd=3)

# Load a BPF program
$ bpf-rbac load-prog --type kprobe --name my_probe ./probe.bpf.o
✓ Loaded program 'my_probe' (fd=4)
```

## Policy Configuration

The policy file defines what each role can do:

```yaml
# /etc/bpf-rbac/policy.yaml

roles:
  # Tracing role - for observability tools
  ebpf:
    description: "Tracing and observability workloads"
    groups:
      - ebpf
    map_types:
      - hash
      - array
      - percpu_hash
      - percpu_array
      - ringbuf
      - perf_event_array
    prog_types:
      - kprobe
      - kretprobe
      - uprobe
      - uretprobe
      - tracepoint
      - perf_event
    attach_types:
      - probe

  # Networking role - for XDP/TC programs
  ebpf-net:
    description: "Networking workloads (XDP, TC)"
    groups:
      - ebpf-net
    map_types:
      - hash
      - array
      - lpm_trie
      - devmap
      - cpumap
    prog_types:
      - xdp
      - sched_cls
      - sched_act
    attach_types:
      - xdp
      - tc

  # Admin role - unrestricted access
  ebpf-admin:
    description: "Full BPF access"
    groups:
      - ebpf-admin
    allow_all: true
```

### Policy Reload

```bash
# After editing policy.yaml
sudo systemctl reload bpf-rbacd
```

## Security Model

| Property | Implementation |
|----------|----------------|
| **Authentication** | Kernel-verified `SO_PEERCRED` - cannot be spoofed |
| **Authorization** | Group membership + policy file |
| **Least privilege** | Only allowed program/map types per role |
| **Audit trail** | All operations logged via journald |
| **FD isolation** | Each FD tied to receiving process |
| **No privilege escalation** | Daemon runs as root, clients stay unprivileged |

### Threat Model

**Protected against:**
- Unprivileged users creating arbitrary BPF programs
- Users bypassing group-based access control
- UID/GID spoofing (kernel verifies credentials)

**Not protected against:**
- Malicious BPF programs from authorized users (kernel verifier handles this)
- Daemon compromise (runs as root)
- Policy misconfiguration

## How It Works

1. **Client connects** to `/run/bpf-rbac.sock`
2. **Daemon extracts credentials** via `getsockopt(SO_PEERCRED)` - kernel-verified
3. **UID → username → groups** resolved via `getpwuid()` / `getgrouplist()`
4. **Policy check**: Does any of the user's groups grant the requested operation?
5. **BPF syscall executed** by daemon (which has `CAP_BPF`)
6. **FD sent to client** via `sendmsg()` with `SCM_RIGHTS`
7. **Client uses FD** directly for subsequent BPF operations

The user never makes BPF syscalls directly - they receive file descriptors for objects created by the daemon.

## Comparison with Alternatives

| Approach | Pros | Cons |
|----------|------|------|
| **bpf-rbacd** | Fine-grained RBAC, no kernel mods | Requires daemon |
| `setcap cap_bpf` | Simple | All-or-nothing, persists in binary |
| BPF tokens | Kernel-native | Only works in containers |
| `sudo` | Universal | No fine-grained control |
| `unprivileged_bpf_disabled=0` | Simple | Security risk, global |

## Project Structure

```
bpf-rbacd/
├── src/
│   ├── main.rs          # Daemon entry point
│   ├── lib.rs           # Library exports
│   ├── policy.rs        # YAML policy parsing and evaluation
│   ├── protocol.rs      # Client-daemon protocol + client library
│   └── bin/
│       └── bpf-rbac.rs  # CLI client
├── tests/
│   ├── integration.rs   # Integration tests
│   └── utils.rs         # Test utilities
├── xtask/               # Task runner (Aya-style)
│   └── src/main.rs
├── config/
│   ├── policy.yaml      # Example RBAC policy
│   └── bpf-rbacd.service # Systemd unit file
├── .github/
│   ├── dependabot.yml   # Automated dependency updates
│   └── workflows/
│       └── ci.yml       # CI workflow
├── .cargo/
│   └── config.toml      # cargo xtask alias
├── LICENSE-MIT
├── LICENSE-APACHE
└── README.md
```

## Testing

The project uses the **xtask pattern** (like [Aya](https://github.com/aya-rs/aya)) for development tasks.

### Running Tests

```bash
# Run all tests (requires sudo for integration tests)
cargo xtask test

# Run with verbose output
cargo xtask test --verbose

# Run only unit tests (no root required)
cargo test --lib
```

### What Gets Tested

| Test | Description |
|------|-------------|
| `allowed_hash_map` | User in `ebpf` group creates hash map |
| `allowed_array_map` | User in `ebpf` group creates array map |
| `denied_hash_map` | User NOT in `ebpf` group is denied |
| `denied_array_map` | User NOT in `ebpf` group is denied |

### Test Structure (Aya-style)

```
bpf-rbacd/
├── tests/
│   ├── integration.rs    # Rust integration tests
│   └── utils.rs          # Test utilities (guards)
├── xtask/                # Task runner (like Aya)
│   ├── Cargo.toml
│   └── src/main.rs       # Test orchestration
└── .cargo/
    └── config.toml       # cargo xtask alias
```

### Other xtask Commands

```bash
# Build release binaries
cargo xtask build

# Install to /usr/local/bin
cargo xtask install

# Clean build artifacts
cargo xtask clean
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development

```bash
# Build
cargo build

# Run unit tests
cargo test --lib

# Run integration tests (requires root)
cargo xtask test

# Run with debug logging
RUST_LOG=debug cargo run --bin bpf-rbacd

# Format code
cargo fmt

# Lint
cargo clippy
```

## Related Projects

- [Aya](https://github.com/aya-rs/aya) - eBPF library for Rust
- [bpfman](https://github.com/bpfman/bpfman) - BPF program manager
- [libbpf](https://github.com/libbpf/libbpf) - BPF library for C

## License

bpf-rbacd is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
