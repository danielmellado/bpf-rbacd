# Developer Guide

A walkthrough of how bpf-rbacd works, aimed at new contributors.

---

## What does bpf-rbacd do?

It controls which applications can use eBPF, and what they're allowed to do
with it. Think of it as a bouncer: instead of giving everyone full BPF access,
it checks a policy and only lets each application do what it's been approved for.

It has two modes:

- **Proxy mode** — the daemon runs BPF syscalls on behalf of unprivileged users
  and passes back file descriptors. This is for desktop users who can't use BPF
  tokens (they're in the init user namespace).

- **Capability-granting mode** — the daemon sets up a namespace so the
  application can call `bpf()` directly, and an eBPF LSM in the kernel enforces
  what's allowed. This is for containers and services.

---

## Repository layout

```
bpf-rbacd/
├── src/
│   ├── main.rs           # Daemon entry point (proxy mode loop)
│   ├── lib.rs             # Crate root, re-exports modules
│   ├── policy.rs          # Policy engine (YAML parsing, permission checks)
│   ├── namespace.rs       # Namespace delegation (setns, bpffs mounting)
│   ├── protocol.rs        # Client-daemon protocol (proxy mode)
│   └── bin/
│       └── bpf-rbac.rs    # CLI client for proxy mode
├── bpf-rbacd-common/      # Shared types (used by both userspace and eBPF)
│   └── src/lib.rs         # PolicyKey, PolicyValue, flag/enum constants
├── bpf-rbacd-ebpf/        # eBPF LSM programs (runs inside the kernel)
│   └── src/main.rs        # Three LSM hooks
├── config/
│   └── policy.yaml        # Example policy
├── tests/
│   └── integration.rs     # Integration test suite
└── docs/
    ├── DESIGN.md           # Design proposal
    └── DEVELOPMENT.md      # This file
```

---

## How proxy mode works

This is the original mode and the only one currently wired into the daemon.

### Walkthrough

```
1. Daemon starts, loads policy from /etc/bpf-rbac/policy.yaml
   (or uses built-in defaults).

2. Daemon opens a Unix socket at /run/bpf-rbac.sock
   and waits for connections.

3. Client connects (e.g. via the bpf-rbac CLI).
   The kernel fills in the client's UID/PID via SO_PEERCRED — this
   can't be spoofed.

4. Daemon looks up the client's Unix groups and finds their role
   in the policy (e.g. "ebpf", "ebpf-net", "ebpf-admin").

5. Client sends a request (e.g. "create a hash map").

6. Daemon checks: is this role allowed to do this operation?
   If no → responds with Denied.
   If yes → the daemon itself calls bpf() (it runs as root),
   then passes the resulting file descriptor back to the client
   over the socket using SCM_RIGHTS.

7. Client receives the fd and can use it like any BPF fd.
```

### Key files

- `src/main.rs` — the accept loop, credential check, request dispatch
- `src/protocol.rs` — `Request` and `Response` enums, `BpfRbacClient`
- `src/policy.rs` — `Policy::get_role_for_groups()`, `Policy::is_allowed()`
- `src/bin/bpf-rbac.rs` — the CLI that talks to the daemon

### Limitation

The daemon is doing the BPF work on behalf of the client. This means every
BPF operation needs a wrapper in the protocol. Applications can't use libbpf
or aya directly — they have to go through the daemon's socket API.

---

## How capability-granting mode works (planned)

This is the new model. The building blocks exist but aren't wired into the
daemon yet.

### Walkthrough

```
1. Daemon starts, loads policy, loads the eBPF LSM programs into the
   kernel (using Aya). The LSM hooks are now active and watching every
   bpf() call system-wide.

2. A container starts in its own user namespace. The daemon learns about
   it (how exactly is TBD — cgroup events, CRI hooks, etc.).

3. Daemon looks up which role applies to this container.

4. Daemon enters the container's user namespace using setns(), mounts a
   bpffs inside it with the right delegation options, then exits back
   to its own namespace. This is the "nsenter" step — it's needed
   because the kernel records which user namespace owns the bpffs at
   mount time (s_user_ns), and token creation only works if the caller
   is in that namespace.

5. Daemon writes an entry in the eBPF policy map:
     key   = user namespace inode ID
     value = bitmaps of what's allowed (commands, prog types, map types)

6. Application inside the container calls bpf() normally using libbpf,
   cilium/ebpf, aya, etc. The kernel:
   a. Checks the BPF token (obtained from the bpffs) — this handles
      the basic "is this namespace allowed to use BPF at all?" check.
   b. Calls the LSM hooks — these check the policy map to see if this
      specific operation (this command, this program type, this map type)
      is allowed for this namespace.

7. If the policy says yes → operation proceeds normally.
   If the policy says no → the kernel returns EPERM.
```

### Key files

- `src/namespace.rs` — `delegate_bpf_to_namespace()`, `revoke_bpf_delegation()`
- `src/policy.rs` — `commands_bitmap()`, `prog_types_bitmap()`,
  `map_types_bitmap()` (generate the u32 bitmaps for the eBPF map)
- `bpf-rbacd-common/src/lib.rs` — `PolicyKey`, `PolicyValue` (the map schema)
- `bpf-rbacd-ebpf/src/main.rs` — the three LSM hooks

### What's stubbed

The function `get_current_userns_id()` in `bpf-rbacd-ebpf/src/main.rs` currently
returns 0. It needs to walk `current->nsproxy->user_ns->ns.inum` using CO-RE/BTF
to identify which namespace the caller belongs to. Without this, the LSM can't
look up the right policy entry and allows everything through.

---

## The policy engine

All permission checks go through `src/policy.rs`. The policy is YAML:

```yaml
system_policy: # Optional ceiling — no role can exceed this
  commands: [PROG_LOAD, MAP_CREATE]
  prog_types:
    kprobe: [load, attach]

roles:
  ebpf: # Role name
    groups: [ebpf] # Unix groups that get this role
    commands: [PROG_LOAD, MAP_CREATE, LINK_CREATE]
    prog_types:
      kprobe: [load, attach]
    map_types:
      hash: [create, read, write]
```

The effective policy for a role is the **intersection** of the role's own
permissions and the system policy. In the example above, `LINK_CREATE` is
in the role but not in the system policy, so it's denied.

Three built-in roles exist as defaults:

| Role         | Purpose              | Scope                          |
| ------------ | -------------------- | ------------------------------ |
| `ebpf`       | Tracing workloads    | kprobe, tracepoint, perf_event |
| `ebpf-net`   | Networking workloads | xdp, sched_cls, socket_filter  |
| `ebpf-admin` | Full access          | everything (`any`)             |

Role resolution checks groups in priority order: `ebpf-admin` > `ebpf-net` >
`ebpf`, then any other roles.

### Bitmaps

For the eBPF map, the policy engine converts permissions into `u32` bitmaps
where each bit position matches the kernel's enum value:

```
bit 0 = BPF_MAP_CREATE
bit 1 = BPF_MAP_LOOKUP_ELEM
bit 2 = BPF_MAP_UPDATE_ELEM
bit 5 = BPF_PROG_LOAD
...
```

The functions `commands_bitmap()`, `prog_types_bitmap()`, and
`map_types_bitmap()` do this conversion.

---

## The eBPF LSM

Three hooks in `bpf-rbacd-ebpf/src/main.rs`:

| Hook                      | What it checks                   | When it fires         |
| ------------------------- | -------------------------------- | --------------------- |
| `security_bpf`            | Is this `bpf()` command allowed? | Every `bpf()` syscall |
| `security_bpf_prog_load`  | Is this program type allowed?    | Program loading       |
| `security_bpf_map_create` | Is this map type allowed?        | Map creation          |

Each hook follows the same pattern:

1. Is this a kernel-internal call? → allow (skip userspace policy)
2. Get the caller's user namespace ID
3. Look up the policy entry in the map
4. No entry? → allow (not a managed namespace, kernel's own checks apply)
5. `DENY_ALL` flag set? → deny
6. `ALLOW_ALL` flag set? → allow
7. Check if the specific bit is set in the bitmap → allow or deny

---

## Namespace delegation

`src/namespace.rs` handles the namespace entry logic. The key insight:

> You can't just bind-mount a bpffs from the host into a container. The bpffs
> records which user namespace owns it at mount time. If you mount it from the
> host, it's owned by the host namespace, and BPF token creation inside the
> container will fail with EPERM.

So the daemon must:

1. Save its own namespace file descriptors
2. `setns()` into the target's user namespace
3. `setns()` into the target's mount namespace
4. Mount bpffs with `delegate_cmds=...,delegate_progs=...` options
5. `setns()` back to its original namespaces

The `DelegationOpts` struct holds the delegation bitmaps and formats them as
mount options. `TargetNamespace::from_pid()` resolves a PID to its user
namespace inode ID by stat'ing `/proc/{pid}/ns/user`.

---

## Shared types

`bpf-rbacd-common/` is a `no_std` crate that defines the data structures
crossing the kernel/userspace boundary:

- `PolicyKey` — `{ userns_id: u64 }` — the map key
- `PolicyValue` — bitmaps + flags + reserved padding (32 bytes total)
- Constants matching kernel enums (`prog_types::KPROBE = 2`, etc.)

When built with the `user` feature, it also implements `aya::Pod` so the
structs can be used with Aya's typed map APIs in userspace.

---

## Building

```bash
# Main workspace (daemon, policy, tests)
cargo build

# eBPF programs (needs nightly + rust-src + bpf-linker)
cargo install bpf-linker
cd bpf-rbacd-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
```

## Testing

```bash
# All non-privileged tests (policy, namespace helpers, eBPF binary checks)
cargo test

# Root-required tests (namespace delegation, LSM loading)
sudo -E cargo test -- --ignored
```

---

## CI pipeline

CI runs on every push to `main` and on every pull request. It also runs
daily at 04:00 UTC to catch breakage from nightly toolchain or dependency
updates. All jobs must pass before merging.

### Jobs

| Job                   | Toolchain     | What it does                                                                                                                                               |
| --------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Lint**              | stable        | `cargo fmt --all --check` and `cargo clippy --all-targets --all-features -D warnings` on the main workspace                                                |
| **Lint eBPF**         | nightly       | `cargo fmt --check` on `bpf-rbacd-ebpf/` (separate workspace, needs nightly)                                                                               |
| **Build**             | stable + beta | `cargo build --all-targets` and `cargo build --release` to catch regressions on both channels                                                              |
| **Build eBPF**        | nightly       | Installs `bpf-linker`, then builds the eBPF crate for `bpfel-unknown-none` with `-Z build-std=core`. Needs `rust-src` component                            |
| **Unit Tests**        | stable        | `cargo test --lib` (in-module tests) and `cargo test --doc` (doc examples)                                                                                 |
| **Integration Tests** | stable        | `cargo test --test integration` — runs the non-privileged tests from `tests/integration.rs`. Tests that need root or `CAP_BPF` are `#[ignore]` and skipped |
| **Documentation**     | stable        | `cargo doc` with `-D warnings` for the workspace and for `bpf-rbacd-common --features user`                                                                |
| **All CI passed**     | —             | Gate job using `alls-green`. All 7 jobs above must succeed                                                                                                 |

### Why two workspaces?

The eBPF crate (`bpf-rbacd-ebpf/`) targets `bpfel-unknown-none` — a bare-metal
BPF target with no `std`. It can't be in the same Cargo workspace as the daemon
because normal `cargo build` would try to build it for the host target and fail.
So it has its own `[workspace]` in its `Cargo.toml`, and the parent workspace
uses `exclude = ["bpf-rbacd-ebpf"]`.

This means CI has separate lint/build jobs for each workspace.

### Running CI checks locally

```bash
# Lint (same as CI)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

# Lint eBPF
cd bpf-rbacd-ebpf && cargo +nightly fmt -- --check && cd ..

# Build eBPF
cd bpf-rbacd-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
cd ..

# Tests
cargo test --lib
cargo test --doc
cargo test --test integration

# Docs
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p bpf-rbacd-common --features user
```

### Privileged tests

Tests marked `#[ignore]` require root and/or `CAP_BPF`. These don't run in
GitHub Actions (the default runners don't support BPF LSM). To run them
locally:

```bash
sudo -E cargo test -- --ignored
```

These cover namespace delegation with real `setns()` calls, LSM program loading
and attaching, and policy map population via Aya.

### Dependabot

Dependabot watches two directories:

- `/` — main workspace Cargo dependencies (weekly)
- `/bpf-rbacd-ebpf` — eBPF crate dependencies (weekly)
- GitHub Actions versions (weekly)

---

## What's next

See the [Implementation Phases](DESIGN.md#implementation-phases) in DESIGN.md.
The short version: all the pieces are built and tested individually. The next
milestone is wiring them together in `main.rs` so the daemon loads the LSM,
discovers namespaces, delegates, and populates the policy map at runtime.
