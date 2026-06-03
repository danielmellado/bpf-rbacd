# bpf-rbacd Design Proposal

| Field            | Value                                                |
| ---------------- | ---------------------------------------------------- |
| **Status**       | WIP                                                  |
| **Authors**      | Daniel Mellado, Viktor Malik, Toke Høiland-Jørgensen |
| **Last Updated** | 2026-06-03                                           |

---

## Problem Statement

Today, eBPF access is a privileged operation granted through system-wide capabilities (`CAP_BPF` combined with one or more of `CAP_PERFMON`, `CAP_SYS_ADMIN`, and `CAP_NET_ADMIN`). This makes it an all-or-nothing proposition—an eBPF-based application essentially needs privileges close to indistinguishable from root.

The goal is to allow **granular access** to eBPF for applications running on a system, using a **role-based delegation (RBAC) system**—for example, per-service access, per-container access, etc.

### Business Context

The business need is primarily driven by **OpenShift**, which requires a way to grant BPF access inside containers without granting full host system access. The RBAC system is designed to be sufficiently general for **RHEL and Fedora** as well, given existing community interest for BPF access delegation in Fedora.

### Why Capability Granting (Not Just Proxy Execution)

The current bpf-rbacd uses a **proxy execution model**: the daemon executes BPF syscalls on behalf of clients and passes back file descriptors. This has limitations:

- The `bpf()` syscall is the de facto standard; all commonly used libraries (libbpf, cilium/ebpf) wrap it directly
- Applications that dynamically generate BPF bytecode or use BPF skeletons cannot split out to an external loader
- Proxy execution requires implementing wrappers for all BPF operations and tracking kernel developments

Because we cannot require application changes, we need a **capability-granting** model where applications use the standard `bpf()` syscall directly, with an RBAC system controlling what they are permitted to do.

---

## Prerequisites

### User Namespace Requirements

- A **user namespace with its own mount namespace**
- The user namespace serves as the **identifier for privilege assignment** (the system does not differentiate individual processes inside the user namespace)
- The user namespace is delegated a set of privileges dependent on the assigned role and policy

### Container Environments

- The pod/container needs to be in its **own user namespace**
- OpenShift supports user namespaces from version **4.21**
- Kubernetes user namespaces are GA as of **v1.36**

### Non-Container Environments (RHEL/Fedora)

- The delegating entity (bpf-rbacd) needs to set up the user namespace
- Desktop users in the init user namespace require the **proxy daemon** approach (existing model)

---

## Architecture

### Components Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                 Privileged Daemon (bpf-rbacd)                   │
│  - Reads policy configuration                                   │
│  - Performs privilege delegation via nsenter + bpffs mount      │
│  - Populates eBPF map with policy information                   │
│  - Loads and manages the LSM program                            │
└─────────────────────────────┬───────────────────────────────────┘
                              │ writes policy
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     eBPF Map (Policy Store)                     │
│  - Keyed by user namespace inode ID (u64)                       │
│  - Contains policy bitmaps for LSM decisions                    │
└─────────────────────────────┬───────────────────────────────────┘
                              │ reads policy
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Linux Security Module (LSM in eBPF)                │
│  - Enforces granular permissions per user namespace             │
│  - Hooks: security_bpf, security_bpf_prog_load,                 │
│           security_bpf_map_create                               │
└─────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component            | Role                                                                  |
| -------------------- | --------------------------------------------------------------------- |
| **bpf-rbacd daemon** | Reads policy, performs namespace delegation, populates map, loads LSM |
| **eBPF LSM**         | Enforces granular permissions based on policy in eBPF map             |
| **eBPF map**         | Communication channel between daemon and LSM, keyed by userns ID      |
| **Proxy mode**       | Fallback for init_user_ns clients (existing functionality)            |

The LSM and the daemon are **logically separate components** but part of the same codebase. They communicate via the eBPF map.

---

## Method of Privilege Delegation

### The nsenter Dance

The daemon must **enter the target user namespace** before mounting bpffs. A simple bind-mount from the host will NOT work because the bpffs superblock's `s_user_ns` would still reference `init_user_ns`, causing token creation to fail with `EPERM`.

```
1. bpf-rbacd (host context)
       │
       │ setns(target_userns_fd, CLONE_NEWUSER)
       │ setns(target_mntns_fd, CLONE_NEWNS)
       ▼
2. bpf-rbacd (now inside target namespace context)
       │
       │ mount -t bpf bpf /sys/fs/bpf -o delegate_cmds=...,delegate_progs=...
       │ (s_user_ns = target_userns)
       ▼
3. bpf-rbacd exits back to host context

4. Client (inside target userns) obtains token from bpffs
       │
       │ libbpf/go-bpf acquires token automatically
       │ bpf() syscall with token → kernel checks pass
       ▼
5. LSM enforcement: kernel calls security_bpf_prog_load, etc.
       LSM reads policy map by userns ID → allow/deny
```

### Capability Assignment

The application inside the user namespace needs Linux capabilities **scoped to the namespace**:

| Capability      | Required For                                       |
| --------------- | -------------------------------------------------- |
| `CAP_BPF`       | All BPF operations                                 |
| `CAP_PERFMON`   | Tracing program types (kprobe, tracepoint)         |
| `CAP_NET_ADMIN` | Network program types (XDP, TC) and some map types |

An application can **drop capabilities** after installing its programs.

### Policy Map Population

After mounting bpffs, the daemon populates the eBPF map:

```rust
let key = PolicyKey { userns_id: target_userns_inum };
let value = PolicyValue {
    allowed_cmds: role.commands_bitmap(),
    allowed_prog_types: role.prog_types_bitmap(),
    allowed_map_types: role.map_types_bitmap(),
};
policy_map.insert(key, value, 0)?;
```

---

## Policy Structure

### Policy Model

- **Allow-list only**, always **fails closed** (anything not explicitly allowed is denied)
- **System-wide policy** from global configuration file
- **Role-specific policies** attached to containers/services
- **Effective policy** = set intersection of system-wide and role-specific

### Policy Dimensions

| Dimension                     | Description                                                                               |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| **Allowed bpf() commands**    | Which syscall commands can be invoked                                                     |
| **Allowed map types**         | Which map types can be created, with operations (create/read/write)                       |
| **Allowed program types**     | Which program types can be loaded, with operations (load/attach/detach/test_run/bind_map) |
| **Allowed attachment points** | Where programs can attach (device names, function names, tracepoints)                     |
| **Allowed helpers/kfuncs**    | Which BPF helpers and kfuncs are permitted (future work)                                  |

### Policy Format

```yaml
# /etc/bpf-rbac/policy.yaml

system_policy:
  commands:
    [
      PROG_LOAD,
      MAP_CREATE,
      MAP_LOOKUP_ELEM,
      MAP_UPDATE_ELEM,
      MAP_DELETE_ELEM,
      LINK_CREATE,
      OBJ_PIN,
      OBJ_GET,
      BTF_LOAD,
    ]
  prog_types:
    kprobe: [load, attach, detach]
    tracepoint: [load, attach, detach]
    xdp: [load, attach, detach]
    sched_cls: [load, attach, detach]
  map_types:
    hash: [create, read, write]
    array: [create, read, write]
    ringbuf: [create, read]
    perf_event_array: [create, read]

roles:
  ebpf:
    groups: [ebpf]
    commands:
      [PROG_LOAD, MAP_CREATE, MAP_LOOKUP_ELEM, MAP_UPDATE_ELEM, LINK_CREATE]
    prog_types:
      kprobe: [load, attach]
      tracepoint: [load, attach]
      perf_event: [load, attach]
    map_types:
      hash: [create, read, write]
      array: [create, read, write]
      ringbuf: [create, read]

  ebpf-net:
    groups: [ebpf-net]
    commands:
      [PROG_LOAD, MAP_CREATE, MAP_LOOKUP_ELEM, MAP_UPDATE_ELEM, LINK_CREATE]
    prog_types:
      xdp: [load, attach, detach]
      sched_cls: [load, attach, detach]
      socket_filter: [load, attach]
    map_types:
      hash: [create, read, write]
      devmap: [create, read, write]
      xskmap: [create, read, write]

  ebpf-admin:
    groups: [ebpf-admin, wheel]
    commands: [any]
    prog_types: { any: [any] }
    map_types: { any: [any] }
```

### Default Policy

A default policy representing "reasonable defaults" is compiled into the daemon and used when no configuration file is present. The contents of this default policy will be defined as part of the implementation.

---

## LSM Implementation (Aya)

### Hooks

The eBPF LSM implements the following hooks:

#### `security_bpf` — Syscall command filtering

```rust
#[lsm(hook = "bpf")]
pub fn bpf_rbac_bpf(ctx: LsmContext) -> i32 {
    // Extract cmd from context
    // Lookup policy by current userns ID
    // Check if cmd is in allowed_cmds bitmap
    // Return 0 (allow) or -EPERM (deny)
}
```

#### `security_bpf_prog_load` — Program type filtering

```rust
#[lsm(hook = "bpf_prog_load")]
pub fn bpf_rbac_prog_load(ctx: LsmContext) -> i32 {
    // Extract prog_type from bpf_prog struct
    // Lookup policy by current userns ID
    // Check if prog_type is in allowed_prog_types bitmap
    // Return 0 (allow) or -EPERM (deny)
}
```

#### `security_bpf_map_create` — Map type filtering

```rust
#[lsm(hook = "bpf_map_create")]
pub fn bpf_rbac_map_create(ctx: LsmContext) -> i32 {
    // Extract map_type from bpf_map struct
    // Lookup policy by current userns ID
    // Check if map_type is in allowed_map_types bitmap
    // Return 0 (allow) or -EPERM (deny)
}
```

### Shared Types

Defined in `bpf-rbacd-common/`:

```rust
#[repr(C)]
pub struct PolicyKey {
    pub userns_id: u64,
}

#[repr(C)]
pub struct PolicyValue {
    pub allowed_cmds: u32,
    pub allowed_prog_types: u32,
    pub allowed_map_types: u32,
    pub allowed_attach_types: u32,
}
```

### Bootstrap Consideration

Loading the LSM itself requires BPF privileges. bpf-rbacd runs as a privileged daemon (root or `CAP_BPF` + `CAP_SYS_ADMIN`) and loads the LSM at startup, before any delegated namespaces are created.

---

## Dual Mode Operation

bpf-rbacd will support **two modes simultaneously**:

| Mode                    | Target Users                           | Mechanism                                |
| ----------------------- | -------------------------------------- | ---------------------------------------- |
| **Capability granting** | Containers/services in user namespaces | Token delegation + LSM enforcement       |
| **Proxy execution**     | Desktop users in init_user_ns          | Daemon executes BPF on behalf (existing) |

This allows the daemon to serve both use cases from a single process.

---

## Implementation Phases

### Phase 1: Foundation ✅

Building blocks: design, policy engine, shared types, eBPF LSM programs,
and namespace delegation library. Each component is independently testable.

- [x] Create this design document
- [x] Define policy schema with commands, prog_types, map_types and per-type operations
- [x] Implement policy engine (`src/policy.rs`): parsing, bitmap generation, system-policy intersection
- [x] Create `bpf-rbacd-common` crate with shared `#[repr(C)]` types (`PolicyKey`, `PolicyValue`)
- [x] Create `bpf-rbacd-ebpf` crate with three LSM hooks (`security_bpf`, `security_bpf_prog_load`, `security_bpf_map_create`)
- [x] Implement namespace delegation library (`src/namespace.rs`): `setns()` entry, bpffs mounting, delegation, revocation
- [x] Add protocol module for proxy-mode fallback (`src/protocol.rs`)
- [x] Maintain backward compatibility with existing proxy mode

**Note — stubbed in this phase:**

- The userns ID resolver in `bpf-rbacd-ebpf` returns 0 (needs CO-RE/BTF access to `current->nsproxy->user_ns->ns.inum`)

### Phase 2: Component Testing ✅

Verify each building block works in isolation before wiring them together.

- [x] Unit tests for policy engine (22 tests: role assignment, per-type operations, bitmap generation, admin/net roles, system-policy intersection, YAML loading)
- [x] Namespace delegation tests (8 tests: userns creation, target namespace resolution, delegation lifecycle, mount data, bpffs detection)
- [x] LSM smoke tests (4 tests: eBPF binary validation, load+attach, policy map population)
- [x] CI workflow: workspace lint, eBPF crate build (`bpfel-unknown-none`), non-privileged tests, rustdoc with warnings-as-errors
- [x] Dependabot coverage for both workspace and `bpf-rbacd-ebpf` crate

### Phase 3: Daemon Integration (next)

Wire the components into a running system. This is where the daemon
becomes a functioning eBPF RBAC enforcer.

- [ ] Implement userns ID resolver via CO-RE/BTF (`current->nsproxy->user_ns->ns.inum`) — replace the stub
- [ ] Load and manage LSM lifecycle at daemon startup
- [ ] Add container/namespace discovery (inotify on `/proc`, cgroup events, or CRI hooks)
- [ ] Wire namespace delegation into daemon main loop (on namespace event: delegate, populate map)
- [ ] Populate eBPF policy map per delegated namespace
- [ ] Policy hot-reload: update map entries when policy file changes

### Phase 4: End-to-End Validation (future)

Test the complete system in real environments.

- [ ] End-to-end testing with podman user namespaces
- [ ] End-to-end testing with systemd `PrivateBPF=`
- [ ] Revocation testing: remove map entry, verify LSM denies subsequent operations
- [ ] Multi-role testing: multiple namespaces with different policies simultaneously
- [ ] Performance benchmarking of LSM hook overhead

---

## Known Limitations and Open Questions

| Item                          | Status        | Notes                                                                   |
| ----------------------------- | ------------- | ----------------------------------------------------------------------- |
| Program/map type restriction  | Feasible      | Via LSM hooks                                                           |
| Syscall command restriction   | Feasible      | Via `security_bpf` hook                                                 |
| Attachment point restriction  | Partial       | Devices feasible via `security_netlink_send`; functions harder          |
| Helper/kfunc restriction      | TBD           | May require kernel changes; not inspectable from LSM hook easily        |
| Bind-mount of bpffs from host | Does NOT work | Must enter target userns before mounting; `s_user_ns` set at mount time |
| Init user namespace users     | Proxy only    | Cannot use BPF tokens in init_user_ns (`EOPNOTSUPP`)                    |

### Open Questions

1. **Container discovery**: How does the daemon learn about new containers/namespaces that need delegation? Options: cgroup notifications, container runtime hooks, CRI plugin.

2. **Policy hot-reload**: When policy changes, how are running namespaces updated? The eBPF map can be updated in-place, but existing tokens are already issued.

3. **Default policy contents**: What constitutes "reasonable defaults" for a Fedora system?

4. **Revocation**: How to revoke access from a running namespace? Removing the map entry will cause the LSM to deny future operations, but existing FDs remain valid.

---

## Crate Structure

```
bpf-rbacd/
├── src/                        # Daemon + proxy (existing, enhanced)
│   ├── main.rs                 # Daemon entry point
│   ├── lib.rs                  # Library exports
│   ├── policy.rs               # Enhanced policy parsing
│   ├── protocol.rs             # Client protocol (proxy mode)
│   ├── namespace.rs            # NEW: namespace delegation logic
│   └── bin/
│       └── bpf-rbac.rs         # CLI client
├── bpf-rbacd-common/           # NEW: shared types
│   ├── Cargo.toml
│   └── src/lib.rs
├── bpf-rbacd-ebpf/             # NEW: eBPF LSM programs
│   ├── Cargo.toml
│   └── src/main.rs
├── docs/
│   └── DESIGN.md               # This document
├── config/
│   ├── policy.yaml             # Enhanced policy format
│   └── bpf-rbacd.service
└── tests/
```

---

## References

- [eBPF RBAC Design Proposal](../fedora-proposal.md) — Fedora change proposal
- [kernel/bpf/token.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/bpf/token.c) — BPF token implementation
- [Aya](https://github.com/aya-rs/aya) — eBPF library for Rust
- [bpfman](https://bpfman.io/) — BPF management daemon
- [systemd PrivateBPF](https://github.com/systemd/systemd/blob/main/test/units/TEST-07-PID1.private-bpf.sh) — systemd bpf_token support
