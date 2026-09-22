# Unprivileged eBPF: RBAC Daemon with LSM Enforcement and Rootless Access

This is a proposed Change for Fedora Linux. This document represents a proposed Change. As part of the Changes process, proposals are publicly announced in order to receive community feedback. This proposal will only be implemented if approved by the Fedora Engineering Steering Committee.

## Summary

Enable unprivileged, policy-controlled eBPF access in Fedora by shipping `bpf-rbacd`, a system daemon that operates in two complementary modes from a single process:

* **Capability granting mode** — For containers and services in user namespaces. Delegates BPF privileges via upstream BPF tokens (kernel 6.9+) and enforces granular, per-namespace policies through three eBPF LSM hooks in-kernel.
* **Proxy execution mode** — For desktop users in the initial user namespace (where BPF tokens are not supported). Executes allowed `bpf()` syscalls on behalf of clients and passes file descriptors back via `SCM_RIGHTS`.

Both modes are governed by a single YAML policy, gated by a distribution-managed `ebpf` system group, and served by the same daemon. The result: containers gain transparent eBPF access with mandatory LSM enforcement; desktop users gain rootless BPF access without `sudo` or `CAP_BPF`.

## Owner

* Name: [Fedora eBPF SIG](https://fedoraproject.org/wiki/SIGs/eBPF)
* FAS group: [@ebpf-sig](https://accounts.fedoraproject.org/group/ebpf-sig/)
* Members:
  * Daniel Mellado — dmellado@fedoraproject.org
  * Toke Høiland-Jørgensen — toke@redhat.com
  * Viktor Malik — vmalik@redhat.com

## Current status

* Targeted release: Fedora Linux 46
* Last updated: 2026-09-22
* Announced:
* Discussion thread:
* FESCo issue:
* Tracker bug:
* Release notes tracker:

## Detailed Description

### Background

eBPF is a powerful kernel technology for networking, observability, and security, but its use requires system-wide capabilities (`CAP_BPF` combined with `CAP_PERFMON`, `CAP_NET_ADMIN`, or `CAP_SYS_ADMIN`). This is an all-or-nothing proposition: applications need privileges close to root, which blocks adoption in containers and restricts desktop developers.

The kernel's BPF token mechanism (Linux 6.9+) allows a privileged issuer to delegate a constrained set of BPF operations to unprivileged consumers inside user namespaces. However, tokens alone have two significant limitations:

1. **No per-entity enforcement.** Token constraints are set at the bpffs mount level and apply uniformly to all consumers. There is no mechanism to give different containers different allowed program types, or to revoke access dynamically.

2. **No desktop path.** BPF tokens are not supported in the initial user namespace (`BPF_TOKEN_CREATE` returns `EOPNOTSUPP`). Desktop developers running tracers or profilers must still use `sudo`.

This change addresses both gaps through a single daemon that operates in two complementary modes simultaneously.

### Dual-mode architecture

`bpf-rbacd` serves two distinct classes of eBPF consumers from a single process, using the same policy engine and the same YAML configuration:

| Mode | Target environment | Mechanism | LSM enforcement |
|------|--------------------|-----------|-----------------|
| **Capability granting** | Containers and services in user namespaces | BPF token delegation via bpffs mount + "nsenter dance" | Yes — three LSM hooks enforce per-namespace policy bitmaps in-kernel |
| **Proxy execution** | Desktop users and applications in the initial user namespace (`init_user_ns`) | Daemon executes `bpf()` on behalf of clients, passes FDs via `SCM_RIGHTS` over a Unix socket | N/A — policy enforced daemon-side before executing the syscall |

**Why two modes?** BPF tokens only work inside user namespaces — the kernel explicitly rejects `BPF_TOKEN_CREATE` in `init_user_ns` with `EOPNOTSUPP`. Containers naturally have user namespaces, so tokens are the right mechanism there. Desktop users do not, so they need a different path. The proxy mode fills that gap without requiring application changes: standard tools like bpftrace or bcc can be adapted to request FDs from the daemon instead of calling `bpf()` directly.

Both modes share the same policy model (allow-list only, fails closed, system-policy intersection) and the same group-based role resolution (`ebpf`, `ebpf-net`, `ebpf-admin`). An administrator writes one policy file and both modes obey it.

```
                    bpf-rbacd (privileged daemon)
                   ┌──────────────────────────────┐
                   │         Policy Engine         │
                   │    (YAML → role → bitmaps)    │
                   └──────┬───────────┬────────────┘
                          │           │
              ┌───────────▼──┐   ┌────▼──────────────┐
              │  Capability  │   │  Proxy execution   │
              │  granting    │   │  (SCM_RIGHTS)      │
              │  mode        │   │  mode              │
              └──────┬───────┘   └────┬───────────────┘
                     │                │
         ┌───────────▼──┐   ┌────────▼────────────┐
         │ Container /  │   │ Desktop user         │
         │ service in   │   │ (init_user_ns)       │
         │ user ns      │   │                      │
         │              │   │ $ bpf-rbac create-map│
         │ Uses BPF     │   │   → daemon executes  │
         │ token from   │   │   → FD passed back   │
         │ bpffs        │   │   via SCM_RIGHTS     │
         │   ↓          │   └─────────────────────-┘
         │ LSM enforces │
         │ per-ns policy│
         └──────────────┘
```

### What this change delivers

#### BPF token delegation and the ebpf system group

`bpf-rbacd` uses systemd-driven bpffs delegation to provide BPF tokens to containers and services in user namespaces:

* A fixed `ebpf` system group gates who may consume the delegated bpffs/token path. The group is for OS-level discovery and packaging defaults; the kernel still enforces token constraints independently.
* The daemon performs the **"nsenter dance"** — entering the target user namespace via `setns()` before mounting bpffs, so the `s_user_ns` is set correctly and `BPF_TOKEN_CREATE` works inside the namespace.
* Integration with systemd `PrivateBPF=` (upstream [PR #36134](https://github.com/systemd/systemd/pull/36134)) enables automatic namespace delegation for systemd-managed services.
* Libraries such as libbpf, bpftool, and bcc automatically discover and use delegated tokens without requiring `sudo`.

#### In-kernel eBPF LSM policy enforcement

The daemon loads eBPF LSM programs at startup that attach to the kernel's security hooks for BPF operations. Each hook looks up the calling process's user namespace inode ID in an eBPF hash map, retrieves the policy bitmaps for that namespace's role, and returns allow or deny. This gives administrators **per-namespace, per-role granularity** enforced in-kernel, on top of the bpffs mount-level token constraints.

**Core hooks** (implemented in both the Aya and C codebases):

| LSM Hook | What it controls | Policy dimension |
|----------|-----------------|------------------|
| `security_bpf` | Every `bpf()` syscall invocation | `allowed_cmds` bitmap (PROG_LOAD, MAP_CREATE, etc.) |
| `security_bpf_prog_load` | Program loading — inspects program type | `allowed_prog_types` bitmap (kprobe, xdp, etc.) |
| `security_bpf_map_create` | Map creation — inspects map type | `allowed_map_types` bitmap (hash, array, etc.) |

**Extended hooks** (implemented in the C codebase — [tohojo/bpf-rbac-lsm](https://github.com/tohojo/bpf-rbac-lsm)):

| LSM Hook | What it controls | Why it matters |
|----------|-----------------|----------------|
| `security_bpf_prog` | FD-level access to existing programs | Controls who can inspect or reuse loaded programs |
| `security_mmap` | Memory-mapping of BPF maps | Controls map data access mode (read/write/exec) |

**Bytecode walking for helper/kfunc policy:** The C implementation also uses open-coded iterators to walk BPF program bytecode at `security_bpf_prog_load` time, extracting the helper function IDs and kfunc BTF IDs that the program calls. This enables a future policy dimension: restricting *which kernel functions* a program may invoke, not just which program type it is. Events are reported to userspace via a BPF ring buffer for audit logging and policy decisions.

**How LSM and tokens complement each other:**

```
Token says "you may load            LSM checks: "your namespace
kprobe programs"                    role only permits tracepoint"
        ↓                                   → DENIED
```

Even if a token is overly permissive (broad bpffs mount options), the per-namespace LSM policy restricts actual operations to the role's intersection with the system policy.

**eBPF program loading at daemon startup:** The daemon loads and attaches the LSM programs before accepting any delegation requests. This requires `CAP_BPF` + `CAP_SYS_ADMIN` on the daemon itself (granted via the systemd unit's `AmbientCapabilities`). Once loaded, the LSM hooks are active system-wide; the eBPF policy map serves as the control plane between the daemon and the LSM.

#### Rootless BPF for desktop users (proxy mode)

For users in the initial user namespace (desktops, developer workstations), `bpf-rbacd` provides a proxy execution mode:

1. User runs `bpf-rbac <command>` (e.g., `bpf-rbac create-map --type hash ...`)
2. The CLI connects to the daemon's Unix socket at `/run/bpf-rbac.sock`
3. The daemon reads `SO_PEERCRED` — kernel-verified, tamper-proof credentials
4. Group membership is resolved to a policy role
5. The daemon executes the allowed `bpf()` syscall with its own privileges
6. Resulting file descriptors are passed back via `SCM_RIGHTS`
7. Denied operations return actionable error messages

### Policy model

Policies are defined in `/etc/bpf-rbac/policy.yaml` using an allow-list model that always fails closed:

```yaml
system_policy:                          # System-wide ceiling
  commands: [PROG_LOAD, MAP_CREATE, MAP_LOOKUP_ELEM, MAP_UPDATE_ELEM,
             LINK_CREATE, OBJ_PIN, OBJ_GET, BTF_LOAD]
  prog_types:
    kprobe: [load, attach, detach]
    tracepoint: [load, attach, detach]
    xdp: [load, attach, detach]
  map_types:
    hash: [create, read, write]
    array: [create, read, write]
    ringbuf: [create, read]

roles:
  ebpf:                                 # Tracing role
    groups: [ebpf]
    commands: [PROG_LOAD, MAP_CREATE, MAP_LOOKUP_ELEM, MAP_UPDATE_ELEM,
               LINK_CREATE, BTF_LOAD]
    prog_types:
      kprobe: [load, attach]
      tracepoint: [load, attach]
    map_types:
      hash: [create, read, write]
      array: [create, read, write]
      ringbuf: [create, read]

  ebpf-net:                             # Networking role
    groups: [ebpf-net]
    prog_types:
      xdp: [load, attach, detach]
      sched_cls: [load, attach, detach]
    map_types:
      hash: [create, read, write]
      devmap: [create, read, write]

  ebpf-admin:                           # Unrestricted
    groups: [ebpf-admin, wheel]
    commands: [any]
    prog_types: {any: [any]}
    map_types: {any: [any]}
```

The effective policy for any role is the **set intersection** of the role policy and the system policy. A role can never exceed administrator-defined system limits.

### Two LSM implementations and the Rust BPF toolchain gap

The eBPF LSM programs exist in two parallel implementations. This is not redundancy — it is a deliberate response to a Rust compiler limitation that currently prevents the Aya-based implementation from using advanced BPF features.

#### The Rust/DWARF/BTF problem

eBPF programs that call kernel functions (kfuncs) or reference kernel symbols (ksyms) require BTF (BPF Type Format) metadata in the compiled ELF. The toolchain flow is:

```
Rust source → rustc (BPF target) → LLVM → ELF with DWARF
    → bpf-linker → ELF with BTF (including .ksyms DATASEC)
        → kernel verifier resolves kfuncs/ksyms at load time
```

The problem: **`rustc` does not emit DWARF debug info for `extern` declarations on BPF targets.** When a Rust eBPF program declares:

```rust
#[link_section = ".ksyms"]
extern "C" {
    static LINUX_KERNEL_VERSION: u32;      // ksym
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32); // kfunc
}
```

…the compiler produces the LLVM global/function declaration but attaches no `DIGlobalVariable` or `DISubprogram` metadata. Without DWARF, `bpf-linker` cannot generate the `.ksyms` BTF DATASEC entry, and the kernel verifier cannot resolve these symbols at load time. The program fails to load.

This blocks:
* **Open-coded iterators** (`bpf_iter_num_new/next/destroy`) — needed for bytecode walking in the `security_bpf_prog_load` hook
* **kfunc calls** (`bpf_task_acquire`, etc.) — needed for CO-RE task/namespace introspection
* **The userns ID resolver** — `current->nsproxy->user_ns->ns.inum` access via BTF, currently stubbed to return 0

The three core bitmap-based hooks (`security_bpf`, `security_bpf_prog_load`, `security_bpf_map_create`) work today with Aya because they only use map lookups and context argument reads — no kfuncs or ksyms. But the extended hooks (bytecode walking, FD access control, mmap control) require kfuncs and are blocked.

#### The upstream Rust compiler fix

We are driving the fix in [rust-lang/rust#161390](https://github.com/rust-lang/rust/pull/161390) ("Generate debug info for BPF extern declarations"). This patch:

* Allows `#[link_section]` on `ForeignStatic` and `ForeignFn` (gated to BPF targets)
* Adds an `LLVMRustDIBuilderCreateGlobalVariableExpression` wrapper exposing the `isDefinition` parameter (the LLVM-C API hard-codes it to `true`)
* Emits `DIGlobalVariable` with `isDefinition: false` for extern statics
* Emits `DISubprogram` without `SPFlagDefinition` for extern functions

This is a reworked version of [#152899](https://github.com/rust-lang/rust/pull/152899), rebased on current `main` with review feedback addressed. It is currently in review with the Rust compiler team (assigned to @jdonszelmann, reviews from @bjorn3 and @tamird). The Aya maintainer (@vadorovsky) is also involved.

Once this lands in nightly `rustc`, the full chain works: Rust eBPF → DWARF with extern metadata → `bpf-linker` → BTF with `.ksyms` → kernel loads kfuncs. This unblocks the complete Aya-based LSM.

#### The C implementation: tohojo/bpf-rbac-lsm

[tohojo/bpf-rbac-lsm](https://github.com/tohojo/bpf-rbac-lsm) is an actively developed C-based LSM implementation (Toke Høiland-Jørgensen, latest commits Sep 2026) that sidesteps the Rust toolchain limitation entirely. It uses:

* **C for the eBPF programs** — compiled with clang/llvm, full BTF/CO-RE support, no DWARF issues
* **Rust + libbpf-rs for userspace** — loads the C eBPF programs via libbpf skeleton generation, processes ring buffer events, manages policies

This implementation is more capable than the Aya version today:

| Feature | Aya (Rust eBPF) | C eBPF + libbpf-rs |
|---------|:---------------:|:------------------:|
| `security_bpf` (command filtering) | ✅ | ✅ |
| `security_bpf_prog_load` (type filtering) | ✅ | ✅ |
| `security_bpf_map_create` (type filtering) | ✅ | ✅ |
| `security_bpf_prog` (FD access) | ❌ | ✅ |
| `security_mmap` (map mmap control) | ❌ | ✅ |
| Userns ID resolution (CO-RE/BTF) | ❌ (stubbed) | ✅ |
| Bytecode walking (open-coded iterators) | ❌ (blocked on rustc) | ✅ |
| Helper/kfunc ID extraction | ❌ (blocked on rustc) | ✅ |
| Policy enforcement per namespace | ❌ (stub returns 0) | ✅ |
| Ring buffer event reporting | ❌ | ✅ |

#### Integration strategy and the path to a pure Rust/Aya stack

The two implementations share the same userspace daemon (`bpf-rbacd`) and the same policy engine. They are designed to converge:

**Phase 1 — Fedora 46 delivery (C eBPF + Rust userspace):**

Use the C eBPF programs from `bpf-rbac-lsm` loaded via `libbpf-rs` in the `bpf-rbacd` Rust userspace daemon. This gives us the full feature set (all hooks, bytecode walking, namespace resolution, policy enforcement) without waiting for the Rust compiler fix. The daemon, policy engine, CLI, and all userspace logic remain in Rust; only the eBPF kernel programs are in C. This is a pragmatic split — the same pattern used by many production eBPF projects (e.g., Cilium, bpfman).

**Phase 2 — After `rustc` fix lands (Aya catches up):**

Once [rust-lang/rust#161390](https://github.com/rust-lang/rust/pull/161390) is merged and reaches stable `rustc`, we migrate the eBPF programs to Rust/Aya. The groundwork is already done:

* The Aya-based LSM in [danielmellado/bpf-rbacd](https://github.com/danielmellado/bpf-rbacd) already compiles and produces correct ELF relocations for the three core hooks.
* The [load-lsm branch](https://github.com/tohojo/bpf-rbacd/tree/load-lsm) already has kfunc declarations and open-coded iterator code that compiles — it only needs the BTF DATASEC generation that the `rustc` fix enables.
* Aya's kfunc relocation support ([aya-rs/aya#1372](https://github.com/aya-rs/aya/pull/1372)) is progressing upstream.

The migration is a drop-in replacement: the userspace daemon, policy engine, and CLI are unchanged. Only the eBPF binary source changes from C to Rust.

**Phase 3 — Target state (pure Rust):**

A fully Rust stack — daemon, CLI, policy engine, *and* eBPF kernel programs — all built with `cargo`. This is the desired end state for `bpf-rbacd` because:

* **Single toolchain:** One `cargo build` compiles everything. No separate clang/llvm dependency for the eBPF programs.
* **Shared types:** The `bpf-rbacd-common` crate already defines `#[repr(C)]` policy types (`PolicyKey`, `PolicyValue`) that compile for both `no_std` (eBPF target) and `std` (userspace). With Aya, these types are shared at compile time with full type safety — no manual struct layout synchronization between C and Rust.
* **Memory safety:** Rust's borrow checker and type system apply to the eBPF programs too. While eBPF's verifier provides runtime safety, compile-time guarantees from Rust catch bugs earlier.
* **Ecosystem alignment:** Aya is the standard Rust eBPF framework. Contributing improvements back (kfunc support, LSM patterns) benefits the entire Rust eBPF community.

The `rustc` fix is not just a `bpf-rbacd` concern — it unblocks kfunc/ksym usage for *every* Rust eBPF program. We are driving this upstream because it is the right thing for the ecosystem, and `bpf-rbacd` is a concrete, high-profile consumer that validates the fix.

This phased approach means the Fedora 46 deliverable is **not blocked by the Rust compiler fix**, while the Rust/Aya migration remains a first-class goal tracked by the eBPF SIG.

### Kernel requirements

| Config | Required for | In Fedora? |
|--------|--------------|--------------------|
| `CONFIG_BPF_SYSCALL=y` | All BPF operations | Yes |
| `CONFIG_BPF_LSM=y` | LSM hook attachment | Yes |
| `bpf` in active LSM list | LSM program loading | Needs verification |
| `CONFIG_DEBUG_INFO_BTF=y` | CO-RE/BTF for portable eBPF | Yes |
| `CONFIG_BPF_TOKEN` | BPF token delegation | Yes |

**Action item:** Verify that `bpf` is in the kernel's compiled-in LSM list or `lsm=` boot parameter. If not, a kernel config change is needed to add `bpf` to the LSM order alongside `lockdown,yama,integrity,selinux`.

## Feedback

The design of `bpf-rbacd` is being presented at [Linux Plumbers Conference 2026](https://lpc.events/event/20/contributions/2441/) (Oct 6, eBPF Track) to solicit community feedback. The talk covers the architecture, policy model, and LSM enforcement, with the goal of making the design useful to other distributions and operators.

Community consultation with kernel, systemd, and security stakeholders is ongoing.

## Benefit to Fedora

* **Security posture:** Moves eBPF access from all-or-nothing capabilities toward granular, role-based delegation. LSM enforcement adds a mandatory kernel-level policy layer that token delegation alone cannot provide.
* **Per-entity granularity:** Different containers, services, or users get different eBPF permissions based on their role — not a single system-wide delegation.
* **Developer experience:** Desktop developers and operators can run eBPF tools without `sudo`, with clear errors when an operation is outside their role's policy.
* **Unified policy:** One YAML file governs both container (LSM + tokens) and desktop (proxy) access. Administrators learn one model.
* **Dynamic policy and revocation:** Policies can be updated at runtime; removing a namespace's map entry causes the LSM to deny subsequent operations without killing processes.
* **Downstream alignment:** Establishes the reference RBAC implementation for RHEL, OpenShift (user namespaces GA in 4.21+), and CoreOS. Kubernetes user namespaces are GA as of v1.36.
* **Rust BPF ecosystem:** The upstream `rustc` fix ([#161390](https://github.com/rust-lang/rust/pull/161390)) benefits the entire Rust eBPF community. `bpf-rbacd` is designed to become a fully pure-Rust eBPF project (daemon + kernel programs via Aya) once the toolchain gap is closed, demonstrating that production eBPF LSM programs can be written entirely in Rust.
* **Community leadership:** Fedora becomes the first distribution with a complete, integrated eBPF RBAC stack spanning containers and desktops.

## Scope

* Proposal owners:

  * Package `bpf-rbacd` (daemon), `bpf-rbac` (CLI client), and `bpf-rbacd-common` (shared types) as RPMs. Source is hosted on [Fedora Forge](https://forge.fedoraproject.org/ebpf/bpf-rbacd).
  * Ship the eBPF LSM programs from [tohojo/bpf-rbac-lsm](https://github.com/tohojo/bpf-rbac-lsm) (C eBPF + libbpf-rs for loading). Migrate to Rust/Aya once [rust-lang/rust#161390](https://github.com/rust-lang/rust/pull/161390) lands.
  * Deliver systemd unit (`bpf-rbacd.service`) with security hardening (`ProtectSystem=strict`, `ProtectHome=true`, capability bounding).
  * Deliver default policy (`/etc/bpf-rbac/policy.yaml`) reviewed with the Security Team.
  * Create `ebpf`, `ebpf-net`, and `ebpf-admin` system groups via `systemd-sysusers`.
  * Implement systemd-driven bpffs delegation (mount units, `PrivateBPF=` coordination).
  * Coordinate with kernel team to ensure `bpf` is in the active LSM list.
  * Drive the Rust compiler fix ([rust-lang/rust#161390](https://github.com/rust-lang/rust/pull/161390)) or use C fallback.
  * Complete the CO-RE/BTF userns ID resolver in the eBPF LSM.
  * Wire container/namespace discovery into the daemon (cgroup events or CRI hooks).
  * Coordinate library/tool updates for automatic token usage (libbpf, bpftool, bcc).
  * File Fedora package review, FESCo process, and tracker bugs.
  * Write Fedora Quick Docs article on usage and security model.

* Other developers:

  * Kernel maintainers: Confirm `CONFIG_BPF_LSM=y` and `bpf` in LSM list; advise on LSM hook semantics and regression triage.
  * systemd maintainers: Coordinate on `PrivateBPF=` integration so systemd-launched services automatically get delegated namespaces.
  * Rust compiler team: Review and land [rust-lang/rust#161390](https://github.com/rust-lang/rust/pull/161390).
  * Aya maintainers: kfunc relocation support ([aya-rs/aya#1372](https://github.com/aya-rs/aya/pull/1372)).
  * Security Team: Review default policy, group membership model, and LSM enforcement guarantees.
  * eBPF tooling maintainers (bcc, bpftool, libbpf consumers): Ensure tools work with proxy-mode FD passing and token-based flows.
  * Container runtime maintainers (podman, CRI-O): Test user namespace + BPF token + LSM enforcement end-to-end.
  * Edition WGs (Workstation, Server, CoreOS): Consider default group membership and documentation per edition.

* Release engineering: #(TBD)

* Policies and guidelines: The initial delivery uses C eBPF programs compiled with clang/llvm and loaded via libbpf-rs — this follows standard Fedora packaging (clang and libbpf are already packaged). The future Aya-based path targets `bpfel-unknown-none` and requires nightly Rust + `rust-src`, which may need a packaging exemption or pre-built binary vendoring when that migration occurs. Default policy requires Security Team review.

* Trademark approval: N/A (not needed for this Change)

* Alignment with the Fedora Strategy: Aligns with secure-by-default, developer-friendly platform, and upstream-first goals. The change drives fixes in `rustc`, Aya, and systemd rather than carrying downstream patches.

## Upgrade/compatibility impact

This change introduces a new opt-in package. It does not modify existing system behavior.

* **Existing systems:** No change unless `bpf-rbacd` is installed. Workflows that use root or explicit capabilities continue to work.
* **New path:** Users or administrators who want unprivileged eBPF install `bpf-rbacd`, add users to the `ebpf`, `ebpf-net`, or `ebpf-admin` groups, and enable the service.
* **Kernel config:** If `bpf` needs to be added to the LSM list, this could interact with other LSM consumers (notably SELinux). Must be coordinated with the kernel team.
* **ABI:** No Fedora-specific ABI commitment beyond documented `bpf()` semantics and the policy YAML format. Tools that gain automatic token discovery may succeed in situations where they previously failed without sudo.

## Early Testing (Optional)

Do you require 'QA Blueprint' support? N

## How To Test

1. **Hardware/data:** Standard x86_64 or aarch64 Fedora install. VM acceptable if BPF features are not stripped.

2. **Prepare:** Install `bpf-rbacd`, start the service, add test user to `ebpf` group.

3. **Proxy mode (desktop):**

```bash
# As a user in the ebpf group:
$ bpf-rbac status
Connected to: /run/bpf-rbac.sock
Your roles: ebpf
Allowed operations:
  Maps: hash, array, percpu_hash, percpu_array, ringbuf
  Programs: kprobe, uprobe, tracepoint, perf_event

# Create a map (should succeed)
$ bpf-rbac create-map --type hash --name test \
    --key-size 4 --value-size 8 --max-entries 64

# Attempt a denied operation (should fail with clear error)
$ bpf-rbac create-map --type devmap --name test \
    --key-size 4 --value-size 8 --max-entries 64
Error: map type 'devmap' is not allowed by your role 'ebpf'
```

4. **LSM enforcement (requires root for setup):** Launch a podman container in a user namespace (`podman run --userns=auto ...`). Verify that the daemon delegates bpffs and populates the policy map. Inside the container, attempt to load an allowed program type (should succeed) and a denied type (should fail with `EPERM`).

5. **Non-member:** As a user NOT in any ebpf group, verify that all operations are denied.

6. **Unit tests (no root required):**

```bash
cargo test --lib               # Policy parsing, bitmaps, intersection
cargo test --test integration  # Non-privileged integration tests
```

7. **Expected results:** Delegated operations succeed within the role's allowlist; out-of-scope operations fail with clear errors; no system instability or privilege escalation beyond the documented policy.

## User Experience

* Most users see no change unless they use eBPF tooling.
* Desktop developers who run tracers or networking experiments may stop needing `sudo` for supported scenarios, with clear errors when an operation is denied.
* Container workloads are transparent — applications use standard `bpf()` with automatic token acquisition; the LSM silently enforces the namespace's policy.
* Administrators get a single documented policy file (`/etc/bpf-rbac/policy.yaml`) and `journalctl -u bpf-rbacd` for audit logging.

## Dependencies

* Linux kernel: 6.9+ with `CONFIG_BPF_TOKEN`, `CONFIG_BPF_LSM=y`, `bpf` in active LSM list, `CONFIG_DEBUG_INFO_BTF=y`
* Rust: Stable 1.85+ (daemon and CLI)
* [libbpf](https://github.com/libbpf/libbpf) and [libbpf-rs](https://github.com/libbpf/libbpf-rs): For loading C-based eBPF LSM programs from the Rust daemon (initial delivery path)
* clang/llvm: For compiling the C eBPF programs with full BTF/CO-RE support
* [Aya](https://github.com/aya-rs/aya): eBPF library for Rust (long-term target once [rust-lang/rust#161390](https://github.com/rust-lang/rust/pull/161390) lands; requires nightly Rust + `bpfel-unknown-none` target)
* systemd: `PrivateBPF=` support ([PR #36134](https://github.com/systemd/systemd/pull/36134))
* Optional: podman with `--userns=auto`, CRI-O with user namespace support

## Contingency Plan

* Contingency mechanism:
  - The primary delivery path already uses the C eBPF programs (via libbpf-rs), so the Rust compiler fix ([rust-lang/rust#161390](https://github.com/rust-lang/rust/pull/161390)) is not on the critical path for F46.
  - If BPF LSM cannot be enabled in the Fedora kernel (e.g., SELinux interaction with `bpf` in the LSM list): disable LSM loading in `bpf-rbacd`; ship proxy mode only and rely on token-level constraints for container workloads.
  - If proxy mode has unresolved security concerns: ship LSM/container path only; desktop users fall back to `sudo`/`CAP_BPF`.
  - If neither component is ready: do not ship `bpf-rbacd`. eBPF access continues to work as it does today (privileged only). No regression.
* Contingency deadline: Beta freeze
* Blocks release? No. `bpf-rbacd` is an opt-in package.

## Documentation

* Upstream code: [Fedora Forge ebpf/bpf-rbacd](https://forge.fedoraproject.org/ebpf/bpf-rbacd) (primary), [GitHub mirror](https://github.com/danielmellado/bpf-rbacd)
* C reference implementation: [tohojo/bpf-rbac-lsm](https://github.com/tohojo/bpf-rbac-lsm)
* Rust compiler fix: [rust-lang/rust#161390](https://github.com/rust-lang/rust/pull/161390)
* Kernel docs: [BPF Token documentation](https://docs.kernel.org/bpf/bpf_token.html)
* systemd: [PrivateBPF= PR](https://github.com/systemd/systemd/pull/36134)
* LPC 2026 talk: [BPF-RBACd: Delegating BPF permissions with high granularity](https://lpc.events/event/20/contributions/2441/)
* Fedora: Quick Docs article covering installation, group membership, policy customization, security model, and container vs. desktop usage paths.
* eBPF SIG: [SIGs/eBPF](https://fedoraproject.org/wiki/SIGs/eBPF), Matrix: [#ebpf:fedoraproject.org](https://matrix.to/#/#ebpf:fedoraproject.org)

## Release Notes

Fedora 46 introduces `bpf-rbacd`, a system daemon that enables unprivileged, policy-controlled eBPF access through two complementary modes:

* **Capability granting** for containers and services in user namespaces — transparent eBPF access via BPF token delegation with mandatory in-kernel LSM enforcement (three hooks: `security_bpf`, `security_bpf_prog_load`, `security_bpf_map_create`).
* **Proxy execution** for desktop users in the initial user namespace — rootless BPF access via the `bpf-rbac` CLI, with the daemon executing allowed operations on the user's behalf and passing file descriptors back via `SCM_RIGHTS`.

Both modes are governed by a single YAML policy file (`/etc/bpf-rbac/policy.yaml`) and gated by role-based groups (`ebpf`, `ebpf-net`, `ebpf-admin`). Install with `sudo dnf install bpf-rbacd`.
