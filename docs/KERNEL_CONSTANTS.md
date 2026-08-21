# Kernel BPF Constants

This document describes how `bpf-rbacd` maps kernel BPF constant values to
Rust types and how ABI correctness is enforced.

## Background

The Linux kernel defines several C enums in `include/uapi/linux/bpf.h` that
control BPF operations:

| Kernel enum | Purpose | Max value (Linux 6.15) |
|---|---|---|
| `bpf_cmd` | `bpf()` syscall command | 36 (`BPF_TOKEN_CREATE`) |
| `bpf_prog_type` | BPF program types | 32 (`BPF_PROG_TYPE_NETFILTER`) |
| `bpf_map_type` | BPF map types | 33 (`BPF_MAP_TYPE_ARENA`) |

`bpf-rbacd` uses these values as bit positions in permission bitmaps. Each
bit in a `PolicyValue` bitmap corresponds to exactly one kernel enum variant.
If the bit is set, the operation is allowed; if clear, it is denied.

## The problem (before this refactoring)

Prior to this change, kernel constants were defined in **two independent
places** with no cross-checking:

1. **`bpf-rbacd-common/src/lib.rs`** — `pub mod prog_types`, `pub mod
   map_types`, `pub mod commands` with hand-written `pub const` values.
   Used by the eBPF LSM programs.

2. **`src/policy.rs`** — `fn prog_type_to_bit()`, `fn map_type_to_bit()`,
   `fn command_to_bit()` with hand-written `match` arms returning
   `Option<u32>`. Used by the userspace policy engine.

This caused several issues:

- **Incorrect values**: `TOKEN_CREATE` was defined as 33 in
  `bpf-rbacd-common`, but the actual kernel value is 36. The value 33
  corresponds to `BPF_ITER_CREATE`. A policy allowing `TOKEN_CREATE` would
  have silently allowed `ITER_CREATE` instead.

- **Incomplete coverage**: The `bpf-rbacd-common` modules covered only a
  subset of kernel constants. The `policy.rs` match arms were more complete
  but still missed several types.

- **No ABI verification**: Neither set of definitions was checked against
  the kernel headers or any generated binding. Drift was invisible.

- **Bitmap overflow**: All bitmaps were `u32`, which can only represent
  values 0–31. Kernel enums have already grown past 31 (e.g.
  `BPF_PROG_TYPE_NETFILTER = 32`, `BPF_MAP_TYPE_ARENA = 33`,
  `BPF_TOKEN_CREATE = 36`). These values were silently unrepresentable.

## The solution

### Single source of truth: `#[repr(u32)]` enums

All kernel constants are now defined as proper Rust enums in
`bpf-rbacd-common/src/lib.rs`:

- `BpfCmd` — `bpf()` syscall commands
- `BpfProgType` — BPF program types
- `BpfMapType` — BPF map types

Each enum variant has an explicit discriminant matching the kernel's value.
The old `pub mod` constant blocks and `fn *_to_bit()` match functions have
been deleted.

### YAML policy name mapping

Each enum provides a `from_policy_name(&str) -> Option<Self>` method that
maps the lowercase names used in policy YAML files to enum variants. Aliases
are supported (e.g. `"fentry"` → `Tracing`, `"uprobe"` → `Kprobe`).

### Widened bitmaps: u32 → u64

`PolicyValue` bitmaps are now `u64`, covering bit positions 0–63. This
accommodates all current kernel enums and provides headroom for future
additions. The `PolicyValue` struct is 48 bytes:

```text
allowed_cmds:         u64  (8 bytes)
allowed_prog_types:   u64  (8 bytes)
allowed_map_types:    u64  (8 bytes)
allowed_attach_types: u64  (8 bytes)
flags:                u32  (4 bytes)
_reserved:            [u32; 3]  (12 bytes)
Total:                48 bytes
```

The eBPF LSM programs use `1u64 << bit` for bitmap checks, and the guard
condition is `bit < 64` instead of the old `bit < 32`.

### `DelegationOpts` truncation

The kernel's bpffs `delegate_*` mount options are `u32`. When creating
`DelegationOpts` from policy bitmaps, the u64 values are truncated to u32.
Kernel enum values above 31 cannot be delegated via mount options; they are
enforced solely by the eBPF LSM.

## ABI correctness testing

The `bpf-rbacd-common` crate includes tests (gated behind `#[cfg(feature =
"user")]`) that assert every enum discriminant matches the corresponding
constant from `aya_obj::generated`:

```rust
assert_eq!(BpfCmd::TokenCreate as u32,
           aya_obj::generated::bpf_cmd::BPF_TOKEN_CREATE as u32);
```

`aya-obj` generates its bindings from kernel UAPI headers via `bindgen`.
When the kernel adds or renumbers an enum variant, updating `aya-obj` will
cause these tests to fail, alerting us to add or correct our enum.

Run the ABI tests with:

```bash
cargo test --lib -p bpf-rbacd-common --features user
```

## Adding new kernel constants

When the kernel introduces new `bpf_cmd`, `bpf_prog_type`, or
`bpf_map_type` values:

1. Add the new variant to the corresponding enum in
   `bpf-rbacd-common/src/lib.rs` with the correct discriminant.

2. Add a `from_policy_name` match arm for the YAML name.

3. Add an ABI test assertion in the `abi_tests` module comparing against
   the `aya_obj::generated` constant.

4. Update `aya-obj` if needed (the generated bindings must include the new
   constant).

5. The eBPF programs and policy engine automatically support the new
   constant — no other code changes are needed as long as the bit position
   fits in 64 bits.
