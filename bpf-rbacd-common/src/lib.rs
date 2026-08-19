//! Shared types between `bpf-rbacd` userspace and eBPF programs.
//!
//! This crate defines the `#[repr(C)]` data structures that cross the
//! eBPF map boundary. The same types are used by:
//!
//! - The **userspace daemon** to populate the policy map.
//! - The **eBPF LSM programs** to read the policy map and make access
//!   control decisions.
//!
//! # Layout guarantees
//!
//! All types are `#[repr(C)]`, `Copy`, and `Clone` to ensure a stable ABI.
//! When the `user` feature is enabled, they also implement `aya::Pod` for
//! safe use with aya's typed map APIs.
//!
//! # Features
//!
//! - **`user`** — Enables `std` and `aya::Pod` implementations. Use this
//!   feature in the userspace daemon. Omit it when compiling for the
//!   `bpfel-unknown-none` target.
//!
//! # Map schema
//!
//! The eBPF map is a `BPF_MAP_TYPE_HASH` keyed by [`PolicyKey`] (user
//! namespace inode ID) with [`PolicyValue`] containing permission bitmaps.
//!
//! ```text
//! ┌──────────────────┐     ┌────────────────────────────┐
//! │   PolicyKey       │     │       PolicyValue           │
//! │ ┌──────────────┐ │     │ ┌──────────────────────┐   │
//! │ │ userns_id: u64│─┼────▶│ │ allowed_cmds: u32    │   │
//! │ └──────────────┘ │     │ │ allowed_prog_types:u32│   │
//! └──────────────────┘     │ │ allowed_map_types: u32│   │
//!                          │ │ allowed_attach_types:u32  │
//!                          │ │ flags: u32             │   │
//!                          │ │ _reserved: [u32; 3]    │   │
//!                          │ └──────────────────────────┘ │
//!                          └────────────────────────────┘
//! ```

#![cfg_attr(not(feature = "user"), no_std)]

/// Key for the policy eBPF map.
///
/// The user namespace inode ID uniquely identifies the target namespace
/// and is obtained from `stat("/proc/{pid}/ns/user").ino` or, inside an
/// eBPF program, via `bpf_get_current_task_btf() → nsproxy → user_ns → ns.inum`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyKey {
    /// User namespace inode number.
    pub userns_id: u64,
}

/// Value for the policy eBPF map.
///
/// Contains bitmaps where each bit position corresponds to the kernel's
/// enum value for that type or command. A set bit means the operation is
/// allowed. The [`flags`](mod@flags) field provides additional controls
/// like [`POLICY_FLAG_DENY_ALL`](flags::POLICY_FLAG_DENY_ALL).
///
/// The struct is 32 bytes (8 × `u32`), padded with `_reserved` for
/// future extensibility without changing the map entry size.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyValue {
    /// Bitmap of allowed `bpf()` syscall commands (`BPF_MAP_CREATE` = bit 0, etc.).
    pub allowed_cmds: u32,
    /// Bitmap of allowed BPF program types (`BPF_PROG_TYPE_KPROBE` = bit 2, etc.).
    pub allowed_prog_types: u32,
    /// Bitmap of allowed BPF map types (`BPF_MAP_TYPE_HASH` = bit 1, etc.).
    pub allowed_map_types: u32,
    /// Bitmap of allowed BPF attach types (reserved for future use).
    pub allowed_attach_types: u32,
    /// Policy control flags. See the [`flags`] module.
    pub flags: u32,
    /// Reserved for future use. Must be zero.
    pub _reserved: [u32; 3],
}

impl PolicyValue {
    /// Create an empty policy value that denies everything.
    pub const fn empty() -> Self {
        Self {
            allowed_cmds: 0,
            allowed_prog_types: 0,
            allowed_map_types: 0,
            allowed_attach_types: 0,
            flags: 0,
            _reserved: [0; 3],
        }
    }

    /// Create a policy value that allows all operations (all bits set).
    pub const fn allow_all() -> Self {
        Self {
            allowed_cmds: 0xFFFFFFFF,
            allowed_prog_types: 0xFFFFFFFF,
            allowed_map_types: 0xFFFFFFFF,
            allowed_attach_types: 0xFFFFFFFF,
            flags: 0,
            _reserved: [0; 3],
        }
    }
}

/// Policy control flags used in [`PolicyValue::flags`].
pub mod flags {
    /// Fully trusted namespace — all operations allowed regardless of bitmaps.
    pub const POLICY_FLAG_ALLOW_ALL: u32 = 1 << 0;
    /// Deny all operations. Takes precedence over everything else, including
    /// `POLICY_FLAG_ALLOW_ALL`.
    pub const POLICY_FLAG_DENY_ALL: u32 = 1 << 1;
}

/// Maximum number of policy entries in the eBPF map.
///
/// This limits the number of simultaneously-managed user namespaces.
pub const MAX_POLICY_ENTRIES: u32 = 1024;

/// Kernel `BPF_PROG_TYPE_*` enum values used as bit positions in bitmaps.
///
/// Values match the kernel's `enum bpf_prog_type` in
/// `include/uapi/linux/bpf.h`.
pub mod prog_types {
    pub const SOCKET_FILTER: u32 = 1;
    pub const KPROBE: u32 = 2;
    pub const SCHED_CLS: u32 = 3;
    pub const SCHED_ACT: u32 = 4;
    pub const TRACEPOINT: u32 = 5;
    pub const XDP: u32 = 6;
    pub const PERF_EVENT: u32 = 7;
    pub const CGROUP_SKB: u32 = 8;
    pub const CGROUP_SOCK: u32 = 9;
    pub const LWT_IN: u32 = 10;
    pub const LWT_OUT: u32 = 11;
    pub const LWT_XMIT: u32 = 12;
    pub const SOCK_OPS: u32 = 13;
    pub const SK_SKB: u32 = 14;
    pub const CGROUP_DEVICE: u32 = 15;
    pub const SK_MSG: u32 = 16;
    pub const RAW_TRACEPOINT: u32 = 17;
    pub const CGROUP_SOCK_ADDR: u32 = 18;
    pub const LWT_SEG6LOCAL: u32 = 19;
    pub const SK_REUSEPORT: u32 = 21;
    pub const FLOW_DISSECTOR: u32 = 22;
    pub const TRACING: u32 = 26;
    pub const STRUCT_OPS: u32 = 27;
    pub const EXT: u32 = 28;
    pub const LSM: u32 = 29;
    pub const SK_LOOKUP: u32 = 30;
}

/// Kernel `BPF_MAP_TYPE_*` enum values used as bit positions in bitmaps.
///
/// Values match the kernel's `enum bpf_map_type` in
/// `include/uapi/linux/bpf.h`.
pub mod map_types {
    pub const HASH: u32 = 1;
    pub const ARRAY: u32 = 2;
    pub const PROG_ARRAY: u32 = 3;
    pub const PERF_EVENT_ARRAY: u32 = 4;
    pub const PERCPU_HASH: u32 = 5;
    pub const PERCPU_ARRAY: u32 = 6;
    pub const STACK_TRACE: u32 = 7;
    pub const CGROUP_ARRAY: u32 = 8;
    pub const LRU_HASH: u32 = 9;
    pub const LRU_PERCPU_HASH: u32 = 10;
    pub const LPM_TRIE: u32 = 11;
    pub const ARRAY_OF_MAPS: u32 = 12;
    pub const HASH_OF_MAPS: u32 = 13;
    pub const DEVMAP: u32 = 14;
    pub const SOCKMAP: u32 = 15;
    pub const CPUMAP: u32 = 16;
    pub const XSKMAP: u32 = 17;
    pub const SOCKHASH: u32 = 18;
    pub const RINGBUF: u32 = 27;
}

/// BPF instruction layout matching the kernel's `struct bpf_insn`.
///
/// Each BPF instruction is exactly 8 bytes. The `code` field encodes
/// the operation class and source/mode bits. For call instructions,
/// `src_reg` distinguishes helper calls (0) from kfunc calls (2) and
/// `imm` holds the callee identifier.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BpfInsn {
    /// Opcode: class | source | mode.
    pub code: u8,
    /// Packed dst_reg (low nibble) and src_reg (high nibble).
    pub regs: u8,
    /// Signed offset used by jumps and memory ops.
    pub off: i16,
    /// Signed immediate operand (helper ID, kfunc BTF ID, etc.).
    pub imm: i32,
}

impl BpfInsn {
    /// Extract the source register (high nibble of `regs`).
    pub const fn src_reg(&self) -> u8 {
        self.regs >> 4
    }

    /// Extract the destination register (low nibble of `regs`).
    pub const fn dst_reg(&self) -> u8 {
        self.regs & 0x0f
    }
}

/// BPF instruction class and opcode constants from `include/uapi/linux/bpf.h`.
pub mod insn {
    /// Instruction class: jump (64-bit).
    pub const BPF_JMP: u8 = 0x05;
    /// Source modifier: call instruction.
    pub const BPF_CALL: u8 = 0x80;
    /// Opcode for a BPF function call (`BPF_JMP | BPF_CALL`).
    pub const BPF_JMP_CALL: u8 = BPF_JMP | BPF_CALL; // 0x85
    /// src_reg value indicating a kfunc call (BPF_PSEUDO_KFUNC_CALL).
    pub const BPF_PSEUDO_KFUNC_CALL: u8 = 2;
    /// src_reg value indicating a helper call.
    pub const BPF_HELPER_CALL: u8 = 0;
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyValue {}

/// Kernel `BPF_*` syscall command enum values used as bit positions in bitmaps.
///
/// Values match the kernel's `enum bpf_cmd` in `include/uapi/linux/bpf.h`.
pub mod commands {
    pub const MAP_CREATE: u32 = 0;
    pub const MAP_LOOKUP_ELEM: u32 = 1;
    pub const MAP_UPDATE_ELEM: u32 = 2;
    pub const MAP_DELETE_ELEM: u32 = 3;
    pub const MAP_GET_NEXT_KEY: u32 = 4;
    pub const PROG_LOAD: u32 = 5;
    pub const OBJ_PIN: u32 = 6;
    pub const OBJ_GET: u32 = 7;
    pub const PROG_ATTACH: u32 = 8;
    pub const PROG_DETACH: u32 = 9;
    pub const PROG_TEST_RUN: u32 = 10;
    pub const OBJ_GET_INFO_BY_FD: u32 = 15;
    pub const BTF_LOAD: u32 = 18;
    pub const LINK_CREATE: u32 = 28;
    pub const LINK_UPDATE: u32 = 29;
    pub const TOKEN_CREATE: u32 = 33;
}
