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
//! │ │ userns_id: u64│─┼────▶│ │ allowed_cmds: u64    │   │
//! │ └──────────────┘ │     │ │ allowed_prog_types:u64│   │
//! └──────────────────┘     │ │ allowed_map_types: u64│   │
//!                          │ │ allowed_attach_types:u64  │
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
/// Bitmaps are `u64` to accommodate kernel enum values up to 63. Current
/// kernel enums reach ~38, so this provides ample headroom.
///
/// The struct is 48 bytes, padded with `_reserved` for future
/// extensibility without changing the map entry size.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyValue {
    /// Bitmap of allowed `bpf()` syscall commands (`BPF_MAP_CREATE` = bit 0, etc.).
    pub allowed_cmds: u64,
    /// Bitmap of allowed BPF program types (`BPF_PROG_TYPE_KPROBE` = bit 2, etc.).
    pub allowed_prog_types: u64,
    /// Bitmap of allowed BPF map types (`BPF_MAP_TYPE_HASH` = bit 1, etc.).
    pub allowed_map_types: u64,
    /// Bitmap of allowed BPF attach types (reserved for future use).
    pub allowed_attach_types: u64,
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
            allowed_cmds: u64::MAX,
            allowed_prog_types: u64::MAX,
            allowed_map_types: u64::MAX,
            allowed_attach_types: u64::MAX,
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

/// Kernel `bpf_cmd` enum values.
///
/// Each variant maps to the corresponding `BPF_*` constant in
/// `include/uapi/linux/bpf.h`. The discriminant is used as the bit
/// position in the [`PolicyValue::allowed_cmds`] bitmap.
///
/// When the `user` feature is enabled, ABI correctness tests verify
/// these discriminants against `aya_obj::generated::bpf_cmd`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfCmd {
    MapCreate = 0,
    MapLookupElem = 1,
    MapUpdateElem = 2,
    MapDeleteElem = 3,
    MapGetNextKey = 4,
    ProgLoad = 5,
    ObjPin = 6,
    ObjGet = 7,
    ProgAttach = 8,
    ProgDetach = 9,
    ProgTestRun = 10,
    ProgGetNextId = 11,
    MapGetNextId = 12,
    ProgGetFdById = 13,
    MapGetFdById = 14,
    ObjGetInfoByFd = 15,
    ProgQuery = 16,
    RawTracepointOpen = 17,
    BtfLoad = 18,
    BtfGetFdById = 19,
    TaskFdQuery = 20,
    MapLookupAndDeleteElem = 21,
    MapFreeze = 22,
    BtfGetNextId = 23,
    MapLookupBatch = 24,
    MapLookupAndDeleteBatch = 25,
    MapUpdateBatch = 26,
    MapDeleteBatch = 27,
    LinkCreate = 28,
    LinkUpdate = 29,
    LinkGetFdById = 30,
    LinkGetNextId = 31,
    EnableStats = 32,
    IterCreate = 33,
    LinkDetach = 34,
    ProgBindMap = 35,
    TokenCreate = 36,
}

impl BpfCmd {
    /// Map a YAML policy command name to the corresponding variant.
    ///
    /// Accepts uppercase names matching the kernel constants without the
    /// `BPF_` prefix (e.g. `"PROG_LOAD"`, `"MAP_CREATE"`).
    pub fn from_policy_name(s: &str) -> Option<Self> {
        match s {
            "MAP_CREATE" => Some(Self::MapCreate),
            "MAP_LOOKUP_ELEM" => Some(Self::MapLookupElem),
            "MAP_UPDATE_ELEM" => Some(Self::MapUpdateElem),
            "MAP_DELETE_ELEM" => Some(Self::MapDeleteElem),
            "MAP_GET_NEXT_KEY" => Some(Self::MapGetNextKey),
            "PROG_LOAD" => Some(Self::ProgLoad),
            "OBJ_PIN" => Some(Self::ObjPin),
            "OBJ_GET" => Some(Self::ObjGet),
            "PROG_ATTACH" => Some(Self::ProgAttach),
            "PROG_DETACH" => Some(Self::ProgDetach),
            "PROG_TEST_RUN" | "PROG_RUN" => Some(Self::ProgTestRun),
            "PROG_GET_NEXT_ID" => Some(Self::ProgGetNextId),
            "MAP_GET_NEXT_ID" => Some(Self::MapGetNextId),
            "PROG_GET_FD_BY_ID" => Some(Self::ProgGetFdById),
            "MAP_GET_FD_BY_ID" => Some(Self::MapGetFdById),
            "OBJ_GET_INFO_BY_FD" => Some(Self::ObjGetInfoByFd),
            "PROG_QUERY" => Some(Self::ProgQuery),
            "RAW_TRACEPOINT_OPEN" => Some(Self::RawTracepointOpen),
            "BTF_LOAD" => Some(Self::BtfLoad),
            "BTF_GET_FD_BY_ID" => Some(Self::BtfGetFdById),
            "TASK_FD_QUERY" => Some(Self::TaskFdQuery),
            "MAP_LOOKUP_AND_DELETE_ELEM" => Some(Self::MapLookupAndDeleteElem),
            "MAP_FREEZE" => Some(Self::MapFreeze),
            "BTF_GET_NEXT_ID" => Some(Self::BtfGetNextId),
            "MAP_LOOKUP_BATCH" => Some(Self::MapLookupBatch),
            "MAP_LOOKUP_AND_DELETE_BATCH" => Some(Self::MapLookupAndDeleteBatch),
            "MAP_UPDATE_BATCH" => Some(Self::MapUpdateBatch),
            "MAP_DELETE_BATCH" => Some(Self::MapDeleteBatch),
            "LINK_CREATE" => Some(Self::LinkCreate),
            "LINK_UPDATE" => Some(Self::LinkUpdate),
            "LINK_GET_FD_BY_ID" => Some(Self::LinkGetFdById),
            "LINK_GET_NEXT_ID" => Some(Self::LinkGetNextId),
            "ENABLE_STATS" => Some(Self::EnableStats),
            "ITER_CREATE" => Some(Self::IterCreate),
            "LINK_DETACH" => Some(Self::LinkDetach),
            "PROG_BIND_MAP" => Some(Self::ProgBindMap),
            "TOKEN_CREATE" => Some(Self::TokenCreate),
            _ => None,
        }
    }

    /// Bit position in the `allowed_cmds` bitmap (same as the discriminant).
    pub const fn bit_position(self) -> u32 {
        self as u32
    }

    /// Bitmap mask for this command: `1u64 << bit_position`.
    pub const fn to_bitmap_mask(self) -> u64 {
        1u64 << self as u32
    }
}

/// Kernel `bpf_prog_type` enum values.
///
/// Each variant maps to the corresponding `BPF_PROG_TYPE_*` constant in
/// `include/uapi/linux/bpf.h`. The discriminant is used as the bit
/// position in the [`PolicyValue::allowed_prog_types`] bitmap.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfProgType {
    SocketFilter = 1,
    Kprobe = 2,
    SchedCls = 3,
    SchedAct = 4,
    Tracepoint = 5,
    Xdp = 6,
    PerfEvent = 7,
    CgroupSkb = 8,
    CgroupSock = 9,
    LwtIn = 10,
    LwtOut = 11,
    LwtXmit = 12,
    SockOps = 13,
    SkSkb = 14,
    CgroupDevice = 15,
    SkMsg = 16,
    RawTracepoint = 17,
    CgroupSockAddr = 18,
    LwtSeg6local = 19,
    LircMode2 = 20,
    SkReuseport = 21,
    FlowDissector = 22,
    CgroupSysctl = 23,
    RawTracepointWritable = 24,
    CgroupSockopt = 25,
    Tracing = 26,
    StructOps = 27,
    Ext = 28,
    Lsm = 29,
    SkLookup = 30,
    Syscall = 31,
    Netfilter = 32,
}

impl BpfProgType {
    /// Map a YAML policy program type name to the corresponding variant.
    ///
    /// Accepts lowercase names as used in policy YAML files. Some aliases
    /// are supported (e.g. `"fentry"` and `"fexit"` map to `Tracing`,
    /// `"uprobe"` and `"uretprobe"` map to `Kprobe`).
    pub fn from_policy_name(s: &str) -> Option<Self> {
        match s {
            "socket_filter" => Some(Self::SocketFilter),
            "kprobe" | "kretprobe" | "uprobe" | "uretprobe" => Some(Self::Kprobe),
            "sched_cls" => Some(Self::SchedCls),
            "sched_act" => Some(Self::SchedAct),
            "tracepoint" => Some(Self::Tracepoint),
            "xdp" => Some(Self::Xdp),
            "perf_event" => Some(Self::PerfEvent),
            "cgroup_skb" => Some(Self::CgroupSkb),
            "cgroup_sock" => Some(Self::CgroupSock),
            "lwt_in" => Some(Self::LwtIn),
            "lwt_out" => Some(Self::LwtOut),
            "lwt_xmit" => Some(Self::LwtXmit),
            "sock_ops" => Some(Self::SockOps),
            "sk_skb" => Some(Self::SkSkb),
            "cgroup_device" => Some(Self::CgroupDevice),
            "sk_msg" => Some(Self::SkMsg),
            "raw_tracepoint" => Some(Self::RawTracepoint),
            "cgroup_sock_addr" => Some(Self::CgroupSockAddr),
            "lwt_seg6local" => Some(Self::LwtSeg6local),
            "lirc_mode2" => Some(Self::LircMode2),
            "sk_reuseport" => Some(Self::SkReuseport),
            "flow_dissector" => Some(Self::FlowDissector),
            "cgroup_sysctl" => Some(Self::CgroupSysctl),
            "raw_tracepoint_writable" => Some(Self::RawTracepointWritable),
            "cgroup_sockopt" => Some(Self::CgroupSockopt),
            "tracing" | "fentry" | "fexit" => Some(Self::Tracing),
            "struct_ops" => Some(Self::StructOps),
            "ext" => Some(Self::Ext),
            "lsm" => Some(Self::Lsm),
            "sk_lookup" => Some(Self::SkLookup),
            "syscall" => Some(Self::Syscall),
            "netfilter" => Some(Self::Netfilter),
            _ => None,
        }
    }

    /// Bit position in the `allowed_prog_types` bitmap (same as the discriminant).
    pub const fn bit_position(self) -> u32 {
        self as u32
    }

    /// Bitmap mask for this program type: `1u64 << bit_position`.
    pub const fn to_bitmap_mask(self) -> u64 {
        1u64 << self as u32
    }
}

/// Kernel `bpf_map_type` enum values.
///
/// Each variant maps to the corresponding `BPF_MAP_TYPE_*` constant in
/// `include/uapi/linux/bpf.h`. The discriminant is used as the bit
/// position in the [`PolicyValue::allowed_map_types`] bitmap.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfMapType {
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PercpuHash = 5,
    PercpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPercpuHash = 10,
    LpmTrie = 11,
    ArrayOfMaps = 12,
    HashOfMaps = 13,
    Devmap = 14,
    Sockmap = 15,
    Cpumap = 16,
    Xskmap = 17,
    Sockhash = 18,
    CgroupStorage = 19,
    ReuseportSockarray = 20,
    PercpuCgroupStorage = 21,
    Queue = 22,
    Stack = 23,
    SkStorage = 24,
    DevmapHash = 25,
    StructOps = 26,
    Ringbuf = 27,
    InodeStorage = 28,
    TaskStorage = 29,
    BloomFilter = 30,
    UserRingbuf = 31,
    CgrpStorage = 32,
    Arena = 33,
}

impl BpfMapType {
    /// Map a YAML policy map type name to the corresponding variant.
    ///
    /// Accepts lowercase names as used in policy YAML files.
    pub fn from_policy_name(s: &str) -> Option<Self> {
        match s {
            "hash" => Some(Self::Hash),
            "array" => Some(Self::Array),
            "prog_array" => Some(Self::ProgArray),
            "perf_event_array" => Some(Self::PerfEventArray),
            "percpu_hash" => Some(Self::PercpuHash),
            "percpu_array" => Some(Self::PercpuArray),
            "stack_trace" => Some(Self::StackTrace),
            "cgroup_array" => Some(Self::CgroupArray),
            "lru_hash" => Some(Self::LruHash),
            "lru_percpu_hash" => Some(Self::LruPercpuHash),
            "lpm_trie" => Some(Self::LpmTrie),
            "array_of_maps" => Some(Self::ArrayOfMaps),
            "hash_of_maps" => Some(Self::HashOfMaps),
            "devmap" => Some(Self::Devmap),
            "sockmap" => Some(Self::Sockmap),
            "cpumap" => Some(Self::Cpumap),
            "xskmap" => Some(Self::Xskmap),
            "sockhash" => Some(Self::Sockhash),
            "cgroup_storage" => Some(Self::CgroupStorage),
            "reuseport_sockarray" => Some(Self::ReuseportSockarray),
            "percpu_cgroup_storage" => Some(Self::PercpuCgroupStorage),
            "queue" => Some(Self::Queue),
            "stack" => Some(Self::Stack),
            "sk_storage" => Some(Self::SkStorage),
            "devmap_hash" => Some(Self::DevmapHash),
            "struct_ops" => Some(Self::StructOps),
            "ringbuf" => Some(Self::Ringbuf),
            "inode_storage" => Some(Self::InodeStorage),
            "task_storage" => Some(Self::TaskStorage),
            "bloom_filter" => Some(Self::BloomFilter),
            "user_ringbuf" => Some(Self::UserRingbuf),
            "cgrp_storage" => Some(Self::CgrpStorage),
            "arena" => Some(Self::Arena),
            _ => None,
        }
    }

    /// Bit position in the `allowed_map_types` bitmap (same as the discriminant).
    pub const fn bit_position(self) -> u32 {
        self as u32
    }

    /// Bitmap mask for this map type: `1u64 << bit_position`.
    pub const fn to_bitmap_mask(self) -> u64 {
        1u64 << self as u32
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyValue {}

#[cfg(all(test, feature = "user"))]
mod abi_tests {
    use super::*;
    use aya_obj::generated::{bpf_cmd, bpf_map_type, bpf_prog_type};

    #[test]
    fn bpf_cmd_values_match_kernel() {
        assert_eq!(BpfCmd::MapCreate as u32, bpf_cmd::BPF_MAP_CREATE as u32);
        assert_eq!(
            BpfCmd::MapLookupElem as u32,
            bpf_cmd::BPF_MAP_LOOKUP_ELEM as u32
        );
        assert_eq!(
            BpfCmd::MapUpdateElem as u32,
            bpf_cmd::BPF_MAP_UPDATE_ELEM as u32
        );
        assert_eq!(
            BpfCmd::MapDeleteElem as u32,
            bpf_cmd::BPF_MAP_DELETE_ELEM as u32
        );
        assert_eq!(
            BpfCmd::MapGetNextKey as u32,
            bpf_cmd::BPF_MAP_GET_NEXT_KEY as u32
        );
        assert_eq!(BpfCmd::ProgLoad as u32, bpf_cmd::BPF_PROG_LOAD as u32);
        assert_eq!(BpfCmd::ObjPin as u32, bpf_cmd::BPF_OBJ_PIN as u32);
        assert_eq!(BpfCmd::ObjGet as u32, bpf_cmd::BPF_OBJ_GET as u32);
        assert_eq!(BpfCmd::ProgAttach as u32, bpf_cmd::BPF_PROG_ATTACH as u32);
        assert_eq!(BpfCmd::ProgDetach as u32, bpf_cmd::BPF_PROG_DETACH as u32);
        assert_eq!(
            BpfCmd::ProgTestRun as u32,
            bpf_cmd::BPF_PROG_TEST_RUN as u32
        );
        assert_eq!(
            BpfCmd::ProgGetNextId as u32,
            bpf_cmd::BPF_PROG_GET_NEXT_ID as u32
        );
        assert_eq!(
            BpfCmd::MapGetNextId as u32,
            bpf_cmd::BPF_MAP_GET_NEXT_ID as u32
        );
        assert_eq!(
            BpfCmd::ProgGetFdById as u32,
            bpf_cmd::BPF_PROG_GET_FD_BY_ID as u32
        );
        assert_eq!(
            BpfCmd::MapGetFdById as u32,
            bpf_cmd::BPF_MAP_GET_FD_BY_ID as u32
        );
        assert_eq!(
            BpfCmd::ObjGetInfoByFd as u32,
            bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as u32
        );
        assert_eq!(BpfCmd::ProgQuery as u32, bpf_cmd::BPF_PROG_QUERY as u32);
        assert_eq!(
            BpfCmd::RawTracepointOpen as u32,
            bpf_cmd::BPF_RAW_TRACEPOINT_OPEN as u32
        );
        assert_eq!(BpfCmd::BtfLoad as u32, bpf_cmd::BPF_BTF_LOAD as u32);
        assert_eq!(
            BpfCmd::BtfGetFdById as u32,
            bpf_cmd::BPF_BTF_GET_FD_BY_ID as u32
        );
        assert_eq!(
            BpfCmd::TaskFdQuery as u32,
            bpf_cmd::BPF_TASK_FD_QUERY as u32
        );
        assert_eq!(
            BpfCmd::MapLookupAndDeleteElem as u32,
            bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_ELEM as u32
        );
        assert_eq!(BpfCmd::MapFreeze as u32, bpf_cmd::BPF_MAP_FREEZE as u32);
        assert_eq!(
            BpfCmd::BtfGetNextId as u32,
            bpf_cmd::BPF_BTF_GET_NEXT_ID as u32
        );
        assert_eq!(
            BpfCmd::MapLookupBatch as u32,
            bpf_cmd::BPF_MAP_LOOKUP_BATCH as u32
        );
        assert_eq!(
            BpfCmd::MapLookupAndDeleteBatch as u32,
            bpf_cmd::BPF_MAP_LOOKUP_AND_DELETE_BATCH as u32
        );
        assert_eq!(
            BpfCmd::MapUpdateBatch as u32,
            bpf_cmd::BPF_MAP_UPDATE_BATCH as u32
        );
        assert_eq!(
            BpfCmd::MapDeleteBatch as u32,
            bpf_cmd::BPF_MAP_DELETE_BATCH as u32
        );
        assert_eq!(BpfCmd::LinkCreate as u32, bpf_cmd::BPF_LINK_CREATE as u32);
        assert_eq!(BpfCmd::LinkUpdate as u32, bpf_cmd::BPF_LINK_UPDATE as u32);
        assert_eq!(
            BpfCmd::LinkGetFdById as u32,
            bpf_cmd::BPF_LINK_GET_FD_BY_ID as u32
        );
        assert_eq!(
            BpfCmd::LinkGetNextId as u32,
            bpf_cmd::BPF_LINK_GET_NEXT_ID as u32
        );
        assert_eq!(BpfCmd::EnableStats as u32, bpf_cmd::BPF_ENABLE_STATS as u32);
        assert_eq!(BpfCmd::IterCreate as u32, bpf_cmd::BPF_ITER_CREATE as u32);
        assert_eq!(BpfCmd::LinkDetach as u32, bpf_cmd::BPF_LINK_DETACH as u32);
        assert_eq!(
            BpfCmd::ProgBindMap as u32,
            bpf_cmd::BPF_PROG_BIND_MAP as u32
        );
        assert_eq!(BpfCmd::TokenCreate as u32, bpf_cmd::BPF_TOKEN_CREATE as u32);
    }

    #[test]
    fn bpf_prog_type_values_match_kernel() {
        assert_eq!(
            BpfProgType::SocketFilter as u32,
            bpf_prog_type::BPF_PROG_TYPE_SOCKET_FILTER as u32
        );
        assert_eq!(
            BpfProgType::Kprobe as u32,
            bpf_prog_type::BPF_PROG_TYPE_KPROBE as u32
        );
        assert_eq!(
            BpfProgType::SchedCls as u32,
            bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS as u32
        );
        assert_eq!(
            BpfProgType::SchedAct as u32,
            bpf_prog_type::BPF_PROG_TYPE_SCHED_ACT as u32
        );
        assert_eq!(
            BpfProgType::Tracepoint as u32,
            bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT as u32
        );
        assert_eq!(
            BpfProgType::Xdp as u32,
            bpf_prog_type::BPF_PROG_TYPE_XDP as u32
        );
        assert_eq!(
            BpfProgType::PerfEvent as u32,
            bpf_prog_type::BPF_PROG_TYPE_PERF_EVENT as u32
        );
        assert_eq!(
            BpfProgType::CgroupSkb as u32,
            bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB as u32
        );
        assert_eq!(
            BpfProgType::CgroupSock as u32,
            bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK as u32
        );
        assert_eq!(
            BpfProgType::LwtIn as u32,
            bpf_prog_type::BPF_PROG_TYPE_LWT_IN as u32
        );
        assert_eq!(
            BpfProgType::LwtOut as u32,
            bpf_prog_type::BPF_PROG_TYPE_LWT_OUT as u32
        );
        assert_eq!(
            BpfProgType::LwtXmit as u32,
            bpf_prog_type::BPF_PROG_TYPE_LWT_XMIT as u32
        );
        assert_eq!(
            BpfProgType::SockOps as u32,
            bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS as u32
        );
        assert_eq!(
            BpfProgType::SkSkb as u32,
            bpf_prog_type::BPF_PROG_TYPE_SK_SKB as u32
        );
        assert_eq!(
            BpfProgType::CgroupDevice as u32,
            bpf_prog_type::BPF_PROG_TYPE_CGROUP_DEVICE as u32
        );
        assert_eq!(
            BpfProgType::SkMsg as u32,
            bpf_prog_type::BPF_PROG_TYPE_SK_MSG as u32
        );
        assert_eq!(
            BpfProgType::RawTracepoint as u32,
            bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT as u32
        );
        assert_eq!(
            BpfProgType::CgroupSockAddr as u32,
            bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK_ADDR as u32
        );
        assert_eq!(
            BpfProgType::LwtSeg6local as u32,
            bpf_prog_type::BPF_PROG_TYPE_LWT_SEG6LOCAL as u32
        );
        assert_eq!(
            BpfProgType::LircMode2 as u32,
            bpf_prog_type::BPF_PROG_TYPE_LIRC_MODE2 as u32
        );
        assert_eq!(
            BpfProgType::SkReuseport as u32,
            bpf_prog_type::BPF_PROG_TYPE_SK_REUSEPORT as u32
        );
        assert_eq!(
            BpfProgType::FlowDissector as u32,
            bpf_prog_type::BPF_PROG_TYPE_FLOW_DISSECTOR as u32
        );
        assert_eq!(
            BpfProgType::CgroupSysctl as u32,
            bpf_prog_type::BPF_PROG_TYPE_CGROUP_SYSCTL as u32
        );
        assert_eq!(
            BpfProgType::RawTracepointWritable as u32,
            bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE as u32
        );
        assert_eq!(
            BpfProgType::CgroupSockopt as u32,
            bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCKOPT as u32
        );
        assert_eq!(
            BpfProgType::Tracing as u32,
            bpf_prog_type::BPF_PROG_TYPE_TRACING as u32
        );
        assert_eq!(
            BpfProgType::StructOps as u32,
            bpf_prog_type::BPF_PROG_TYPE_STRUCT_OPS as u32
        );
        assert_eq!(
            BpfProgType::Ext as u32,
            bpf_prog_type::BPF_PROG_TYPE_EXT as u32
        );
        assert_eq!(
            BpfProgType::Lsm as u32,
            bpf_prog_type::BPF_PROG_TYPE_LSM as u32
        );
        assert_eq!(
            BpfProgType::SkLookup as u32,
            bpf_prog_type::BPF_PROG_TYPE_SK_LOOKUP as u32
        );
        assert_eq!(
            BpfProgType::Syscall as u32,
            bpf_prog_type::BPF_PROG_TYPE_SYSCALL as u32
        );
        assert_eq!(
            BpfProgType::Netfilter as u32,
            bpf_prog_type::BPF_PROG_TYPE_NETFILTER as u32
        );
    }

    #[test]
    fn bpf_map_type_values_match_kernel() {
        assert_eq!(
            BpfMapType::Hash as u32,
            bpf_map_type::BPF_MAP_TYPE_HASH as u32
        );
        assert_eq!(
            BpfMapType::Array as u32,
            bpf_map_type::BPF_MAP_TYPE_ARRAY as u32
        );
        assert_eq!(
            BpfMapType::ProgArray as u32,
            bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY as u32
        );
        assert_eq!(
            BpfMapType::PerfEventArray as u32,
            bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32
        );
        assert_eq!(
            BpfMapType::PercpuHash as u32,
            bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH as u32
        );
        assert_eq!(
            BpfMapType::PercpuArray as u32,
            bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as u32
        );
        assert_eq!(
            BpfMapType::StackTrace as u32,
            bpf_map_type::BPF_MAP_TYPE_STACK_TRACE as u32
        );
        assert_eq!(
            BpfMapType::CgroupArray as u32,
            bpf_map_type::BPF_MAP_TYPE_CGROUP_ARRAY as u32
        );
        assert_eq!(
            BpfMapType::LruHash as u32,
            bpf_map_type::BPF_MAP_TYPE_LRU_HASH as u32
        );
        assert_eq!(
            BpfMapType::LruPercpuHash as u32,
            bpf_map_type::BPF_MAP_TYPE_LRU_PERCPU_HASH as u32
        );
        assert_eq!(
            BpfMapType::LpmTrie as u32,
            bpf_map_type::BPF_MAP_TYPE_LPM_TRIE as u32
        );
        assert_eq!(
            BpfMapType::ArrayOfMaps as u32,
            bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS as u32
        );
        assert_eq!(
            BpfMapType::HashOfMaps as u32,
            bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS as u32
        );
        assert_eq!(
            BpfMapType::Devmap as u32,
            bpf_map_type::BPF_MAP_TYPE_DEVMAP as u32
        );
        assert_eq!(
            BpfMapType::Sockmap as u32,
            bpf_map_type::BPF_MAP_TYPE_SOCKMAP as u32
        );
        assert_eq!(
            BpfMapType::Cpumap as u32,
            bpf_map_type::BPF_MAP_TYPE_CPUMAP as u32
        );
        assert_eq!(
            BpfMapType::Xskmap as u32,
            bpf_map_type::BPF_MAP_TYPE_XSKMAP as u32
        );
        assert_eq!(
            BpfMapType::Sockhash as u32,
            bpf_map_type::BPF_MAP_TYPE_SOCKHASH as u32
        );
        assert_eq!(
            BpfMapType::CgroupStorage as u32,
            bpf_map_type::BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED as u32
        );
        assert_eq!(
            BpfMapType::ReuseportSockarray as u32,
            bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY as u32
        );
        assert_eq!(
            BpfMapType::PercpuCgroupStorage as u32,
            bpf_map_type::BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED as u32
        );
        assert_eq!(
            BpfMapType::Queue as u32,
            bpf_map_type::BPF_MAP_TYPE_QUEUE as u32
        );
        assert_eq!(
            BpfMapType::Stack as u32,
            bpf_map_type::BPF_MAP_TYPE_STACK as u32
        );
        assert_eq!(
            BpfMapType::SkStorage as u32,
            bpf_map_type::BPF_MAP_TYPE_SK_STORAGE as u32
        );
        assert_eq!(
            BpfMapType::DevmapHash as u32,
            bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH as u32
        );
        assert_eq!(
            BpfMapType::StructOps as u32,
            bpf_map_type::BPF_MAP_TYPE_STRUCT_OPS as u32
        );
        assert_eq!(
            BpfMapType::Ringbuf as u32,
            bpf_map_type::BPF_MAP_TYPE_RINGBUF as u32
        );
        assert_eq!(
            BpfMapType::InodeStorage as u32,
            bpf_map_type::BPF_MAP_TYPE_INODE_STORAGE as u32
        );
        assert_eq!(
            BpfMapType::TaskStorage as u32,
            bpf_map_type::BPF_MAP_TYPE_TASK_STORAGE as u32
        );
        assert_eq!(
            BpfMapType::BloomFilter as u32,
            bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER as u32
        );
        assert_eq!(
            BpfMapType::UserRingbuf as u32,
            bpf_map_type::BPF_MAP_TYPE_USER_RINGBUF as u32
        );
        assert_eq!(
            BpfMapType::CgrpStorage as u32,
            bpf_map_type::BPF_MAP_TYPE_CGRP_STORAGE as u32
        );
        assert_eq!(
            BpfMapType::Arena as u32,
            bpf_map_type::BPF_MAP_TYPE_ARENA as u32
        );
    }

    #[test]
    fn policy_value_size_is_48_bytes() {
        assert_eq!(core::mem::size_of::<PolicyValue>(), 48);
    }
}
