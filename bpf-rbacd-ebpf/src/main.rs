//! eBPF LSM programs for bpf-rbacd policy enforcement.
//!
//! These programs hook into the kernel's LSM framework to enforce
//! per-namespace BPF access policies. They read the policy from an
//! eBPF map populated by the userspace daemon.

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};
use aya_log_ebpf::info;
use bpf_rbacd_common::{flags, PolicyKey, PolicyValue, MAX_POLICY_ENTRIES};

#[map]
static POLICY_MAP: HashMap<PolicyKey, PolicyValue> =
    HashMap::with_max_entries(MAX_POLICY_ENTRIES, 0);

/// LSM hook: security_bpf
///
/// Called on every bpf() syscall. Checks whether the command is allowed
/// for the calling process's user namespace.
///
/// Arguments in context:
///   - cmd: i32 (BPF syscall command)
///   - attr: *const bpf_attr
///   - size: u32
///   - kernel: bool
#[lsm(hook = "bpf")]
pub fn bpf_rbac_bpf(ctx: LsmContext) -> i32 {
    match try_bpf_rbac_bpf(&ctx) {
        Ok(ret) => ret,
        Err(_) => -1, // EPERM on error (fail closed)
    }
}

fn try_bpf_rbac_bpf(ctx: &LsmContext) -> Result<i32, i64> {
    let cmd: i32 = unsafe { ctx.arg(0) };

    let kernel: u32 = unsafe { ctx.arg(3) };
    if kernel != 0 {
        return Ok(0);
    }

    let userns_id = get_current_userns_id()?;

    // If no policy entry exists for this namespace, it's not managed by us.
    // Allow the operation (other kernel checks still apply).
    let key = PolicyKey { userns_id };
    let policy = unsafe { POLICY_MAP.get(&key) };

    let policy = match policy {
        Some(p) => p,
        None => return Ok(-1), // Not a managed namespace
    };

    if policy.flags & flags::POLICY_FLAG_DENY_ALL != 0 {
        return Ok(-1);
    }
    if policy.flags & flags::POLICY_FLAG_ALLOW_ALL != 0 {
        return Ok(0);
    }

    // Check if this command is in the allowed bitmap
    let cmd_bit = cmd as u32;
    if cmd_bit < 32 && (policy.allowed_cmds & (1 << cmd_bit)) != 0 {
        Ok(0)
    } else {
        info!(ctx, "bpf_rbac: denied cmd={} for userns={}", cmd, userns_id);
        Ok(-1) // EPERM
    }
}

/// LSM hook: security_bpf_prog_load
///
/// Called when a BPF program is being loaded. Checks whether the program type
/// is allowed for the calling process's user namespace.
///
/// Arguments in context:
///   - prog: *const bpf_prog
///   - attr: *const bpf_attr
///   - token: *const bpf_token
///   - kernel: bool
#[lsm(hook = "bpf_prog_load")]
pub fn bpf_rbac_prog_load(ctx: LsmContext) -> i32 {
    match try_bpf_rbac_prog_load(&ctx) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

fn try_bpf_rbac_prog_load(ctx: &LsmContext) -> Result<i32, i64> {
    let kernel: u32 = unsafe { ctx.arg(3) };
    if kernel != 0 {
        return Ok(0);
    }

    let userns_id = get_current_userns_id()?;
    let key = PolicyKey { userns_id };
    let policy = unsafe { POLICY_MAP.get(&key) };

    let policy = match policy {
        Some(p) => p,
        None => return Ok(-1),
    };

    if policy.flags & flags::POLICY_FLAG_DENY_ALL != 0 {
        return Ok(-1);
    }
    if policy.flags & flags::POLICY_FLAG_ALLOW_ALL != 0 {
        return Ok(0);
    }

    // Read prog_type from the bpf_prog struct.
    // The prog_type field is at a known offset in struct bpf_prog.
    // This offset depends on kernel version; we use BTF to resolve it.
    // For now, read from bpf_attr which is the second argument.
    // attr->prog_type is the first u32 field in the prog_load union member.
    let attr: *const u32 = unsafe { ctx.arg(1) };
    if attr.is_null() {
        return Ok(-1);
    }
    let prog_type: u32 = unsafe { core::ptr::read_volatile(attr) };

    if prog_type < 32 && (policy.allowed_prog_types & (1 << prog_type)) != 0 {
        Ok(0)
    } else {
        info!(
            ctx,
            "bpf_rbac: denied prog_type={} for userns={}", prog_type, userns_id
        );
        Ok(-1)
    }
}

/// LSM hook: security_bpf_map_create
///
/// Called when a BPF map is being created. Checks whether the map type
/// is allowed for the calling process's user namespace.
///
/// Arguments in context:
///   - map: *const bpf_map
///   - attr: *const bpf_attr
///   - token: *const bpf_token
///   - kernel: bool
#[lsm(hook = "bpf_map_create")]
pub fn bpf_rbac_map_create(ctx: LsmContext) -> i32 {
    match try_bpf_rbac_map_create(&ctx) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

fn try_bpf_rbac_map_create(ctx: &LsmContext) -> Result<i32, i64> {
    let kernel: u32 = unsafe { ctx.arg(3) };
    if kernel != 0 {
        return Ok(0);
    }

    let userns_id = get_current_userns_id()?;
    let key = PolicyKey { userns_id };
    let policy = unsafe { POLICY_MAP.get(&key) };

    let policy = match policy {
        Some(p) => p,
        None => return Ok(-1),
    };

    if policy.flags & flags::POLICY_FLAG_DENY_ALL != 0 {
        return Ok(-1);
    }
    if policy.flags & flags::POLICY_FLAG_ALLOW_ALL != 0 {
        return Ok(0);
    }

    // Read map_type from bpf_attr (first u32 field in map_create union member)
    let attr: *const u32 = unsafe { ctx.arg(1) };
    if attr.is_null() {
        return Ok(-1);
    }
    let map_type: u32 = unsafe { core::ptr::read_volatile(attr) };

    if map_type < 32 && (policy.allowed_map_types & (1 << map_type)) != 0 {
        Ok(0)
    } else {
        info!(
            ctx,
            "bpf_rbac: denied map_type={} for userns={}", map_type, userns_id
        );
        Ok(-1)
    }
}

/// Get the current task's user namespace inode ID.
///
/// This walks: current->nsproxy->user_ns->ns.inum
/// Requires BTF support on the target kernel.
fn get_current_userns_id() -> Result<u64, i64> {
    // In a real implementation, this would use BPF helpers/kfuncs to read:
    //   bpf_get_current_task() -> task_struct
    //   task->nsproxy->user_ns->ns.inum
    //
    // With BTF and CO-RE, this can be done portably:
    //   let task = bpf_get_current_task_btf();
    //   let userns = task->nsproxy->user_ns;
    //   let inum = userns->ns.inum;
    //
    // For the initial skeleton, return 0 (will match no policy entry,
    // causing the hook to allow the operation by default).
    // TODO: Implement with bpf_get_current_task_btf() + CO-RE field access
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
