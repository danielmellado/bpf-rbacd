//! eBPF LSM programs for bpf-rbacd policy enforcement.
//!
//! These programs hook into the kernel's LSM framework to enforce
//! per-namespace BPF access policies. They read the policy from an
//! eBPF map populated by the userspace daemon.

#![no_std]
#![no_main]
// The link_section attribute on extern fns is the current way to declare
// kfuncs in Rust eBPF programs. The compiler warns it will become a hard
// error, but there is no alternative yet -- see aya-rs/aya#432.
#![allow(unused_attributes)]

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};
use aya_log_ebpf::info;
use bpf_rbacd_common::{flags, insn, BpfInsn, PolicyKey, PolicyValue, MAX_POLICY_ENTRIES};

// ---------------------------------------------------------------------------
// Open-coded iterator kfunc declarations (kernel 6.4+)
//
// These are kernel functions resolved at load time via BTF. The
// .ksyms link section tells the loader to look them up in vmlinux BTF
// rather than expecting them in the ELF object.
// ---------------------------------------------------------------------------

/// On-stack state for the numeric open-coded iterator.
/// Size must match the kernel's `struct bpf_iter_num` (8 bytes, 8-aligned).
#[repr(C, align(8))]
struct BpfIterNum {
    __opaque: [u64; 1],
}

unsafe extern "C" {
    /// Initialize a numeric iterator over the range `[start, end)`.
    #[link_section = ".ksyms"]
    fn bpf_iter_num_new(it: *mut BpfIterNum, start: i32, end: i32) -> i32;

    /// Advance the iterator. Returns a pointer to the current value,
    /// or NULL when iteration is complete.
    #[link_section = ".ksyms"]
    fn bpf_iter_num_next(it: *mut BpfIterNum) -> *const i32;

    /// Destroy the iterator and free stack resources.
    #[link_section = ".ksyms"]
    fn bpf_iter_num_destroy(it: *mut BpfIterNum);
}

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
    let cmd: i32 = ctx.arg(0);

    let kernel: u32 = ctx.arg(3);
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
        None => return Ok(0), // Not a managed namespace
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

/// Walk the BPF bytecode of a program being loaded and log any
/// helper or kfunc calls it makes.
///
/// Uses the numeric open-coded iterator (`bpf_iter_num_*` kfuncs) to
/// loop over every instruction without hitting verifier complexity
/// limits.  Each instruction is read from kernel memory via
/// `bpf_probe_read_kernel` and checked for `BPF_JMP | BPF_CALL`
/// opcodes.
///
/// # Safety
///
/// `prog` must be a valid pointer to a kernel `struct bpf_prog`.
/// The `len` field (u32 at byte offset 4) and `insnsi` pointer
/// (at byte offset 48 on 6.x kernels) are read with
/// `bpf_probe_read_kernel`.
///
/// # Arguments
///
/// * `ctx` - LSM context, forwarded for logging.
/// * `prog` - Pointer to the `struct bpf_prog` being loaded.
unsafe fn walk_bpf_instructions(ctx: &LsmContext, prog: *const u8) {
    // Read prog->len (instruction count).
    // offsetof(struct bpf_prog, len) = 4 on current kernels.
    let insn_cnt: u32 = match bpf_probe_read_kernel(prog.add(4) as *const u32) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Read prog->insnsi pointer.
    // offsetof(struct bpf_prog, insnsi) = 48 on 6.x kernels.
    let insnsi: *const u8 = match bpf_probe_read_kernel(prog.add(48) as *const *const u8) {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut it = core::mem::MaybeUninit::<BpfIterNum>::uninit();
    bpf_iter_num_new(it.as_mut_ptr(), 0, insn_cnt as i32);

    loop {
        let idx_ptr = bpf_iter_num_next(it.as_mut_ptr());
        if idx_ptr.is_null() {
            break;
        }
        let idx = *idx_ptr as u32;

        let insn_ptr = insnsi.add((idx as usize) * core::mem::size_of::<BpfInsn>());
        let insn_result: Result<BpfInsn, _> = bpf_probe_read_kernel(insn_ptr as *const BpfInsn);
        let bpf_insn = match insn_result {
            Ok(v) => v,
            Err(_) => continue,
        };

        if bpf_insn.code != insn::BPF_JMP_CALL {
            continue;
        }

        if bpf_insn.src_reg() == insn::BPF_HELPER_CALL {
            info!(ctx, "bpf_rbac: prog calls helper id={}", bpf_insn.imm);
        } else if bpf_insn.src_reg() == insn::BPF_PSEUDO_KFUNC_CALL {
            info!(ctx, "bpf_rbac: prog calls kfunc id={}", bpf_insn.imm);
        }
    }

    bpf_iter_num_destroy(it.as_mut_ptr());
}

/// LSM hook: security_bpf_prog_load
///
/// Called when a BPF program is being loaded. Checks whether the program type
/// is allowed for the calling process's user namespace, and walks the
/// program's bytecode to log helper/kfunc usage.
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
    let kernel: u32 = ctx.arg(3);
    if kernel != 0 {
        return Ok(0);
    }

    // Walk the program's instructions to log helper/kfunc calls.
    let prog: *const u8 = ctx.arg(0);
    if !prog.is_null() {
        unsafe { walk_bpf_instructions(ctx, prog) };
    }

    let userns_id = get_current_userns_id()?;
    let key = PolicyKey { userns_id };
    let policy = unsafe { POLICY_MAP.get(&key) };

    let policy = match policy {
        Some(p) => p,
        None => return Ok(0),
    };

    if policy.flags & flags::POLICY_FLAG_DENY_ALL != 0 {
        return Ok(-1);
    }
    if policy.flags & flags::POLICY_FLAG_ALLOW_ALL != 0 {
        return Ok(0);
    }

    // Read prog_type from bpf_attr (second argument).
    // attr->prog_type is the first u32 field in the prog_load union member.
    let attr: *const u32 = ctx.arg(1);
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
    let kernel: u32 = ctx.arg(3);
    if kernel != 0 {
        return Ok(0);
    }

    let userns_id = get_current_userns_id()?;
    let key = PolicyKey { userns_id };
    let policy = unsafe { POLICY_MAP.get(&key) };

    let policy = match policy {
        Some(p) => p,
        None => return Ok(0),
    };

    if policy.flags & flags::POLICY_FLAG_DENY_ALL != 0 {
        return Ok(-1);
    }
    if policy.flags & flags::POLICY_FLAG_ALLOW_ALL != 0 {
        return Ok(0);
    }

    // Read map_type from bpf_attr (first u32 field in map_create union member)
    let attr: *const u32 = ctx.arg(1);
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
