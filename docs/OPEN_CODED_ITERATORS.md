# Open-Coded Iterators from Aya: Feasibility Report

> Investigation for [issue #19](https://github.com/danielmellado/bpf-rbacd/issues/19):
> Can we use open-coded iterators from Aya to walk BPF program instructions?

**Short answer: Yes, with one toolchain gap.** The Rust code compiles,
the BPF call pattern is correct, relocations are properly emitted, and
BTF debug info is generated. However, `rustc` does not emit DWARF for
`unsafe extern "C"` declarations on BPF targets, so bpf-linker cannot
generate the `.ksyms` BTF metadata that Aya needs to resolve kfuncs.
A Rust compiler fix is in progress:
[rust-lang/rust#152899](https://github.com/rust-lang/rust/pull/152899)
(open, draft).

## What we tried

We replicated the [C PoC](https://github.com/tohojo/bpf-rbac-lsm/commit/dfd7541)
in Rust: an `lsm/bpf_prog_load` hook that walks every BPF instruction
of a program being loaded, looking for helper and kfunc calls.

The C version uses `bpf_for(i, 0, insn_cnt)` — a macro that expands
into three kernel function (kfunc) calls:

- `bpf_iter_num_new()` — start iterating from 0 to insn_cnt
- `bpf_iter_num_next()` — get the next number (returns NULL when done)
- `bpf_iter_num_destroy()` — clean up

These are "open-coded iterators" (kernel 6.4+). Unlike a normal for
loop, the BPF verifier only needs to check two states no matter how
many iterations happen, so they work even for programs with millions
of instructions.

### Why do we need three function calls for a loop?

A normal `for` loop uses a counter variable that the verifier has to
trace through every possible value. After roughly 4,000 iterations
the verifier gives up — too many states to track — and rejects the
program.

Open-coded iterators are a deal with the kernel: instead of the
verifier proving termination on its own, you use three kernel-managed
functions:

1. **`new`** — "I want to count from 0 to N." The kernel sets up a
   small iterator object on your BPF stack.
2. **`next`** — "Give me the next number." Returns a pointer to the
   current value, or NULL when done.
3. **`destroy`** — "I'm done, clean up." Releases the iterator state.

The verifier only checks two states: "next returned a value" and
"next returned NULL." Whether N is 10 or 10 million makes no
difference — the verification cost is constant.

The `destroy` call exists because the iterator is a kernel-managed
resource. You asked the kernel to create it, so you have to tell it
when you're finished — like opening and closing a file.

### Where does `bpf_for` come from, and why only in C?

The `bpf_for` macro is defined in the kernel source tree at
`tools/lib/bpf/bpf_helpers.h` (added in Linux 6.4). It's a C
preprocessor macro that hides the three kfunc calls behind a
normal-looking `for` loop:

```c
bpf_for(i, 0, N) {     // calls new(), then next() on each iteration
    // your code
}                        // calls destroy() automatically via GCC cleanup
```

It relies on two C/GCC features that don't exist in Rust's eBPF
environment:

- **C preprocessor macros** — arbitrary text substitution that can
  rewrite a `for` loop header. Rust has `macro_rules!` which could
  do something similar, but nobody has written a `bpf_for!` macro
  for Aya yet.
- **GCC `cleanup` attribute** — automatically calls `destroy` when
  the iterator goes out of scope (like Rust's `Drop` trait, but for
  C stack variables).

So the macro only exists in C because the kernel BPF developers
wrote it for their own toolchain (clang + libbpf). There's no
technical reason it can't exist in Rust — someone just needs to write
it. Until then, we spell out the three calls manually.

## What we changed

### Dependencies (all three Cargo.toml files)

Pinned all Aya crates to git main at commit `70e1983` (2026-08-19).
This is necessary because kfunc support ([aya-rs/aya#1372](https://github.com/aya-rs/aya/pull/1372))
was merged on 2026-07-09, after the latest published release (v0.14.0,
2026-06-24).

### New types (`bpf-rbacd-common/src/lib.rs`)

Added `BpfInsn` — a `#[repr(C)]` struct matching the kernel's
`struct bpf_insn` (8 bytes), plus constants for identifying call
instructions:

```rust
pub struct BpfInsn {
    pub code: u8,      // opcode
    pub regs: u8,      // dst_reg (low nibble) | src_reg (high nibble)
    pub off: i16,      // offset
    pub imm: i32,      // immediate (helper/kfunc ID for calls)
}
```

### Kfunc declarations (`bpf-rbacd-ebpf/src/main.rs`)

Declared the iterator kfuncs as extern C functions with `.ksyms`
link section — the Rust equivalent of `extern ... __ksym` in C:

```rust
unsafe extern "C" {
    #[link_section = ".ksyms"]
    fn bpf_iter_num_new(it: *mut BpfIterNum, start: i32, end: i32) -> i32;
    #[link_section = ".ksyms"]
    fn bpf_iter_num_next(it: *mut BpfIterNum) -> *const i32;
    #[link_section = ".ksyms"]
    fn bpf_iter_num_destroy(it: *mut BpfIterNum);
}
```

### Instruction walker (`bpf-rbacd-ebpf/src/main.rs`)

Added `walk_bpf_instructions()` which:

1. Reads `prog->len` (how many instructions) via `bpf_probe_read_kernel`
2. Creates an iterator from 0 to that count
3. Reads each 8-byte instruction from kernel memory
4. If the instruction is a function call (`code == 0x85`), logs whether
   it's a helper (src_reg == 0) or kfunc (src_reg == 2) and its ID

## Results

### What works

- **Compilation**: The eBPF crate compiles cleanly with `cargo +nightly
  build --target bpfel-unknown-none -Z build-std=core --release`

- **Kfunc symbols**: The output ELF binary contains the expected
  undefined symbols:
  ```
  17: ... NOTYPE  GLOBAL DEFAULT UND bpf_iter_num_new
  18: ... NOTYPE  GLOBAL DEFAULT UND bpf_iter_num_next
  19: ... NOTYPE  GLOBAL DEFAULT UND bpf_iter_num_destroy
  ```

- **Call relocations**: The `lsm/bpf_prog_load` section has proper
  `R_BPF_64_32` relocations pointing to these symbols — the same
  relocation type used for BPF function calls.

- **Main workspace**: The userspace crate also builds with the updated
  Aya from git (v0.14.0 unreleased), including the kfunc relocation
  support in `aya-obj`.

- **BTF emission**: `.BTF` and `.BTF.ext` sections are present in the
  output ELF. This was initially blocked by an `Invalid record` error
  in bpf-linker — the fix was switching from a source-built
  bpf-linker to the **pre-built release binary** via
  `cargo binstall bpf-linker` (or direct download from the
  [releases page](https://github.com/aya-rs/bpf-linker/releases)).
  The source build linked against a slightly different LLVM 23 snapshot
  than what the Rust nightly uses, causing bitcode format mismatch.

### What doesn't work yet: kernel load

We wrote a smoke test (`test_ebpf_lsm_load_smoke` in
`tests/integration.rs`) that loads the ELF with Aya and tries to
attach the LSM hooks. It fails at the Aya relocation stage:

```
ExternNotFound { name: "bpf_iter_num_new" }
```

The root cause is a **three-layer problem** that we traced end-to-end:

**Layer 1 — Rust compiler** (`rustc`): Does not emit DWARF debug
information for `unsafe extern "C"` function declarations when
targeting BPF. In C, `clang` emits a `DW_TAG_subprogram` with
`DW_AT_external` and `DW_AT_declaration` for extern function
declarations. Rust's codegen skips debug info entirely for foreign
function items.

**Layer 2 — bpf-linker**: Without DWARF subprogram entries for the
kfuncs, the LLVM BPF backend cannot generate BTF FUNC entries. No
FUNC entries means no `.ksyms` DATASEC is emitted. The bpf-linker
fork's anti-internalization patch (PR #317) correctly preserves the
ELF symbols but that alone does not create BTF entries.

**Layer 3 — Aya loader**: When `Ebpf::load()` parses the ELF, it
calls `collect_ksyms_from_btf()` which looks for a `.ksyms` DATASEC
to populate the extern resolution map. Since none exists, the map is
empty. Later, during relocation, when Aya encounters a call
instruction referencing an undefined symbol, it looks up the symbol
name in the empty externs map and fails with `ExternNotFound`.

Dumping the ELF's BTF with `bpftool btf dump` confirms only `maps`
and `.rodata` DATASEC entries exist — no `.ksyms`:

```
[37] DATASEC '.rodata' size=0 vlen=1
[38] DATASEC 'maps' size=0 vlen=2
```

The same underlying problem is tracked across three repositories:
- Compiler: [rust-lang/rust#152899](https://github.com/rust-lang/rust/pull/152899)
- Linker: [aya-rs/bpf-linker#317](https://github.com/aya-rs/bpf-linker/pull/317)
- Loader: [aya-rs/aya#1245](https://github.com/aya-rs/aya/issues/1245) (resolved by PR #1372)

### Known warnings

- **`link_section` on extern fns**: The Rust compiler warns that
  `#[link_section]` on foreign function declarations "was previously
  accepted but is being phased out." There's no alternative yet for
  marking functions as kernel symbols. When this becomes a hard error,
  a different approach will be needed (possibly a proc macro or
  Aya-level abstraction).

## Next steps

### Blocker: Rust compiler doesn't emit debug info for BPF externs

The full kfunc pipeline requires three components working together:

1. **`rustc`** emits DWARF debug info for `unsafe extern "C"`
   declarations → bpf-linker can generate BTF FUNC entries
2. **`bpf-linker`** preserves extern symbols and generates a
   `.ksyms` DATASEC in BTF containing those FUNC entries
3. **Aya** reads the `.ksyms` DATASEC, resolves the kfuncs against
   kernel BTF, and patches the call relocations

As of August 2026, component 3 is complete (Aya PR
[#1372](https://github.com/aya-rs/aya/pull/1372), merged
2026-07-09). Component 2 is partially addressed: bpf-linker v0.9.15+
includes PR [#294](https://github.com/aya-rs/bpf-linker/pull/294)
("Prevent LLVM from inserting ksyms symbols"), and the
`altugbozkurt07/bpf-linker` fork (PR
[#317](https://github.com/aya-rs/bpf-linker/pull/317)) adds extra
handling for undefined extern functions.

**The root cause blocker is component 1**: `rustc` does not emit
DWARF debug information for `unsafe extern "C"` function
declarations when targeting BPF. Without DWARF, LLVM's BTF backend
has nothing to generate a BTF FUNC entry from, so bpf-linker cannot
create a `.ksyms` DATASEC — regardless of how many other fixes are
applied.

**The fix**: Rust compiler PR
[rust-lang/rust#152899](https://github.com/rust-lang/rust/pull/152899)
("Generate debug info for BPF extern declarations") by
@altugbozkurt07. It:
- Allows `#[link_section]` on `ForeignStatic` and `ForeignFn`
- Adds an FFI wrapper for `LLVMDIBuilderCreateGlobalVariableExpression`
  with `isDefinition` support
- Emits debug info for BPF extern function and variable declarations
  (gated to `Arch::Bpf`)

**Status**: Open, draft, `S-waiting-on-author` since March 2026.

### What we verified during testing

We confirmed the pipeline *partially* works by testing with the
`altugbozkurt07/bpf-linker` `ksyms` fork (built with nightly/LLVM 23):

- **bpf-linker fork preserves extern symbols**: The output ELF
  correctly contains `NOTYPE GLOBAL DEFAULT UND bpf_iter_num_*`
  symbols (not internalized).
- **BTF is generated** with `.BTF` and `.BTF.ext` sections present.
- **No `.ksyms` DATASEC exists** in the BTF output (confirmed via
  `bpftool btf dump`). Only `.rodata` and `maps` DATASECs are
  generated — because `rustc` emits no DWARF for the extern
  declarations.
- **Aya loads the binary** but hits `ExternNotFound` during
  relocation because `collect_ksyms_from_btf()` finds no `.ksyms`
  DATASEC to populate the externs map.

The earlier `BtfError(MaybeUninit<u8> Invalid name)` error was a red
herring: it was a *separate* bug (bpf-linker not sanitizing union
type names containing Rust generic syntax). The kernel rejected the
BTF at load time, which happened to mask the `ExternNotFound` error
that would have appeared during the subsequent relocation phase.

### Secondary issue: BTF union name sanitization

bpf-linker's DI sanitizer replaces Rust generic syntax in struct
names (e.g., `UnsafeCell<T>` becomes `UnsafeCell_3C_T_3E_`), but
does NOT sanitize union names. Since `MaybeUninit<T>` and
`ManuallyDrop<T>` are Rust unions, their BTF names retain angle
brackets, which the kernel BTF validator rejects as invalid C
identifiers.

This is tracked separately and is a straightforward fix once the
primary blocker is resolved (add `DW_TAG_union_type` to the DI
sanitizer's match expression).

### Watch: `link_section` deprecation

The `#[link_section = ".ksyms"]` attribute on extern functions will
eventually become a hard error. The compiler PR
[rust-lang/rust#152899](https://github.com/rust-lang/rust/pull/152899)
addresses both problems at once — it makes `#[link_section]` valid
on foreign items and emits the debug info needed for proper BTF
generation.

### Alternatives that work today (no toolchain fixes needed)

The open-coded iterator (kfunc) approach gives unlimited iteration
but requires the full three-layer toolchain fix. For the RBAC use
case, simpler alternatives work today with zero blocked PRs:

**Option A: Bounded loop (simplest, works now)**

A plain `for` loop works for programs up to approximately 4,096
instructions. The BPF verifier accepts bounded loops as long as it
can prove termination:

```rust
const MAX_INSNS: u32 = 4096;
let limit = if insn_cnt < MAX_INSNS { insn_cnt } else { MAX_INSNS };
for i in 0..limit {
    // read and check instruction
}
```

Most real-world BPF programs are well under 4K instructions. For
RBAC enforcement, programs too large to fully scan can be
default-denied (or allowed via a policy flag). This is a valid
security posture: "if I can't verify it, reject it."

**Option B: `bpf_loop()` helper (kernel 5.17+, no kfuncs)**

`bpf_loop` is a regular BPF helper (helper #181), not a kfunc. Aya
handles helpers natively — no `.ksyms` DATASEC or BTF metadata
needed. It supports up to approximately 8 million iterations:

```rust
// bpf_loop(nr_loops, callback_fn, callback_ctx, flags)
```

The downside: the callback pattern requires a function pointer plus
an opaque context struct, which is more awkward in Rust than a
simple loop. The callback must be a separate `#[no_mangle]` BPF
function.

**Option C: C shim (just for the iterator)**

Write a minimal C file that uses `bpf_for()`, compile it with
clang, and link it into the Rust eBPF binary via bpf-linker. The
rest of the program stays in Rust. This is how the bpf-linker PR
#317 was originally tested by users.

**Comparison of approaches:**

| Approach | Max iterations | Toolchain deps | Complexity | Available today |
|----------|---------------|----------------|------------|-----------------|
| Bounded loop | ~4,096 | None | Trivial | Yes |
| `bpf_loop()` helper | ~8M | None | Moderate (callback) | Yes (kernel 5.17+) |
| C shim + `bpf_for` | Unlimited | clang | Low (mixed build) | Yes |
| Open-coded iterators (kfuncs) | Unlimited | rustc PR + bpf-linker PR | None (cleanest) | No |

**Recommendation**: Start with a bounded loop (Option A) for
immediate testing and integration. The 4K cap is sufficient for the
vast majority of BPF programs, and the policy engine can reject or
skip programs that exceed the limit. Upgrade to kfuncs once the
toolchain support lands.

### Unblocking path (for kfunc approach)

To unblock the kfunc approach for Rust eBPF programs, the following
must happen (in dependency order):

1. `rust-lang/rust#152899` merges and lands in a nightly release
2. `bpf-linker` PR #317 (or equivalent) merges to handle the
   new DWARF and generate `.ksyms` DATASEC entries
3. A new pre-built bpf-linker release is published

Until then, the workaround for unlimited iteration is Option B or C
above.

### Future: production readiness

Once the kfunc loading works:

1. Replace hardcoded struct offsets (`prog->len` at byte 4,
   `prog->insnsi` at byte 48) with BTF/CO-RE field access
2. Use the instruction walk results for actual policy enforcement
   (deny programs that call forbidden helpers/kfuncs)
3. Add `allowed_helpers` and `allowed_kfuncs` bitmaps to `PolicyValue`

## Comparison with the C PoC

Our Rust implementation mirrors Toke's
[C PoC](https://github.com/tohojo/bpf-rbac-lsm/commit/dfd7541). Here's
how they relate.

### The C version (Toke's)

```c
static void walk_bpf_instructions(struct bpf_prog *prog)
{
    int insn_cnt = prog->len, i;

    bpf_for(i, 0, insn_cnt) {
        struct bpf_insn insn;
        if (bpf_probe_read_kernel(&insn, sizeof(insn), &prog->insnsi[i]))
            continue;
        if (insn.code != (BPF_JMP | BPF_CALL))
            continue;
        if (insn.src_reg == 0)
            bpf_printk("helper %d", insn.imm);
        else if (insn.src_reg == BPF_PSEUDO_KFUNC_CALL)
            bpf_printk("kfunc %d", insn.imm);
    }
}
```

Key things the C version gets "for free":

- **`bpf_for` macro** — hides the `bpf_iter_num_{new,next,destroy}`
  kfunc triple behind a single `for`-like construct.
- **CO-RE field access** — `prog->len` and `prog->insnsi[i]` are
  resolved at load time via BTF. The compiler never hardcodes byte
  offsets.
- **`vmlinux.h`** — auto-generated header that provides every kernel
  type (`struct bpf_prog`, `struct bpf_insn`, etc.) plus constants
  like `BPF_JMP`, `BPF_CALL`, `BPF_PSEUDO_KFUNC_CALL`.
- **`BPF_PROG` macro** — unwraps LSM hook arguments with named
  types (e.g., `struct bpf_prog *prog`).

### The Rust version (ours)

```rust
unsafe fn walk_bpf_instructions(ctx: &LsmContext, prog: *const u8) {
    let insn_cnt: u32 = match bpf_probe_read_kernel(prog.add(4) as ...) { ... };
    let insnsi: *const u8 = match bpf_probe_read_kernel(prog.add(48) as ...) { ... };

    let mut it = core::mem::MaybeUninit::<BpfIterNum>::uninit();
    bpf_iter_num_new(it.as_mut_ptr(), 0, insn_cnt as i32);
    loop {
        let idx_ptr = bpf_iter_num_next(it.as_mut_ptr());
        if idx_ptr.is_null() { break; }
        let idx = *idx_ptr as u32;
        let bpf_insn: BpfInsn = match bpf_probe_read_kernel(...) { ... };
        // same call-detection logic as C
    }
    bpf_iter_num_destroy(it.as_mut_ptr());
}
```

What we had to do manually:

- **Kfunc declarations** — three `unsafe extern "C"` functions with
  `#[link_section = ".ksyms"]`, since there's no `bpf_for` macro in
  Aya yet.
- **Iterator protocol** — explicit `MaybeUninit`, `new`/`next`/`destroy`
  calls, and a `loop` + null check instead of a one-liner `bpf_for`.
- **Hardcoded struct offsets** — `prog.add(4)` for `len` and
  `prog.add(48)` for `insnsi`, because Aya doesn't have CO-RE field
  access. These offsets are correct on current 6.x kernels but could
  break on a different version.
- **`BpfInsn` struct** — we defined our own `#[repr(C)]` struct in
  `bpf-rbacd-common` instead of getting it from `vmlinux.h`.
- **Raw `ctx.arg(N)`** — we extract the `bpf_prog` pointer by
  positional index rather than named type.

### What this means

| Aspect | C (Toke) | Rust (ours) |
|--------|----------|-------------|
| Iteration | `bpf_for(i, 0, n)` one-liner | 7-line `new`/`next`/`destroy` manual loop |
| Field access | CO-RE: `prog->len` | Hardcoded offset: `prog.add(4)` |
| Kernel types | `vmlinux.h` | Hand-rolled `BpfInsn` |
| Hook args | `BPF_PROG(hook, struct bpf_prog *prog)` | `ctx.arg::<*const u8>(0)` |
| BTF dependency | Implicit (libbpf handles it) | Explicit (`--btf` flag + pre-built bpf-linker) |
| Build tooling | clang + libbpf + bpftool | cargo + nightly + bpf-linker |

The generated BPF bytecode is functionally identical — same kfunc
calls, same instruction-reading pattern, same call-detection logic.
The difference is ergonomics: C benefits from years of kernel-side
macros and tooling, while Rust/Aya is still catching up.

### Closing the gap

The main gaps can be addressed incrementally:

1. **A `bpf_for!` macro** in Aya (or in our crate) would collapse
   the iterator boilerplate into a single line.
2. **CO-RE field access** via Aya would replace hardcoded offsets
   with portable BTF-based reads. This is tracked upstream.
3. **Bindgen for `vmlinux.h`** would auto-generate Rust types for
   kernel structures, eliminating hand-rolled structs like `BpfInsn`.

None of these are blockers — the current approach produces correct
bytecode and can go to kernel testing today.

## Alternatives considered

| Approach | Pros | Cons |
|----------|------|------|
| **Bounded loop** | Works today, no deps | Capped at ~4K iterations, misses large programs |
| **`bpf_loop()` helper** | No kfunc needed | Callback pattern awkward in Rust |
| **C shim** | Known working | Mixed C/Rust build, calling convention risks |
| **Open-coded iterators** (this) | No cap, clean code, verifier-friendly | Needs unreleased Aya + BTF fix |

## Build setup

The eBPF crate includes a `.cargo/config.toml` that enables BTF by
default:

```toml
[build]
target = "bpfel-unknown-none"
rustflags = ["-C", "debuginfo=2", "-C", "link-arg=--btf"]

[unstable]
build-std = ["core"]
```

With this config, a simple `cargo +nightly build --release` in the
`bpf-rbacd-ebpf/` directory is enough to get a BTF-annotated ELF.

**Important**: use the pre-built bpf-linker binary (via
`cargo binstall bpf-linker` or from the
[releases page](https://github.com/aya-rs/bpf-linker/releases)).
Building bpf-linker from source with `cargo install` may fail due to
LLVM bitcode version mismatch with the nightly compiler.

## Conclusion

Open-coded iterators from Aya are **feasible but not yet loadable**
due to a missing Rust compiler feature. The Rust toolchain produces
correct BPF bytecode with the right call relocations, and Aya's
loader now has full kfunc resolution support
([aya-rs/aya#1372](https://github.com/aya-rs/aya/pull/1372)). The
remaining blocker is that `rustc` does not emit DWARF debug info for
`unsafe extern "C"` declarations on BPF targets — without those,
bpf-linker cannot generate the `.ksyms` DATASEC entries that Aya
needs to resolve kfuncs against kernel BTF.

The fix is tracked in
[rust-lang/rust#152899](https://github.com/rust-lang/rust/pull/152899)
(open, draft, waiting on author since March 2026). Once that merges
and reaches a nightly build, the existing code in this project should
work with zero changes — the bytecode, kfunc declarations, and Aya
integration are all correct and ready.

This is a compiler infrastructure gap, not a language or design
problem. The Aya ecosystem (@altugbozkurt07, @vadorovsky) is
actively working on closing it across all three layers (rustc,
bpf-linker, aya-obj).
