//! Soft (INT3) and hardware (Dr0–Dr3) breakpoint primitives.
//!
//! # Soft breakpoints (INT3)
//!
//! Classical implementation: save the original byte at `address`,
//! `WriteProcessMemory` the `0xCC` opcode in its place, and
//! `FlushInstructionCache`. When the CPU executes `0xCC` an
//! `EXCEPTION_BREAKPOINT` event reaches Aurora's debug loop.
//!
//! To CONTINUE execution after a soft-BP hit, the handler
//! follows the **restore-and-single-step-and-reapply** pattern:
//!
//! 1. `SoftBreakpoint::restore(process, addr)` writes the
//!    original byte back.
//! 2. `set_trap_flag(thread)` sets `EFLAGS.TF` so the next
//!    instruction generates `EXCEPTION_SINGLE_STEP`.
//! 3. After the single-step exception lands, the handler clears
//!    TF (`clear_trap_flag`) and calls `SoftBreakpoint::install`
//!    again to re-arm the BP for next time.
//!
//! `breakpoints.rs` only ships the primitives. The compose-the-
//! pattern logic lives in the per-event handlers Aurora's
//! session orchestrator wires up at Step 54.
//!
//! # Hardware breakpoints (Dr0–Dr3)
//!
//! The x86-64 processor has four debug-address registers
//! (Dr0–Dr3) plus a control register (Dr7) that selects which
//! slots fire and on what access (execute / write / read-write)
//! at what length (1 / 2 / 4 / 8 bytes). Hardware BPs are
//! visible only to the kernel — the target's code can detect
//! them only by reading the debug registers (which Aurora's
//! anti-anti-debug hooks at Step 32 will block).
//!
//! Hardware BPs are PER-THREAD on Windows: each thread has its
//! own DR0–DR7 state. Aurora's hook handlers will need to
//! install + clear HW BPs across every observed thread in the
//! target. For Group B Step 10 only the per-thread primitives
//! ship.
//!
//! # Why we suspend the thread for DR changes
//!
//! `SetThreadContext` on a running thread is documented as
//! permitted, but on some Windows builds the kernel only writes
//! the new context at the next user-mode->kernel transition,
//! which can race with the target executing. Suspending +
//! Get/Set + Resume is the documented-safe pattern.

use crate::unpack::UnpackError;

/// One of the four x86-64 hardware-debug slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwSlot {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
}

impl HwSlot {
    pub fn index(self) -> u32 {
        match self {
            HwSlot::Dr0 => 0,
            HwSlot::Dr1 => 1,
            HwSlot::Dr2 => 2,
            HwSlot::Dr3 => 3,
        }
    }
}

/// Which kind of access triggers a HW BP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwBreakpointKind {
    /// Instruction fetch. LEN must be `One`.
    Execute,
    /// Write only.
    Write,
    /// Read or write. Does NOT fire on instruction fetch.
    ReadWrite,
}

impl HwBreakpointKind {
    /// 2-bit field for DR7 RW slot.
    fn rw_bits(self) -> u64 {
        match self {
            HwBreakpointKind::Execute => 0b00,
            HwBreakpointKind::Write => 0b01,
            HwBreakpointKind::ReadWrite => 0b11,
        }
    }
}

/// Watched access length for HW BPs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwBreakpointSize {
    One,
    Two,
    Four,
    Eight,
}

impl HwBreakpointSize {
    /// 2-bit field for DR7 LEN slot. Note `Eight` = 0b10 (P6+);
    /// `Four` = 0b11 — this is the historical Intel encoding,
    /// not a bug.
    fn len_bits(self) -> u64 {
        match self {
            HwBreakpointSize::One => 0b00,
            HwBreakpointSize::Two => 0b01,
            HwBreakpointSize::Eight => 0b10,
            HwBreakpointSize::Four => 0b11,
        }
    }
}

/// A soft (INT3) breakpoint installed at a process VA. Holds the
/// original byte so `restore` can put it back.
#[derive(Clone, Debug)]
pub struct SoftBreakpoint {
    pub address: u64,
    pub original_byte: u8,
}

/// A hardware (Dr0–Dr3) breakpoint installed on a thread.
#[derive(Clone, Debug)]
pub struct HwBreakpoint {
    pub slot: HwSlot,
    pub address: u64,
    pub kind: HwBreakpointKind,
    pub size: HwBreakpointSize,
}

#[cfg(windows)]
impl SoftBreakpoint {
    /// Read 1 byte at `address` (the original opcode), write
    /// `0xCC` in its place, flush the I-cache. Returns the
    /// `SoftBreakpoint` with the saved byte.
    pub fn install(
        process: windows::Win32::Foundation::HANDLE,
        address: u64,
    ) -> Result<Self, UnpackError> {
        let original = read_byte(process, address)?;
        write_byte(process, address, 0xCC)?;
        flush_i_cache(process, address, 1)?;
        Ok(SoftBreakpoint {
            address,
            original_byte: original,
        })
    }

    /// Write `self.original_byte` back at `self.address` and
    /// flush the I-cache. Use as the first step of the
    /// restore-step-reapply continuation pattern.
    pub fn restore(&self, process: windows::Win32::Foundation::HANDLE) -> Result<(), UnpackError> {
        write_byte(process, self.address, self.original_byte)?;
        flush_i_cache(process, self.address, 1)?;
        Ok(())
    }
}

#[cfg(not(windows))]
impl SoftBreakpoint {
    pub fn install(_process: (), _address: u64) -> Result<Self, UnpackError> {
        Err(UnpackError::UnsupportedPlatform)
    }
    pub fn restore(&self, _process: ()) -> Result<(), UnpackError> {
        Err(UnpackError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
impl HwBreakpoint {
    /// Install this HW BP on `thread`. Suspends + Gets + Sets +
    /// Resumes the thread to ensure the DR register update sticks.
    pub fn install(
        thread: windows::Win32::Foundation::HANDLE,
        slot: HwSlot,
        address: u64,
        kind: HwBreakpointKind,
        size: HwBreakpointSize,
    ) -> Result<Self, UnpackError> {
        if matches!(kind, HwBreakpointKind::Execute) && !matches!(size, HwBreakpointSize::One) {
            return Err(UnpackError::Pipeline(
                "Execute HW breakpoints require size=One".into(),
            ));
        }
        with_thread_context(thread, true, |ctx| {
            // Set the address register
            set_dr_address(ctx, slot, address);
            // Enable the slot in DR7
            dr7_enable_slot(ctx, slot, kind, size);
            Ok(())
        })?;
        Ok(HwBreakpoint {
            slot,
            address,
            kind,
            size,
        })
    }

    /// Clear the slot (also resets the DR address register to 0
    /// and the per-slot RW/LEN bits).
    pub fn clear(
        thread: windows::Win32::Foundation::HANDLE,
        slot: HwSlot,
    ) -> Result<(), UnpackError> {
        with_thread_context(thread, true, |ctx| {
            set_dr_address(ctx, slot, 0);
            dr7_disable_slot(ctx, slot);
            Ok(())
        })
    }
}

#[cfg(not(windows))]
impl HwBreakpoint {
    pub fn install(
        _thread: (),
        _slot: HwSlot,
        _address: u64,
        _kind: HwBreakpointKind,
        _size: HwBreakpointSize,
    ) -> Result<Self, UnpackError> {
        Err(UnpackError::UnsupportedPlatform)
    }
    pub fn clear(_thread: (), _slot: HwSlot) -> Result<(), UnpackError> {
        Err(UnpackError::UnsupportedPlatform)
    }
}

/// Set `EFLAGS.TF` (bit 8) on the thread's context — next user-
/// mode instruction generates `EXCEPTION_SINGLE_STEP` (0x80000004).
/// Use during soft-BP restore-step-reapply.
#[cfg(windows)]
pub fn set_trap_flag(thread: windows::Win32::Foundation::HANDLE) -> Result<(), UnpackError> {
    with_thread_context(thread, false, |ctx| {
        ctx.EFlags |= 0x100;
        Ok(())
    })
}

/// Clear `EFLAGS.TF` so the thread stops single-stepping after
/// the next continuation.
#[cfg(windows)]
pub fn clear_trap_flag(thread: windows::Win32::Foundation::HANDLE) -> Result<(), UnpackError> {
    with_thread_context(thread, false, |ctx| {
        ctx.EFlags &= !0x100;
        Ok(())
    })
}

#[cfg(not(windows))]
pub fn set_trap_flag(_thread: ()) -> Result<(), UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}
#[cfg(not(windows))]
pub fn clear_trap_flag(_thread: ()) -> Result<(), UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

// -------------------------------------------------------------
// Windows-internal helpers
// -------------------------------------------------------------

#[cfg(windows)]
fn read_byte(process: windows::Win32::Foundation::HANDLE, address: u64) -> Result<u8, UnpackError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let mut buf = [0u8; 1];
    let mut bytes_read: usize = 0;
    unsafe {
        ReadProcessMemory(
            process,
            address as *const _,
            buf.as_mut_ptr() as *mut _,
            1,
            Some(&mut bytes_read),
        )
        .map_err(|e| UnpackError::Pipeline(format!("ReadProcessMemory @ {:#x}: {}", address, e)))?;
    }
    if bytes_read != 1 {
        return Err(UnpackError::Pipeline(format!(
            "ReadProcessMemory partial: got {} bytes, wanted 1",
            bytes_read
        )));
    }
    Ok(buf[0])
}

#[cfg(windows)]
fn write_byte(
    process: windows::Win32::Foundation::HANDLE,
    address: u64,
    value: u8,
) -> Result<(), UnpackError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    let buf = [value; 1];
    let mut bytes_written: usize = 0;
    unsafe {
        WriteProcessMemory(
            process,
            address as *const _,
            buf.as_ptr() as *const _,
            1,
            Some(&mut bytes_written),
        )
        .map_err(|e| {
            UnpackError::Pipeline(format!("WriteProcessMemory @ {:#x}: {}", address, e))
        })?;
    }
    if bytes_written != 1 {
        return Err(UnpackError::Pipeline(format!(
            "WriteProcessMemory partial: wrote {} bytes, wanted 1",
            bytes_written
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn flush_i_cache(
    process: windows::Win32::Foundation::HANDLE,
    address: u64,
    size: usize,
) -> Result<(), UnpackError> {
    use windows::Win32::System::ProcessStatus::*;
    let _ = (process, address, size);
    // `windows` 0.59 puts FlushInstructionCache under
    // Win32::System::Diagnostics::Debug in some feature sets and
    // under Win32::System::ProcessStatus in others. Cross-version
    // pragmatic path: re-import directly.
    use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    unsafe {
        FlushInstructionCache(process, Some(address as *const _), size).map_err(|e| {
            UnpackError::Pipeline(format!(
                "FlushInstructionCache @ {:#x}..{:#x}: {}",
                address,
                address + size as u64,
                e
            ))
        })?;
    }
    Ok(())
}

/// Suspend → Get → mutate → Set → (optionally) Resume.
///
/// `with_dr_flag = true` selects `CONTEXT_DEBUG_REGISTERS_AMD64`
/// for the Get/Set; `false` selects `CONTEXT_CONTROL_AMD64` (for
/// `EFLAGS` access). Either flag implies `CONTEXT_AMD64`.
#[cfg(windows)]
fn with_thread_context<F>(
    thread: windows::Win32::Foundation::HANDLE,
    with_dr_flag: bool,
    f: F,
) -> Result<(), UnpackError>
where
    F: FnOnce(&mut windows::Win32::System::Diagnostics::Debug::CONTEXT) -> Result<(), UnpackError>,
{
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_CONTROL_AMD64,
        CONTEXT_DEBUG_REGISTERS_AMD64,
    };
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

    let suspended = unsafe { SuspendThread(thread) };
    if suspended == u32::MAX {
        return Err(UnpackError::Pipeline(format!(
            "SuspendThread failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // CONTEXT must be 16-byte aligned. Stack-allocate inside a
    // boxed wrapper to avoid alignment surprises. `windows` 0.59
    // marks CONTEXT with the correct repr but a Box is the
    // simplest cross-compiler-version guarantee.
    let mut ctx: Box<CONTEXT> = Box::new(unsafe { std::mem::zeroed() });
    ctx.ContextFlags = if with_dr_flag {
        CONTEXT_DEBUG_REGISTERS_AMD64
    } else {
        CONTEXT_CONTROL_AMD64
    };

    let get_res = unsafe { GetThreadContext(thread, &mut *ctx) };
    if let Err(e) = get_res {
        unsafe {
            let _ = ResumeThread(thread);
        }
        return Err(UnpackError::Pipeline(format!(
            "GetThreadContext failed: {}",
            e
        )));
    }

    let mutate = f(&mut ctx);
    if let Err(e) = mutate {
        unsafe {
            let _ = ResumeThread(thread);
        }
        return Err(e);
    }

    ctx.ContextFlags = if with_dr_flag {
        CONTEXT_DEBUG_REGISTERS_AMD64
    } else {
        CONTEXT_CONTROL_AMD64
    };
    let set_res = unsafe { SetThreadContext(thread, &*ctx) };
    let resume_res = unsafe { ResumeThread(thread) };
    if let Err(e) = set_res {
        return Err(UnpackError::Pipeline(format!(
            "SetThreadContext failed: {}",
            e
        )));
    }
    if resume_res == u32::MAX {
        return Err(UnpackError::Pipeline(format!(
            "ResumeThread failed after context set: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn set_dr_address(
    ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT,
    slot: HwSlot,
    address: u64,
) {
    match slot {
        HwSlot::Dr0 => ctx.Dr0 = address,
        HwSlot::Dr1 => ctx.Dr1 = address,
        HwSlot::Dr2 => ctx.Dr2 = address,
        HwSlot::Dr3 => ctx.Dr3 = address,
    }
}

#[cfg(windows)]
fn dr7_enable_slot(
    ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT,
    slot: HwSlot,
    kind: HwBreakpointKind,
    size: HwBreakpointSize,
) {
    let i = slot.index() as u64;
    // L0..L3 bits at positions 0,2,4,6
    let local_enable_bit = 1u64 << (i * 2);
    // RW field starts at bit 16 + i*4
    let rw_shift = 16 + (i * 4);
    // LEN field starts at bit 18 + i*4
    let len_shift = 18 + (i * 4);

    let mask_rw = 0b11u64 << rw_shift;
    let mask_len = 0b11u64 << len_shift;

    ctx.Dr7 |= local_enable_bit;
    ctx.Dr7 = (ctx.Dr7 & !mask_rw) | (kind.rw_bits() << rw_shift);
    ctx.Dr7 = (ctx.Dr7 & !mask_len) | (size.len_bits() << len_shift);
}

#[cfg(windows)]
fn dr7_disable_slot(ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT, slot: HwSlot) {
    let i = slot.index() as u64;
    let local_enable_bit = 1u64 << (i * 2);
    let global_enable_bit = 1u64 << (i * 2 + 1);
    let rw_shift = 16 + (i * 4);
    let len_shift = 18 + (i * 4);
    let mask_rw = 0b11u64 << rw_shift;
    let mask_len = 0b11u64 << len_shift;
    ctx.Dr7 &= !(local_enable_bit | global_enable_bit);
    ctx.Dr7 &= !mask_rw;
    ctx.Dr7 &= !mask_len;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hw_slot_indexes_are_0_to_3() {
        assert_eq!(HwSlot::Dr0.index(), 0);
        assert_eq!(HwSlot::Dr1.index(), 1);
        assert_eq!(HwSlot::Dr2.index(), 2);
        assert_eq!(HwSlot::Dr3.index(), 3);
    }

    #[test]
    fn hw_rw_bits_encode_intel_layout() {
        assert_eq!(HwBreakpointKind::Execute.rw_bits(), 0b00);
        assert_eq!(HwBreakpointKind::Write.rw_bits(), 0b01);
        assert_eq!(HwBreakpointKind::ReadWrite.rw_bits(), 0b11);
    }

    #[test]
    fn hw_len_bits_encode_intel_layout_including_eight_at_10() {
        // The historical Intel quirk: 8-byte length = 0b10, NOT 0b11.
        // 4-byte length = 0b11. This test guards against the natural
        // "size in bits / byte index" mis-encoding.
        assert_eq!(HwBreakpointSize::One.len_bits(), 0b00);
        assert_eq!(HwBreakpointSize::Two.len_bits(), 0b01);
        assert_eq!(HwBreakpointSize::Eight.len_bits(), 0b10);
        assert_eq!(HwBreakpointSize::Four.len_bits(), 0b11);
    }

    #[cfg(windows)]
    #[test]
    fn execute_bp_with_non_one_size_is_rejected() {
        // We need a HANDLE for the type but the install fails
        // before any FFI call, so a null handle is fine.
        let null = windows::Win32::Foundation::HANDLE(std::ptr::null_mut());
        let result = HwBreakpoint::install(
            null,
            HwSlot::Dr0,
            0x1000,
            HwBreakpointKind::Execute,
            HwBreakpointSize::Four,
        );
        match result {
            Err(UnpackError::Pipeline(msg)) => {
                assert!(msg.contains("Execute HW breakpoints require size=One"));
            }
            other => panic!(
                "expected Pipeline error rejecting size, got {:?}",
                other.err()
            ),
        }
    }

    #[cfg(windows)]
    #[test]
    fn dr7_enable_disable_round_trips_to_clean() {
        use windows::Win32::System::Diagnostics::Debug::CONTEXT;
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        // Enable Dr1 with ReadWrite/Four
        dr7_enable_slot(
            &mut ctx,
            HwSlot::Dr1,
            HwBreakpointKind::ReadWrite,
            HwBreakpointSize::Four,
        );
        assert_ne!(ctx.Dr7, 0);
        // Disable should bring Dr7 back to zero (no other slots
        // were touched).
        dr7_disable_slot(&mut ctx, HwSlot::Dr1);
        assert_eq!(ctx.Dr7, 0);
    }

    #[cfg(windows)]
    #[test]
    fn dr7_per_slot_bit_positions_are_correct() {
        use windows::Win32::System::Diagnostics::Debug::CONTEXT;
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        // Enable Dr2 with Write/Two
        dr7_enable_slot(
            &mut ctx,
            HwSlot::Dr2,
            HwBreakpointKind::Write,
            HwBreakpointSize::Two,
        );
        // L2 is bit 4
        assert_eq!(ctx.Dr7 & (1 << 4), 1 << 4, "L2 should be set");
        // RW2 is at bits 24-25; Write = 0b01
        assert_eq!((ctx.Dr7 >> 24) & 0b11, 0b01, "RW2 should be 01 for Write");
        // LEN2 is at bits 26-27; Two = 0b01
        assert_eq!((ctx.Dr7 >> 26) & 0b11, 0b01, "LEN2 should be 01 for Two");
    }

    #[cfg(windows)]
    #[test]
    fn dr7_dr3_field_positions_at_bits_28_to_31() {
        use windows::Win32::System::Diagnostics::Debug::CONTEXT;
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        dr7_enable_slot(
            &mut ctx,
            HwSlot::Dr3,
            HwBreakpointKind::Execute,
            HwBreakpointSize::One,
        );
        // L3 = bit 6
        assert_eq!(ctx.Dr7 & (1 << 6), 1 << 6);
        // RW3 at 28-29 = Execute (00); LEN3 at 30-31 = One (00).
        // So Dr7 should equal exactly (1 << 6).
        assert_eq!(ctx.Dr7, 1 << 6);
    }

    #[cfg(windows)]
    #[test]
    fn set_dr_address_writes_into_correct_register() {
        use windows::Win32::System::Diagnostics::Debug::CONTEXT;
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        set_dr_address(&mut ctx, HwSlot::Dr0, 0x1111);
        set_dr_address(&mut ctx, HwSlot::Dr1, 0x2222);
        set_dr_address(&mut ctx, HwSlot::Dr2, 0x3333);
        set_dr_address(&mut ctx, HwSlot::Dr3, 0x4444);
        assert_eq!(ctx.Dr0, 0x1111);
        assert_eq!(ctx.Dr1, 0x2222);
        assert_eq!(ctx.Dr2, 0x3333);
        assert_eq!(ctx.Dr3, 0x4444);
    }

    #[cfg(not(windows))]
    #[test]
    fn soft_bp_install_on_non_windows_returns_unsupported() {
        match SoftBreakpoint::install((), 0) {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn hw_bp_install_on_non_windows_returns_unsupported() {
        match HwBreakpoint::install(
            (),
            HwSlot::Dr0,
            0,
            HwBreakpointKind::Execute,
            HwBreakpointSize::One,
        ) {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }
}
