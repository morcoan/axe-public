# `aurora_drv` — Aurora kernel driver

VM-artifact hiding at the syscall layer (process enumeration, registry reads, device opens). Opt-in via the axe-core `unpack-driver` feature.

## What's in this crate

`src/lib.rs` ships the **decision logic** as a `no_std`-ready Rust library — the pure functions that decide "is this process VM-tooling that should be hidden?", "is this registry read a VM indicator?", "is this device open a VM-only device?". These functions are exercised by the user-side tests in `src/unpack/hooks/spoof_*.rs` to keep both sides of the decision in sync.

This crate **does NOT produce a loadable `.sys` binary** as-is. Kernel drivers cannot be built by stock `cargo build` — they need either the EWDK or `windows-drivers-rs` plus a custom target spec.

## Building a real `.sys` binary

Two supported paths:

### Path 1: EWDK + C/C++ shim (recommended for production)

1. Install the [Enterprise WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/using-the-enterprise-wdk).
2. Set up a standard Windows driver project (KMDF or WDM).
3. Vendor `aurora_drv/src/lib.rs` as a logic-helper C++/Rust mixin OR translate the four decision functions (`should_hide_process`, `should_hide_registry`, `should_hide_device`, `ctl_code`) directly to C++ inside the driver's dispatch routine.
4. Implement `DriverEntry` + `DispatchDeviceControl` with the IOCTL codes from `IOCTL_FN_*` constants.
5. Sign with your EV cert (or test-signing key for analyst lab use).

### Path 2: `windows-drivers-rs` (experimental, Rust-only)

Microsoft's [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs) project enables pure Rust kernel drivers. As of this writing it requires:

- Nightly Rust toolchain
- `x86_64-pc-windows-msvc-kernel` target spec
- WDK headers installed
- A `wdk-build.toml` config

The path is viable but not production-ready. See the project's README for the latest workflow.

## Why test-signing or EV-signing is required

Windows refuses to load unsigned kernel drivers since Vista x64. Two ways to satisfy the kernel:

1. **Test-signing mode** (analyst lab only):
   ```cmd
   bcdedit /set testsigning on
   ```
   Requires reboot. A "Test Mode" watermark appears on the desktop.

2. **EV code-signing certificate** (production):
   - Sign the `.sys` with `signtool` using an EV cert from a Microsoft-trusted CA.
   - Submit to the Microsoft Hardware Dev Center for attestation signing (optional but recommended).

Aurora's user-side capability probe (`src/unpack/driver/test_signing.rs`) checks for either path and **never** suggests BYOVD ("Bring Your Own Vulnerable Driver" — exploiting a vulnerable third-party signed driver). BYOVD is a malware TTP (MITRE T1068, T1543.003), not an analysis technique.

## IOCTL contract

The user-side at `src/unpack/driver/ioctl.rs` and this crate share the same `ctl_code` packing function and `IOCTL_FN_*` constants. When extending either side, update both.

| Function code | Name                          | Semantics                                            |
| ------------- | ----------------------------- | ---------------------------------------------------- |
| `0x800`       | `IOCTL_FN_PING`               | Round-trip health check                              |
| `0x801`       | `IOCTL_FN_REGISTER_TARGET_PID`| Tell the driver which PID to apply hide-rules to     |
| `0x802`       | `IOCTL_FN_UNREGISTER_TARGET_PID` | Stop applying rules                                |
| `0x803`       | `IOCTL_FN_ENABLE_HIDE_PROCESS`| Enable VM-tool process hiding                         |
| `0x804`       | `IOCTL_FN_ENABLE_HIDE_REGISTRY`| Enable VM-key registry-read filtering                |
| `0x805`       | `IOCTL_FN_ENABLE_HIDE_DEVICES`| Enable VM-device open filtering                       |
