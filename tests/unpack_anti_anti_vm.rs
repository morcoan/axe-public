//! Group E integration — exercises hook + anti-debug spoof
//! decision tables in isolation.
//!
//! The full "fixture binary probes IsDebuggerPresent / VBoxGuest
//! / etc., succeeds under Aurora and fails without" smoke
//! requires the stub DLL artifact (Step 26 follow-up). For now
//! the tests cover the Aurora-side dispatch logic: every
//! spoof decision is correct + the SpoofProfile composes into
//! the manifest's hook list.

#![cfg(feature = "unpack")]

use axe_core::unpack::anti_debug::AntiDebugProfile;
use axe_core::unpack::hooks::{
    spoof_adapters, spoof_firmware, spoof_processes, spoof_registry, spoof_sysinfo, SpoofProfile,
};

#[test]
fn default_spoof_profile_lists_nine_user_mode_hooks() {
    let names = SpoofProfile::default().installed_surface_names();
    assert_eq!(names.len(), 9);
}

#[test]
fn default_anti_debug_profile_lists_six_surfaces() {
    let names = AntiDebugProfile::default().installed_surface_names();
    assert_eq!(names.len(), 6);
}

#[test]
fn firmware_spoof_zeros_rsmb() {
    assert_eq!(spoof_firmware::spoofed_return_value(0x52534D42), 0);
}

#[test]
fn registry_spoof_hides_disk_enum() {
    assert!(spoof_registry::should_spoof(
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
        "0"
    ));
}

#[test]
fn processes_spoof_hides_vmtoolsd_and_vboxservice() {
    assert!(spoof_processes::should_hide("vmtoolsd.exe"));
    assert!(spoof_processes::should_hide("VBoxService.exe"));
}

#[test]
fn adapters_spoof_rewrites_vmware_oui() {
    let mut mac = [0x00, 0x50, 0x56, 0xAA, 0xBB, 0xCC];
    let changed = spoof_adapters::rewrite_oui(&mut mac);
    assert!(changed);
    assert_ne!(&mac[0..3], &[0x00, 0x50, 0x56]);
}

#[test]
fn sysinfo_spoof_hides_vbox_guest_driver() {
    assert!(spoof_sysinfo::should_hide("VBoxGuest.sys"));
    assert!(spoof_sysinfo::should_hide(
        "\\SystemRoot\\System32\\drivers\\vmci.sys"
    ));
}

#[test]
fn disabled_spoof_profile_emits_no_hooks() {
    assert!(SpoofProfile::disabled()
        .installed_surface_names()
        .is_empty());
}

#[test]
fn disabled_anti_debug_profile_emits_no_surfaces() {
    assert!(AntiDebugProfile::disabled()
        .installed_surface_names()
        .is_empty());
}
