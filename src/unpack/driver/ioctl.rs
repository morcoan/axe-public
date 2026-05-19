//! IOCTL codes for Aurora ↔ driver communication.
//!
//! Standard Windows IOCTL packing: `CTL_CODE(DeviceType,
//! Function, Method, Access)`. Aurora reserves device type
//! `0x8001` and function codes 0x800..0x80F.

pub const AURORA_DEVICE_TYPE: u32 = 0x8001;
pub const METHOD_BUFFERED: u32 = 0;
pub const FILE_ANY_ACCESS: u32 = 0;

pub const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_PING: u32 = ctl_code(AURORA_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_REGISTER_TARGET_PID: u32 =
    ctl_code(AURORA_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_UNREGISTER_TARGET_PID: u32 =
    ctl_code(AURORA_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_ENABLE_HIDE_PROCESS: u32 =
    ctl_code(AURORA_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_ENABLE_HIDE_REGISTRY: u32 =
    ctl_code(AURORA_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_ENABLE_HIDE_DEVICES: u32 =
    ctl_code(AURORA_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctl_code_packs_fields_per_windows_convention() {
        // ping: device 0x8001, function 0x800, method 0, access 0
        let expected: u32 = (0x8001u32 << 16) | (0x800u32 << 2);
        assert_eq!(IOCTL_PING, expected);
    }

    #[test]
    fn distinct_ioctls_have_distinct_function_codes() {
        let codes = [
            IOCTL_PING,
            IOCTL_REGISTER_TARGET_PID,
            IOCTL_UNREGISTER_TARGET_PID,
            IOCTL_ENABLE_HIDE_PROCESS,
            IOCTL_ENABLE_HIDE_REGISTRY,
            IOCTL_ENABLE_HIDE_DEVICES,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "IOCTL codes must be unique");
    }
}
