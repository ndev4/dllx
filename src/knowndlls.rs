//! The KnownDLLs list: DLLs the loader always takes from the system directory,
//! ignoring the application directory. Read from the registry, read-only.

use std::collections::HashSet;
use std::ffi::c_void;

type Hkey = *mut c_void;

// HKEY_LOCAL_MACHINE is (HKEY)(LONG)0x80000002, sign-extended on 64-bit.
const HKEY_LOCAL_MACHINE: isize = 0x8000_0002_u32 as i32 as isize;
const KEY_READ: u32 = 0x2_0019;
const KEY_WOW64_64KEY: u32 = 0x0100;
const REG_SZ: u32 = 1;
const ERROR_SUCCESS: i32 = 0;
const ERROR_NO_MORE_ITEMS: i32 = 259;
const MAX_VALUES: u32 = 1024;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(key: Hkey, subkey: *const u16, options: u32, sam: u32, result: *mut Hkey) -> i32;
    fn RegEnumValueW(
        key: Hkey,
        index: u32,
        name: *mut u16,
        name_len: *mut u32,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
}

/// Lowercased DLL names. Empty if the key cannot be read.
pub fn load() -> HashSet<String> {
    let mut names = HashSet::new();
    let subkey: Vec<u16> = r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
        .encode_utf16()
        .chain(Some(0))
        .collect();

    let mut key: Hkey = std::ptr::null_mut();
    // SAFETY: subkey is NUL-terminated and key is a valid out pointer.
    let status = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE as Hkey, subkey.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut key)
    };
    if status != ERROR_SUCCESS {
        return names;
    }

    for index in 0..MAX_VALUES {
        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut data = [0u16; 512];
        let mut data_len = (data.len() * 2) as u32;
        let mut kind = 0u32;
        // SAFETY: every buffer is valid for the length passed alongside it,
        // and the API writes at most that many units.
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut data_len,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        // Values that do not fit (ERROR_MORE_DATA) or are not strings are skipped;
        // the DllDirectory entries are REG_EXPAND_SZ, so they are skipped too.
        if status != ERROR_SUCCESS || kind != REG_SZ {
            continue;
        }
        let units = &data[..(data_len as usize / 2).min(data.len())];
        let value = String::from_utf16_lossy(units);
        let value = value.trim_end_matches('\0');
        if !value.is_empty() {
            names.insert(value.to_ascii_lowercase());
        }
    }

    // SAFETY: key was opened successfully above.
    unsafe { RegCloseKey(key) };
    names
}
