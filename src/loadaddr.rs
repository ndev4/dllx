//! Looks up the address a system DLL is actually mapped at this boot.
//!
//! The image is mapped with `LoadLibraryExW(.., DONT_RESOLVE_DLL_REFERENCES)`,
//! which, per the Win32 contract, does *not* call `DllMain`, does not run TLS
//! callbacks, and does not load the module's own dependencies. So none of the
//! mapped DLL's code runs; we only read the base address the loader assigns and
//! then unmap it. This is only ever called on trusted system DLLs under the
//! Windows directory. The file the user asked about is never loaded here.
//!
//! For a system DLL participating in system-wide ASLR (the default for OS
//! modules), the loader maps it at the same per-boot base in every process, so
//! the address read here matches where the DLL loads in a real run.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

type Hmodule = *mut c_void;
const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x0000_0001;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> Hmodule;
    fn LoadLibraryExW(name: *const u16, reserved: Hmodule, flags: u32) -> Hmodule;
    fn FreeLibrary(module: Hmodule) -> i32;
}

/// Returns the base address `path` is mapped at this boot, or `None` if it
/// could not be found. No code from the image is executed.
pub fn base_of(path: &Path) -> Option<u64> {
    // First ask the loader for a module already mapped in this process: this
    // reads the live base without mapping anything, and it also covers DLLs
    // like kernel32 that LoadLibraryEx refuses to re-map. The loader indexes
    // loaded modules by base name, so look it up by name.
    if let Some(name) = path.file_name() {
        if let Some(base) = get_module_base(name) {
            return Some(base);
        }
    }
    // Otherwise map the image to read its assigned base, then unmap it.
    map_base(path)
}

/// Base of a module already loaded in this process, looked up by name.
fn get_module_base(name: &std::ffi::OsStr) -> Option<u64> {
    let wide = wide(name);
    // SAFETY: `wide` is a valid null-terminated UTF-16 string. GetModuleHandleW
    // only reads the loader's module list; it maps nothing and runs no code,
    // and the handle it returns is borrowed (not reference-counted), so it must
    // not be freed.
    let handle = unsafe { GetModuleHandleW(wide.as_ptr()) };
    (!handle.is_null()).then_some(handle as u64)
}

/// Base a DLL maps to, obtained by mapping the image without running its code.
fn map_base(path: &Path) -> Option<u64> {
    let wide = wide(path.as_os_str());
    // SAFETY: `wide` is a valid null-terminated UTF-16 string that outlives the
    // call. DONT_RESOLVE_DLL_REFERENCES makes the call map the image only: no
    // DllMain, no TLS callbacks, no transitive loads, so no DLL code runs. The
    // returned handle is a plain module base (no low tag bits, unlike the
    // datafile/image-resource flags), which we free once we have read it.
    unsafe {
        let handle = LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), DONT_RESOLVE_DLL_REFERENCES);
        if handle.is_null() {
            return None;
        }
        let base = handle as u64;
        FreeLibrary(handle);
        Some(base)
    }
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    v.push(0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn maps_a_system_dll() {
        let root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let ntdll = root.join("System32").join("ntdll.dll");
        // ntdll is present on every Windows install and always relocatable.
        let base = base_of(&ntdll).expect("ntdll should map");
        assert_ne!(base, 0);
        // System images are mapped on 64 KiB allocation boundaries.
        assert_eq!(base % 0x1_0000, 0);
    }
}
