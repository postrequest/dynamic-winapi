use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::{
    shared::minwindef::{FARPROC, HMODULE},
    um::libloaderapi::{GetProcAddress, LoadLibraryW},
};

pub mod um;

pub fn get_dll(dll_name: &str) -> HMODULE {
    let handle = unsafe { LoadLibraryW(get_wide(dll_name).as_ptr()) };
    if handle.is_null() {
        return 0 as _
    }
    handle
}

pub fn get_fn(dll: HMODULE, fn_name: &str) -> FARPROC {
    let func = unsafe { GetProcAddress(dll, fn_name.as_ptr() as _) };
    if func.is_null() {
        return 0 as _
    }
    func
}

pub fn get_k32_fn(fn_name: &str) -> FARPROC {
    let k32_handle = get_dll(obfstr::obfstr!("kernel32.dll"));
    get_fn(k32_handle, fn_name)
}

pub fn get_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}
