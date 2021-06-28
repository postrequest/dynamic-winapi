#![allow(non_snake_case)]
use winapi::shared::minwindef::{BOOL, DWORD, LPDWORD, LPHANDLE};
use winapi::um::winnt::HANDLE;

use crate::get_k32_fn;

pub fn CloseHandle() -> Option<unsafe fn(
    hObject: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CloseHandle\0")) ) } )
}
pub fn DuplicateHandle() -> Option<unsafe fn(
    hSourceProcessHandle: HANDLE,
    hSourceHandle: HANDLE,
    hTargetProcessHandle: HANDLE,
    lpTargetHandle: LPHANDLE,
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwOptions: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DuplicateHandle\0")) ) } )
}
pub fn CompareObjectHandles() -> Option<unsafe fn(
    hFirstObjectHandle: HANDLE,
    hSecondObjectHandle: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CompareObjectHandles\0")) ) } )
}
pub fn GetHandleInformation() -> Option<unsafe fn(
    hObject: HANDLE,
    lpdwFlags: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetHandleInformation\0")) ) } )
}
pub fn SetHandleInformation() -> Option<unsafe fn(
    hObject: HANDLE,
    dwMask: DWORD,
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetHandleInformation\0")) ) } )
}
