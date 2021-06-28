#![allow(non_snake_case)]
use winapi::shared::basetsd::{PSIZE_T, SIZE_T};
use winapi::shared::minwindef::{BOOL, DWORD, LPCVOID, LPVOID};
use winapi::um::winnt::{HANDLE, HEAP_INFORMATION_CLASS, PHANDLE, PVOID};
use winapi::um::heapapi::LPHEAP_SUMMARY;
use winapi::um::minwinbase::LPPROCESS_HEAP_ENTRY;

use crate::get_k32_fn;

pub fn HeapCreate() -> Option<unsafe fn(
    flOptions: DWORD,
    dwInitialSize: SIZE_T,
    dwMaximumSize: SIZE_T,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapCreate\0")) ) } )
}
pub fn HeapDestroy() -> Option<unsafe fn(
    hHeap: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapDestroy\0")) ) } )
}
pub fn HeapAlloc() -> Option<unsafe fn(
    hHeap: HANDLE,
    dwFlags: DWORD,
    dwBytes: SIZE_T,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapAlloc\0")) ) } )
}
pub fn HeapReAlloc() -> Option<unsafe fn(
    hHeap: HANDLE,
    dwFlags: DWORD,
    lpMem: LPVOID,
    dwBytes: SIZE_T,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapReAlloc\0")) ) } )
}
pub fn HeapFree() -> Option<unsafe fn(
    hHeap: HANDLE,
    dwFlags: DWORD,
    lpMem: LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapFree\0")) ) } )
}
pub fn HeapSize() -> Option<unsafe fn(
    hHeap: HANDLE,
    dwFlags: DWORD,
    lpMem: LPCVOID,
) -> SIZE_T> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapSize\0")) ) } )
}
pub fn GetProcessHeap() -> Option<unsafe fn() -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessHeap\0")) ) } )
}
pub fn HeapCompact() -> Option<unsafe fn(
    hHeap: HANDLE,
    dwFlags: DWORD,
) -> SIZE_T> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapCompact\0")) ) } )
}
pub fn HeapSetInformation() -> Option<unsafe fn(
    HeapHandle: HANDLE,
    HeapInformationClass: HEAP_INFORMATION_CLASS,
    HeapInformation: PVOID,
    HeapInformationLength: SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapSetInformation\0")) ) } )
}
pub fn HeapValidate() -> Option<unsafe fn(
    hHeap: HANDLE,
    dwFlags: DWORD,
    lpMem: LPCVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapValidate\0")) ) } )
}
pub fn HeapSummary() -> Option<unsafe fn(
    hHeap: HANDLE,
    dwFlags: DWORD,
    lpSummary: LPHEAP_SUMMARY,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapSummary\0")) ) } )
}
pub fn GetProcessHeaps() -> Option<unsafe fn(
    NumberOfHeaps: DWORD,
    ProcessHeaps: PHANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessHeaps\0")) ) } )
}
pub fn HeapLock() -> Option<unsafe fn(
    hHeap: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapLock\0")) ) } )
}
pub fn HeapUnlock() -> Option<unsafe fn(
    hHeap: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapUnlock\0")) ) } )
}
pub fn HeapWalk() -> Option<unsafe fn(
    hHeap: HANDLE,
    lpEntry: LPPROCESS_HEAP_ENTRY,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapWalk\0")) ) } )
}
pub fn HeapQueryInformation() -> Option<unsafe fn(
    HeapHandle: HANDLE,
    HeapInformationClass: HEAP_INFORMATION_CLASS,
    HeapInformation: PVOID,
    HeapInformationLength: SIZE_T,
    ReturnLength: PSIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("HeapQueryInformation\0")) ) } )
}
