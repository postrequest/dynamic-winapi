#![allow(non_snake_case)]
use winapi::shared::minwindef::{BOOL, DWORD, HMODULE, LPDWORD, LPVOID, PDWORD};
use winapi::um::winnt::{HANDLE, LPSTR, LPWSTR, PVOID};
use winapi::um::psapi::{LPMODULEINFO, PPSAPI_WS_WATCH_INFORMATION, PPSAPI_WS_WATCH_INFORMATION_EX, PPERFORMANCE_INFORMATION, PENUM_PAGE_FILE_CALLBACKA, PENUM_PAGE_FILE_CALLBACKW, PPROCESS_MEMORY_COUNTERS};

use crate::get_k32_fn;

pub fn K32EnumProcesses() -> Option<unsafe fn(
    lpidProcess: *mut DWORD,
    cb: DWORD,
    lpcbNeeded: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32EnumProcesses\0")) ) } )
}
pub fn K32EnumProcessModules() -> Option<unsafe fn(
    hProcess: HANDLE,
    lphModule: *mut HMODULE,
    cb: DWORD,
    lpcbNeeded: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32EnumProcessModules\0")) ) } )
}
pub fn K32EnumProcessModulesEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lphModule: *mut HMODULE,
    cb: DWORD,
    lpcbNeeded: LPDWORD,
    dwFilterFlag: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32EnumProcessModulesEx\0")) ) } )
}
pub fn K32GetModuleBaseNameA() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpBaseName: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetModuleBaseNameA\0")) ) } )
}
pub fn K32GetModuleBaseNameW() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpBaseName: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetModuleBaseNameW\0")) ) } )
}
pub fn K32GetModuleFileNameExA() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpFilename: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetModuleFileNameExA\0")) ) } )
}
pub fn K32GetModuleFileNameExW() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpFilename: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetModuleFileNameExW\0")) ) } )
}
pub fn K32EmptyWorkingSet() -> Option<unsafe fn(
    hProcess: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32EmptyWorkingSet\0")) ) } )
}
pub fn K32QueryWorkingSet() -> Option<unsafe fn(
    hProcess: HANDLE,
    pv: PVOID,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32QueryWorkingSet\0")) ) } )
}
pub fn K32QueryWorkingSetEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    pv: PVOID,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32QueryWorkingSetEx\0")) ) } )
}
pub fn K32InitializeProcessForWsWatch() -> Option<unsafe fn(
    hProcess: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32InitializeProcessForWsWatch\0")) ) } )
}
pub fn K32GetWsChanges() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpWatchInfo: PPSAPI_WS_WATCH_INFORMATION,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetWsChanges\0")) ) } )
}
pub fn K32GetWsChangesEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpWatchInfoEx: PPSAPI_WS_WATCH_INFORMATION_EX,
    cb: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetWsChangesEx\0")) ) } )
}
pub fn K32GetMappedFileNameW() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpv: LPVOID,
    lpFilename: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetMappedFileNameW\0")) ) } )
}
pub fn K32GetMappedFileNameA() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpv: LPVOID,
    lpFilename: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetMappedFileNameA\0")) ) } )
}
pub fn K32EnumDeviceDrivers() -> Option<unsafe fn(
    lpImageBase: *mut LPVOID,
    cb: DWORD,
    lpcbNeeded: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32EnumDeviceDrivers\0")) ) } )
}
pub fn K32GetDeviceDriverBaseNameA() -> Option<unsafe fn(
    ImageBase: LPVOID,
    lpFilename: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetDeviceDriverBaseNameA\0")) ) } )
}
pub fn K32GetDeviceDriverBaseNameW() -> Option<unsafe fn(
    ImageBase: LPVOID,
    lpFilename: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetDeviceDriverBaseNameW\0")) ) } )
}
pub fn K32GetDeviceDriverFileNameA() -> Option<unsafe fn(
    ImageBase: LPVOID,
    lpFilename: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetDeviceDriverFileNameA\0")) ) } )
}
pub fn K32GetDeviceDriverFileNameW() -> Option<unsafe fn(
    ImageBase: LPVOID,
    lpFilename: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetDeviceDriverFileNameW\0")) ) } )
}
pub fn K32GetPerformanceInfo() -> Option<unsafe fn(
    pPerformanceInformation: PPERFORMANCE_INFORMATION,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetPerformanceInfo\0")) ) } )
}
pub fn K32EnumPageFilesW() -> Option<unsafe fn(
    pCallBackRoutine: PENUM_PAGE_FILE_CALLBACKW,
    pContext: LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32EnumPageFilesW\0")) ) } )
}
pub fn K32EnumPageFilesA() -> Option<unsafe fn(
    pCallBackRoutine: PENUM_PAGE_FILE_CALLBACKA,
    pContext: LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32EnumPageFilesA\0")) ) } )
}
pub fn K32GetProcessImageFileNameA() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpImageFileName: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetProcessImageFileNameA\0")) ) } )
}
pub fn K32GetProcessImageFileNameW() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpImageFileName: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetProcessImageFileNameW\0")) ) } )
}
pub fn EnumProcesses() -> Option<unsafe fn(
    lpidProcess: *mut DWORD,
    cb: DWORD,
    lpcbNeeded: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumProcesses\0")) ) } )
}
pub fn K32GetProcessMemoryInfo() -> Option<unsafe fn(
    Process: HANDLE,
    ppsmemCounters: PPROCESS_MEMORY_COUNTERS,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetProcessMemoryInfo\0")) ) } )
}
pub fn K32GetModuleInformation() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpmodinfo: LPMODULEINFO,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("K32GetModuleInformation\0")) ) } )
}
pub fn EmptyWorkingSet() -> Option<unsafe fn(
    hProcess: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EmptyWorkingSet\0")) ) } )
}
pub fn EnumDeviceDrivers() -> Option<unsafe fn(
    lpImageBase: *mut LPVOID,
    cb: DWORD,
    lpcbNeeded: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumDeviceDrivers\0")) ) } )
}
pub fn EnumPageFilesA() -> Option<unsafe fn(
    pCallBackRoutine: PENUM_PAGE_FILE_CALLBACKA,
    pContext: LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumPageFilesA\0")) ) } )
}
pub fn EnumPageFilesW() -> Option<unsafe fn(
    pCallBackRoutine: PENUM_PAGE_FILE_CALLBACKW,
    pContext: LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumPageFilesW\0")) ) } )
}
pub fn EnumProcessModules() -> Option<unsafe fn(
    hProcess: HANDLE,
    lphModule: *mut HMODULE,
    cb: DWORD,
    lpcbNeeded: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumProcessModules\0")) ) } )
}
pub fn EnumProcessModulesEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lphModule: *mut HMODULE,
    cb: DWORD,
    lpcbNeeded: LPDWORD,
    dwFilterFlag: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumProcessModulesEx\0")) ) } )
}
pub fn GetDeviceDriverBaseNameA() -> Option<unsafe fn(
    ImageBase: LPVOID,
    lpFilename: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetDeviceDriverBaseNameA\0")) ) } )
}
pub fn GetDeviceDriverBaseNameW() -> Option<unsafe fn(
    ImageBase: LPVOID,
    lpFilename: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetDeviceDriverBaseNameW\0")) ) } )
}
pub fn GetDeviceDriverFileNameA() -> Option<unsafe fn(
    ImageBase: LPVOID,
    lpFilename: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetDeviceDriverFileNameA\0")) ) } )
}
pub fn GetDeviceDriverFileNameW() -> Option<unsafe fn(
    ImageBase: LPVOID,
    lpFilename: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetDeviceDriverFileNameW\0")) ) } )
}
pub fn GetMappedFileNameA() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpv: LPVOID,
    lpFilename: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetMappedFileNameA\0")) ) } )
}
pub fn GetMappedFileNameW() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpv: LPVOID,
    lpFilename: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetMappedFileNameW\0")) ) } )
}
pub fn GetModuleBaseNameA() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpBaseName: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetModuleBaseNameA\0")) ) } )
}
pub fn GetModuleBaseNameW() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpBaseName: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetModuleBaseNameW\0")) ) } )
}
pub fn GetModuleFileNameExA() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpFilename: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetModuleFileNameExA\0")) ) } )
}
pub fn GetModuleFileNameExW() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpFilename: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetModuleFileNameExW\0")) ) } )
}
pub fn GetModuleInformation() -> Option<unsafe fn(
    hProcess: HANDLE,
    hModule: HMODULE,
    lpmodinfo: LPMODULEINFO,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetModuleInformation\0")) ) } )
}
pub fn GetPerformanceInfo() -> Option<unsafe fn(
    pPerformanceInformation: PPERFORMANCE_INFORMATION,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPerformanceInfo\0")) ) } )
}
pub fn GetProcessImageFileNameA() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpImageFileName: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessImageFileNameA\0")) ) } )
}
pub fn GetProcessImageFileNameW() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpImageFileName: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessImageFileNameW\0")) ) } )
}
pub fn GetProcessMemoryInfo() -> Option<unsafe fn(
    hProcess: HANDLE,
    ppsmemCounters: PPROCESS_MEMORY_COUNTERS,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessMemoryInfo\0")) ) } )
}
pub fn GetWsChanges() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpWatchInfo: PPSAPI_WS_WATCH_INFORMATION,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetWsChanges\0")) ) } )
}
pub fn GetWsChangesEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpWatchInfoEx: PPSAPI_WS_WATCH_INFORMATION_EX,
    cb: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetWsChangesEx\0")) ) } )
}
pub fn InitializeProcessForWsWatch() -> Option<unsafe fn(
    hProcess: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("InitializeProcessForWsWatch\0")) ) } )
}
pub fn QueryWorkingSet() -> Option<unsafe fn(
    hProcess: HANDLE,
    pv: PVOID,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryWorkingSet\0")) ) } )
}
pub fn QueryWorkingSetEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    pv: PVOID,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryWorkingSetEx\0")) ) } )
}
