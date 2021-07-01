#![allow(non_snake_case)]
use winapi::ctypes::{c_int, c_long};
use winapi::shared::basetsd::{
    DWORD64, DWORD_PTR, LONG_PTR, PDWORD64, PDWORD_PTR, PSIZE_T, PULONG_PTR, SIZE_T, UINT_PTR,
    ULONG_PTR,
};
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::{
    ATOM, BOOL, DWORD, FARPROC, FILETIME, HFILE, HGLOBAL, HLOCAL, HMODULE, HRSRC, LPBOOL,
    LPBYTE, LPCVOID, LPDWORD, LPFILETIME, LPVOID, LPWORD, PBOOL, PDWORD, PUCHAR, PULONG, PUSHORT,
    UCHAR, UINT, ULONG, USHORT, WORD,
};
use winapi::shared::windef::HWND;
use winapi::um::fileapi::STREAM_INFO_LEVELS;
use winapi::um::libloaderapi::{
    ENUMRESLANGPROCA, ENUMRESLANGPROCW, ENUMRESNAMEPROCA, ENUMRESTYPEPROCA, ENUMRESTYPEPROCW,
};
use winapi::um::minwinbase::{
    FILE_INFO_BY_HANDLE_CLASS, FINDEX_INFO_LEVELS, FINDEX_SEARCH_OPS, GET_FILEEX_INFO_LEVELS,
    LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE, LPSECURITY_ATTRIBUTES, PREASON_CONTEXT,
};
use winapi::um::processthreadsapi::{
    LPPROCESS_INFORMATION, LPSTARTUPINFOA, LPSTARTUPINFOW,
};
use winapi::um::winnt::{
    BOOLEAN, DWORDLONG, EXECUTION_STATE, HANDLE, HRESULT, INT, 
    LATENCY_TIME, LONG, LPCCH, LPCH, LPCSTR, LPCWSTR, LPOSVERSIONINFOEXA,
    LPOSVERSIONINFOEXW, LPSTR, LPWSTR, PBOOLEAN, PCONTEXT, PCWSTR, PFIRMWARE_TYPE,
    PHANDLE, PIO_COUNTERS, PJOB_SET_ARRAY, PLUID, POWER_REQUEST_TYPE, PPERFORMANCE_DATA,
    PPROCESSOR_NUMBER, PQUOTA_LIMITS, 
    PSECURE_MEMORY_CACHE_CALLBACK, PSID, PSID_NAME_USE, PULONGLONG, PVOID, PWOW64_CONTEXT,
    PWOW64_LDT_ENTRY, PWSTR, VOID, WAITORTIMERCALLBACK, WOW64_CONTEXT,
};
use winapi::vc::vadefs::va_list;
use winapi::um::winbase::{
    APPLICATION_RECOVERY_CALLBACK, COPYFILE2_EXTENDED_PARAMETERS, DEP_SYSTEM_POLICY_TYPE, 
    LPCOMMCONFIG, LPCOMMTIMEOUTS, LPFILE_ID_DESCRIPTOR, LPLDT_ENTRY, LPHW_PROFILE_INFOA, 
    LPHW_PROFILE_INFOW, LPMEMORYSTATUS, LPDCB, LPFIBER_START_ROUTINE, LPOFSTRUCT, 
    LPPROGRESS_ROUTINE, LPSYSTEM_POWER_STATUS, PCACTCTXA, PCACTCTXW, PACTCTX_SECTION_KEYED_DATA, 
    PUMS_COMPLETION_LIST, PUMS_SCHEDULER_STARTUP_INFO, PUMS_SYSTEM_THREAD_INFORMATION, PUMS_CONTEXT, 
    UMS_THREAD_INFO_CLASS,
};

use crate::{get_advapi32_fn, get_k32_fn};

pub fn GlobalAlloc() -> Option<unsafe fn(
    uFlags: UINT,
    dwBytes: SIZE_T,
) -> HGLOBAL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalAlloc\0")) ) } )
}
pub fn GlobalReAlloc() -> Option<unsafe fn(
    hMem: HGLOBAL,
    dwBytes: SIZE_T,
    uFlags: UINT,
) -> HGLOBAL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalReAlloc\0")) ) } )
}
pub fn GlobalSize() -> Option<unsafe fn(
    hMem: HGLOBAL,
) -> SIZE_T> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalSize\0")) ) } )
}
pub fn GlobalFlags() -> Option<unsafe fn(
    hMem: HGLOBAL,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalFlags\0")) ) } )
}
pub fn GlobalLock() -> Option<unsafe fn(
    hMem: HGLOBAL,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalLock\0")) ) } )
}
pub fn GlobalHandle() -> Option<unsafe fn(
    pMem: LPCVOID,
) -> HGLOBAL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalHandle\0")) ) } )
}
pub fn GlobalUnlock() -> Option<unsafe fn(
    hMem: HGLOBAL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalUnlock\0")) ) } )
}
pub fn GlobalFree() -> Option<unsafe fn(
    hMem: HGLOBAL,
) -> HGLOBAL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalFree\0")) ) } )
}
pub fn GlobalCompact() -> Option<unsafe fn(
    dwMinFree: DWORD,
) -> SIZE_T> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalCompact\0")) ) } )
}
pub fn GlobalFix() -> Option<unsafe fn(
    hMem: HGLOBAL,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalFix\0")) ) } )
}
pub fn GlobalUnfix() -> Option<unsafe fn(
    hMem: HGLOBAL,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalUnfix\0")) ) } )
}
pub fn GlobalWire() -> Option<unsafe fn(
    hMem: HGLOBAL,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalWire\0")) ) } )
}
pub fn GlobalUnWire() -> Option<unsafe fn(
    hMem: HGLOBAL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalUnWire\0")) ) } )
}
pub fn GlobalMemoryStatus() -> Option<unsafe fn(
    lpBuffer: LPMEMORYSTATUS,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalMemoryStatus\0")) ) } )
}
pub fn LocalAlloc() -> Option<unsafe fn(
    uFlags: UINT,
    uBytes: SIZE_T,
) -> HLOCAL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalAlloc\0")) ) } )
}
pub fn LocalReAlloc() -> Option<unsafe fn(
    hMem: HLOCAL,
    uBytes: SIZE_T,
    uFlags: UINT,
) -> HLOCAL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalReAlloc\0")) ) } )
}
pub fn LocalLock() -> Option<unsafe fn(
    hMem: HLOCAL,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalLock\0")) ) } )
}
pub fn LocalHandle() -> Option<unsafe fn(
    pMem: LPCVOID,
) -> HLOCAL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalHandle\0")) ) } )
}
pub fn LocalUnlock() -> Option<unsafe fn(
    hMem: HLOCAL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalUnlock\0")) ) } )
}
pub fn LocalSize() -> Option<unsafe fn(
    hMem: HLOCAL,
) -> SIZE_T> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalSize\0")) ) } )
}
pub fn LocalFlags() -> Option<unsafe fn(
    hMem: HLOCAL,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalFlags\0")) ) } )
}
pub fn LocalFree() -> Option<unsafe fn(
    hMem: HLOCAL,
) -> HLOCAL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalFree\0")) ) } )
}
pub fn LocalShrink() -> Option<unsafe fn(
    hMem: HLOCAL,
    cbNewSize: UINT,
) -> SIZE_T> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalShrink\0")) ) } )
}
pub fn LocalCompact() -> Option<unsafe fn(
    uMinFree: UINT,
) -> SIZE_T> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocalCompact\0")) ) } )
}
pub fn GetBinaryTypeA() -> Option<unsafe fn(
    lpApplicationName: LPCSTR,
    lpBinaryType: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetBinaryTypeA\0")) ) } )
}
pub fn GetBinaryTypeW() -> Option<unsafe fn(
    lpApplicationName: LPCWSTR,
    lpBinaryType: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetBinaryTypeW\0")) ) } )
}
pub fn GetShortPathNameA() -> Option<unsafe fn(
    lpszLongPath: LPCSTR,
    lpszShortPath: LPSTR,
    cchBuffer: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetShortPathNameA\0")) ) } )
}
pub fn GetLongPathNameTransactedA() -> Option<unsafe fn(
    lpszShortPath: LPCSTR,
    lpszLongPath: LPSTR,
    cchBuffer: DWORD,
    hTransaction: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetLongPathNameTransactedA\0")) ) } )
}
pub fn GetLongPathNameTransactedW() -> Option<unsafe fn(
    lpszShortPath: LPCWSTR,
    lpszLongPath: LPWSTR,
    cchBuffer: DWORD,
    hTransaction: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetLongPathNameTransactedW\0")) ) } )
}
pub fn GetProcessAffinityMask() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpProcessAffinityMask: PDWORD_PTR,
    lpSystemAffinityMask: PDWORD_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessAffinityMask\0")) ) } )
}
pub fn SetProcessAffinityMask() -> Option<unsafe fn(
    hProcess: HANDLE,
    dwProcessAffinityMask: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessAffinityMask\0")) ) } )
}
pub fn GetProcessIoCounters() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpIoCounters: PIO_COUNTERS,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessIoCounters\0")) ) } )
}
pub fn GetProcessWorkingSetSize() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpMinimumWorkingSetSize: PSIZE_T,
    lpMaximumWorkingSetSize: PSIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessWorkingSetSize\0")) ) } )
}
pub fn SetProcessWorkingSetSize() -> Option<unsafe fn(
    hProcess: HANDLE,
    dwMinimumWorkingSetSize: SIZE_T,
    dwMaximumWorkingSetSize: SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessWorkingSetSize\0")) ) } )
}
pub fn FatalExit() -> Option<unsafe fn(
    ExitCode: c_int,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FatalExit\0")) ) } )
}
pub fn SetEnvironmentStringsA() -> Option<unsafe fn(
    NewEnvironment: LPCH,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetEnvironmentStringsA\0")) ) } )
}
pub fn SwitchToFiber() -> Option<unsafe fn(
    lpFiber: LPVOID,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SwitchToFiber\0")) ) } )
}
pub fn DeleteFiber() -> Option<unsafe fn(
    lpFiber: LPVOID,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteFiber\0")) ) } )
}
pub fn ConvertFiberToThread() -> Option<unsafe fn() -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ConvertFiberToThread\0")) ) } )
}
pub fn CreateFiberEx() -> Option<unsafe fn(
    dwStackCommitSize: SIZE_T,
    dwStackReserveSize: SIZE_T,
    dwFlags: DWORD,
    lpStartAddress: LPFIBER_START_ROUTINE,
    lpParameter: LPVOID,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateFiberEx\0")) ) } )
}
pub fn ConvertThreadToFiberEx() -> Option<unsafe fn(
    lpParameter: LPVOID,
    dwFlags: DWORD,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ConvertThreadToFiberEx\0")) ) } )
}
pub fn CreateFiber() -> Option<unsafe fn(
    dwStackSize: SIZE_T,
    lpStartAddress: LPFIBER_START_ROUTINE,
    lpParameter: LPVOID,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateFiber\0")) ) } )
}
pub fn ConvertThreadToFiber() -> Option<unsafe fn(
    lpParameter: LPVOID,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ConvertThreadToFiber\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn CreateUmsCompletionList() -> Option<unsafe fn(
    UmsCompletionList: *mut PUMS_COMPLETION_LIST,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateUmsCompletionList\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn DequeueUmsCompletionListItems() -> Option<unsafe fn(
    UmsCompletionList: PUMS_COMPLETION_LIST,
    WaitTimeOut: DWORD,
    UmsThreadList: *mut PUMS_CONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DequeueUmsCompletionListItems\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn GetUmsCompletionListEvent() -> Option<unsafe fn(
    UmsCompletionList: PUMS_COMPLETION_LIST,
    UmsCompletionEvent: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetUmsCompletionListEvent\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn ExecuteUmsThread() -> Option<unsafe fn(
    UmsThread: PUMS_CONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ExecuteUmsThread\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn UmsThreadYield() -> Option<unsafe fn(
    SchedulerParam: PVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UmsThreadYield\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn DeleteUmsCompletionList() -> Option<unsafe fn(
    UmsCompletionList: PUMS_COMPLETION_LIST,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteUmsCompletionList\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn GetCurrentUmsThread() -> Option<unsafe fn() -> PUMS_CONTEXT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentUmsThread\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn GetNextUmsListItem() -> Option<unsafe fn(
    UmsContext: PUMS_CONTEXT,
) -> PUMS_CONTEXT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNextUmsListItem\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn QueryUmsThreadInformation() -> Option<unsafe fn(
    UmsThread: PUMS_CONTEXT,
    UmsThreadInfoClass: UMS_THREAD_INFO_CLASS,
    UmsThreadInformation: PVOID,
    UmsThreadInformationLength: ULONG,
    ReturnLength: PULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryUmsThreadInformation\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn SetUmsThreadInformation() -> Option<unsafe fn(
    UmsThread: PUMS_CONTEXT,
    UmsThreadInfoClass: UMS_THREAD_INFO_CLASS,
    UmsThreadInformation: PVOID,
    UmsThreadInformationLength: ULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetUmsThreadInformation\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn DeleteUmsThreadContext() -> Option<unsafe fn(
    UmsThread: PUMS_CONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteUmsThreadContext\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn CreateUmsThreadContext() -> Option<unsafe fn(
    lpUmsThread: *mut PUMS_CONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateUmsThreadContext\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn EnterUmsSchedulingMode() -> Option<unsafe fn(
    SchedulerStartupInfo: PUMS_SCHEDULER_STARTUP_INFO,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnterUmsSchedulingMode\0")) ) } )
}
#[cfg(target_pointer_width = "64")]
pub fn GetUmsSystemThreadInformation() -> Option<unsafe fn(
    ThreadHandle: HANDLE,
    SystemThreadInfo: PUMS_SYSTEM_THREAD_INFORMATION,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetUmsSystemThreadInformation\0")) ) } )
}
pub fn SetThreadAffinityMask() -> Option<unsafe fn(
    hThread: HANDLE,
    dwThreadAffinityMask: DWORD_PTR,
) -> DWORD_PTR> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadAffinityMask\0")) ) } )
}
pub fn SetProcessDEPPolicy() -> Option<unsafe fn(
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessDEPPolicy\0")) ) } )
}
pub fn GetProcessDEPPolicy() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpFlags: LPDWORD,
    lpPermanent: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessDEPPolicy\0")) ) } )
}
pub fn RequestWakeupLatency() -> Option<unsafe fn(
    latency: LATENCY_TIME,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RequestWakeupLatency\0")) ) } )
}
pub fn IsSystemResumeAutomatic() -> Option<unsafe fn() -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsSystemResumeAutomatic\0")) ) } )
}
pub fn GetThreadSelectorEntry() -> Option<unsafe fn(
    hThread: HANDLE,
    dwSelector: DWORD,
    lpSelectorEntry: LPLDT_ENTRY,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadSelectorEntry\0")) ) } )
}
pub fn SetThreadExecutionState() -> Option<unsafe fn(
    esFlags: EXECUTION_STATE,
) -> EXECUTION_STATE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadExecutionState\0")) ) } )
}
pub fn PowerCreateRequest() -> Option<unsafe fn(
    Context: PREASON_CONTEXT,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("PowerCreateRequest\0")) ) } )
}
pub fn PowerSetRequest() -> Option<unsafe fn(
    PowerRequest: HANDLE,
    RequestType: POWER_REQUEST_TYPE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("PowerSetRequest\0")) ) } )
}
pub fn PowerClearRequest() -> Option<unsafe fn(
    PowerRequest: HANDLE,
    RequestType: POWER_REQUEST_TYPE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("PowerClearRequest\0")) ) } )
}
pub fn RestoreLastError() -> Option<unsafe fn(
    dwErrCode: DWORD,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RestoreLastError\0")) ) } )
}
pub fn SetFileCompletionNotificationModes() -> Option<unsafe fn(
    FileHandle: HANDLE,
    Flags: UCHAR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFileCompletionNotificationModes\0")) ) } )
}
pub fn Wow64GetThreadContext() -> Option<unsafe fn(
    hThread: HANDLE,
    lpContext: PWOW64_CONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("Wow64GetThreadContext\0")) ) } )
}
pub fn Wow64SetThreadContext() -> Option<unsafe fn(
    hThread: HANDLE,
    lpContext: *const WOW64_CONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("Wow64SetThreadContext\0")) ) } )
}
pub fn Wow64GetThreadSelectorEntry() -> Option<unsafe fn(
    hThread: HANDLE,
    dwSelector: DWORD,
    lpSelectorEntry: PWOW64_LDT_ENTRY,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("Wow64GetThreadSelectorEntry\0")) ) } )
}
pub fn Wow64SuspendThread() -> Option<unsafe fn(
    hThread: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("Wow64SuspendThread\0")) ) } )
}
pub fn DebugSetProcessKillOnExit() -> Option<unsafe fn(
    KillOnExit: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DebugSetProcessKillOnExit\0")) ) } )
}
pub fn DebugBreakProcess() -> Option<unsafe fn(
    Process: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DebugBreakProcess\0")) ) } )
}
pub fn PulseEvent() -> Option<unsafe fn(
    hEvent: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("PulseEvent\0")) ) } )
}
pub fn GlobalDeleteAtom() -> Option<unsafe fn(
    nAtom: ATOM,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalDeleteAtom\0")) ) } )
}
pub fn InitAtomTable() -> Option<unsafe fn(
    nSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("InitAtomTable\0")) ) } )
}
pub fn DeleteAtom() -> Option<unsafe fn(
    nAtom: ATOM,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteAtom\0")) ) } )
}
pub fn SetHandleCount() -> Option<unsafe fn(
    uNumber: UINT,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetHandleCount\0")) ) } )
}
pub fn RequestDeviceWakeup() -> Option<unsafe fn(
    hDevice: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RequestDeviceWakeup\0")) ) } )
}
pub fn CancelDeviceWakeupRequest() -> Option<unsafe fn(
    hDevice: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CancelDeviceWakeupRequest\0")) ) } )
}
pub fn GetDevicePowerState() -> Option<unsafe fn(
    hDevice: HANDLE,
    pfOn: *mut BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetDevicePowerState\0")) ) } )
}
pub fn SetMessageWaitingIndicator() -> Option<unsafe fn(
    hMsgIndicator: HANDLE,
    ulMsgCount: ULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetMessageWaitingIndicator\0")) ) } )
}
pub fn SetFileShortNameA() -> Option<unsafe fn(
    hFile: HANDLE,
    lpShortName: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFileShortNameA\0")) ) } )
}
pub fn SetFileShortNameW() -> Option<unsafe fn(
    hFile: HANDLE,
    lpShortName: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFileShortNameW\0")) ) } )
}
pub fn LoadModule() -> Option<unsafe fn(
    lpModuleName: LPCSTR,
    lpParameterBlock: LPVOID,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LoadModule\0")) ) } )
}
pub fn WinExec() -> Option<unsafe fn(
    lpCmdLine: LPCSTR,
    uCmdShow: UINT,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WinExec\0")) ) } )
}
pub fn SetTapePosition() -> Option<unsafe fn(
    hDevice: HANDLE,
    dwPositionMethod: DWORD,
    dwPartition: DWORD,
    dwOffsetLow: DWORD,
    dwOffsetHigh: DWORD,
    bImmediate: BOOL,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetTapePosition\0")) ) } )
}
pub fn GetTapePosition() -> Option<unsafe fn(
    hDevice: HANDLE,
    dwPositionType: DWORD,
    lpdwPartition: LPDWORD,
    lpdwOffsetLow: LPDWORD,
    lpdwOffsetHigh: LPDWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetTapePosition\0")) ) } )
}
pub fn PrepareTape() -> Option<unsafe fn(
    hDevice: HANDLE,
    dwOperation: DWORD,
    bImmediate: BOOL,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("PrepareTape\0")) ) } )
}
pub fn EraseTape() -> Option<unsafe fn(
    hDevice: HANDLE,
    dwEraseType: DWORD,
    bImmediate: BOOL,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EraseTape\0")) ) } )
}
pub fn CreateTapePartition() -> Option<unsafe fn(
    hDevice: HANDLE,
    dwPartitionMethod: DWORD,
    dwCount: DWORD,
    dwSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateTapePartition\0")) ) } )
}
pub fn WriteTapemark() -> Option<unsafe fn(
    hDevice: HANDLE,
    dwTapemarkType: DWORD,
    dwTapemarkCount: DWORD,
    bImmediate: BOOL,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WriteTapemark\0")) ) } )
}
pub fn GetTapeStatus() -> Option<unsafe fn(
    hDevice: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetTapeStatus\0")) ) } )
}
pub fn GetTapeParameters() -> Option<unsafe fn(
    hDevice: HANDLE,
    dwOperation: DWORD,
    lpdwSize: LPDWORD,
    lpTapeInformation: LPVOID,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetTapeParameters\0")) ) } )
}
pub fn SetTapeParameters() -> Option<unsafe fn(
    hDevice: HANDLE,
    dwOperation: DWORD,
    lpTapeInformation: LPVOID,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetTapeParameters\0")) ) } )
}
pub fn MulDiv() -> Option<unsafe fn(
    nNumber: c_int,
    nNumerator: c_int,
    nDenominator: c_int,
) -> c_int> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MulDiv\0")) ) } )
}
pub fn GetSystemDEPPolicy() -> Option<unsafe fn() -> DEP_SYSTEM_POLICY_TYPE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSystemDEPPolicy\0")) ) } )
}
pub fn GetSystemRegistryQuota() -> Option<unsafe fn(
    pdwQuotaAllowed: PDWORD,
    pdwQuotaUsed: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSystemRegistryQuota\0")) ) } )
}
pub fn FileTimeToDosDateTime() -> Option<unsafe fn(
    lpFileTime: *const FILETIME,
    lpFatDate: LPWORD,
    lpFatTime: LPWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FileTimeToDosDateTime\0")) ) } )
}
pub fn DosDateTimeToFileTime() -> Option<unsafe fn(
    wFatDate: WORD,
    wFatTime: WORD,
    lpFileTime: LPFILETIME,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DosDateTimeToFileTime\0")) ) } )
}
pub fn FormatMessageA() -> Option<unsafe fn(
    dwFlags: DWORD,
    lpSource: LPCVOID,
    dwMessageId: DWORD,
    dwLanguageId: DWORD,
    lpBuffer: LPSTR,
    nSize: DWORD,
    Arguments: *mut va_list,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FormatMessageA\0")) ) } )
}
pub fn FormatMessageW() -> Option<unsafe fn(
    dwFlags: DWORD,
    lpSource: LPCVOID,
    dwMessageId: DWORD,
    dwLanguageId: DWORD,
    lpBuffer: LPWSTR,
    nSize: DWORD,
    Arguments: *mut va_list,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FormatMessageW\0")) ) } )
}
pub fn CreateMailslotA() -> Option<unsafe fn(
    lpName: LPCSTR,
    nMaxMessageSize: DWORD,
    lReadTimeout: DWORD,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateMailslotA\0")) ) } )
}
pub fn CreateMailslotW() -> Option<unsafe fn(
    lpName: LPCWSTR,
    nMaxMessageSize: DWORD,
    lReadTimeout: DWORD,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateMailslotW\0")) ) } )
}
pub fn GetMailslotInfo() -> Option<unsafe fn(
    hMailslot: HANDLE,
    lpMaxMessageSize: LPDWORD,
    lpNextSize: LPDWORD,
    lpMessageCount: LPDWORD,
    lpReadTimeout: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetMailslotInfo\0")) ) } )
}
pub fn SetMailslotInfo() -> Option<unsafe fn(
    hMailslot: HANDLE,
    lReadTimeout: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetMailslotInfo\0")) ) } )
}
pub fn lstrcmpA() -> Option<unsafe fn(
    lpString1: LPCSTR,
    lpString2: LPCSTR,
) -> c_int> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcmpA\0")) ) } )
}
pub fn lstrcmpW() -> Option<unsafe fn(
    lpString1: LPCWSTR,
    lpString2: LPCWSTR,
) -> c_int> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcmpW\0")) ) } )
}
pub fn lstrcmpiA() -> Option<unsafe fn(
    lpString1: LPCSTR,
    lpString2: LPCSTR,
) -> c_int> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcmpiA\0")) ) } )
}
pub fn lstrcmpiW() -> Option<unsafe fn(
    lpString1: LPCWSTR,
    lpString2: LPCWSTR,
) -> c_int> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcmpiW\0")) ) } )
}
pub fn lstrcpynA() -> Option<unsafe fn(
    lpString1: LPSTR,
    lpString2: LPCSTR,
    iMaxLength: c_int,
) -> LPSTR> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcpynA\0")) ) } )
}
pub fn lstrcpynW() -> Option<unsafe fn(
    lpString1: LPWSTR,
    lpString2: LPCWSTR,
    iMaxLength: c_int,
) -> LPWSTR> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcpynW\0")) ) } )
}
pub fn lstrcpyA() -> Option<unsafe fn(
    lpString1: LPSTR,
    lpString2: LPCSTR,
) -> LPSTR> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcpyA\0")) ) } )
}
pub fn lstrcpyW() -> Option<unsafe fn(
    lpString1: LPWSTR,
    lpString2: LPCWSTR,
) -> LPWSTR> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcpyW\0")) ) } )
}
pub fn lstrcatA() -> Option<unsafe fn(
    lpString1: LPSTR,
    lpString2: LPCSTR,
) -> LPSTR> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcatA\0")) ) } )
}
pub fn lstrcatW() -> Option<unsafe fn(
    lpString1: LPWSTR,
    lpString2: LPCWSTR,
) -> LPWSTR> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrcatW\0")) ) } )
}
pub fn lstrlenA() -> Option<unsafe fn(
    lpString: LPCSTR,
) -> c_int> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrlenA\0")) ) } )
}
pub fn lstrlenW() -> Option<unsafe fn(
    lpString: LPCWSTR,
) -> c_int> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("lstrlenW\0")) ) } )
}
pub fn OpenFile() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    lpReOpenBuff: LPOFSTRUCT,
    uStyle: UINT,
) -> HFILE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenFile\0")) ) } )
}
pub fn _lopen() -> Option<unsafe fn(
    lpPathName: LPCSTR,
    iReadWrite: c_int,
) -> HFILE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("_lopen\0")) ) } )
}
pub fn _lcreat() -> Option<unsafe fn(
    lpPathName: LPCSTR,
    iAttrubute: c_int,
) -> HFILE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("_lcreat\0")) ) } )
}
pub fn _lread() -> Option<unsafe fn(
    hFile: HFILE,
    lpBuffer: LPVOID,
    uBytes: UINT,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("_lread\0")) ) } )
}
pub fn _lwrite() -> Option<unsafe fn(
    hFile: HFILE,
    lpBuffer: LPCCH,
    uBytes: UINT,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("_lwrite\0")) ) } )
}
pub fn _hread() -> Option<unsafe fn(
    hFile: HFILE,
    lpBuffer: LPVOID,
    lBytes: c_long,
) -> c_long> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("_hread\0")) ) } )
}
pub fn _hwrite() -> Option<unsafe fn(
    hFile: HFILE,
    lpBuffer: LPCCH,
    lBytes: c_long,
) -> c_long> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("_hwrite\0")) ) } )
}
pub fn _lclose() -> Option<unsafe fn(
    hFile: HFILE,
) -> HFILE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("_lclose\0")) ) } )
}
pub fn _llseek() -> Option<unsafe fn(
    hFile: HFILE,
    lOffset: LONG,
    iOrigin: c_int,
) -> LONG> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("_llseek\0")) ) } )
}
pub fn BackupRead() -> Option<unsafe fn(
    hFile: HANDLE,
    lpBuffer: LPBYTE,
    nNumberOfBytesToRead: DWORD,
    lpNumberOfBytesRead: LPDWORD,
    bAbort: BOOL,
    bProcessSecurity: BOOL,
    lpContext: *mut LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BackupRead\0")) ) } )
}
pub fn BackupSeek() -> Option<unsafe fn(
    hFile: HANDLE,
    dwLowBytesToSeek: DWORD,
    dwHighBytesToSeek: DWORD,
    lpdwLowByteSeeked: LPDWORD,
    lpdwHighByteSeeked: LPDWORD,
    lpContext: *mut LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BackupSeek\0")) ) } )
}
pub fn BackupWrite() -> Option<unsafe fn(
    hFile: HANDLE,
    lpBuffer: LPBYTE,
    nNumberOfBytesToWrite: DWORD,
    lpNumberOfBytesWritten: LPDWORD,
    bAbort: BOOL,
    bProcessSecurity: BOOL,
    lpContext: *mut LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BackupWrite\0")) ) } )
}
pub fn OpenMutexA() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    lpName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenMutexA\0")) ) } )
}
pub fn CreateSemaphoreA() -> Option<unsafe fn(
    lpSemaphoreAttributes: LPSECURITY_ATTRIBUTES,
    lInitialCount: LONG,
    lMaximumCount: LONG,
    lpName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateSemaphoreA\0")) ) } )
}
pub fn OpenSemaphoreA() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    lpName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenSemaphoreA\0")) ) } )
}
pub fn CreateWaitableTimerA() -> Option<unsafe fn(
    lpTimerAttributes: LPSECURITY_ATTRIBUTES,
    bManualReset: BOOL,
    lpTimerName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateWaitableTimerA\0")) ) } )
}
pub fn OpenWaitableTimerA() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    lpTimerName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenWaitableTimerA\0")) ) } )
}
pub fn CreateSemaphoreExA() -> Option<unsafe fn(
    lpSemaphoreAttributes: LPSECURITY_ATTRIBUTES,
    lInitialCount: LONG,
    lMaximumCount: LONG,
    lpName: LPCSTR,
    dwFlags: DWORD,
    dwDesiredAccess: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateSemaphoreExA\0")) ) } )
}
pub fn CreateWaitableTimerExA() -> Option<unsafe fn(
    lpTimerAttributes: LPSECURITY_ATTRIBUTES,
    lpTimerName: LPCSTR,
    dwFlags: DWORD,
    dwDesiredAccess: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateWaitableTimerExA\0")) ) } )
}
pub fn CreateFileMappingA() -> Option<unsafe fn(
    hFile: HANDLE,
    lpAttributes: LPSECURITY_ATTRIBUTES,
    flProtect: DWORD,
    dwMaximumSizeHigh: DWORD,
    dwMaximumSizeLow: DWORD,
    lpName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateFileMappingA\0")) ) } )
}
pub fn CreateFileMappingNumaA() -> Option<unsafe fn(
    hFile: HANDLE,
    lpFileMappingAttributes: LPSECURITY_ATTRIBUTES,
    flProtect: DWORD,
    dwMaximumSizeHigh: DWORD,
    dwMaximumSizeLow: DWORD,
    lpName: LPCSTR,
    nndPreferred: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateFileMappingNumaA\0")) ) } )
}
pub fn OpenFileMappingA() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    lpName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenFileMappingA\0")) ) } )
}
pub fn GetLogicalDriveStringsA() -> Option<unsafe fn(
    nBufferLength: DWORD,
    lpBuffer: LPSTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetLogicalDriveStringsA\0")) ) } )
}
pub fn LoadPackagedLibrary() -> Option<unsafe fn(
    lpwLibFileName: LPCWSTR,
    Reserved: DWORD,
) -> HMODULE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LoadPackagedLibrary\0")) ) } )
}
pub fn QueryFullProcessImageNameA() -> Option<unsafe fn(
    hProcess: HANDLE,
    dwFlags: DWORD,
    lpExeName: LPSTR,
    lpdwSize: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryFullProcessImageNameA\0")) ) } )
}
pub fn QueryFullProcessImageNameW() -> Option<unsafe fn(
    hProcess: HANDLE,
    dwFlags: DWORD,
    lpExeName: LPWSTR,
    lpdwSize: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryFullProcessImageNameW\0")) ) } )
}
pub fn GetStartupInfoA() -> Option<unsafe fn(
    lpStartupInfo: LPSTARTUPINFOA,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetStartupInfoA\0")) ) } )
}
pub fn GetFirmwareEnvironmentVariableA() -> Option<unsafe fn(
    lpName: LPCSTR,
    lpGuid: LPCSTR,
    pBuffer: PVOID,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFirmwareEnvironmentVariableA\0")) ) } )
}
pub fn GetFirmwareEnvironmentVariableW() -> Option<unsafe fn(
    lpName: LPCWSTR,
    lpGuid: LPCWSTR,
    pBuffer: PVOID,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFirmwareEnvironmentVariableW\0")) ) } )
}
pub fn GetFirmwareEnvironmentVariableExA() -> Option<unsafe fn(
    lpName: LPCSTR,
    lpGuid: LPCSTR,
    pBuffer: PVOID,
    nSize: DWORD,
    pdwAttribubutes: PDWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFirmwareEnvironmentVariableExA\0")) ) } )
}
pub fn GetFirmwareEnvironmentVariableExW() -> Option<unsafe fn(
    lpName: LPCWSTR,
    lpGuid: LPCWSTR,
    pBuffer: PVOID,
    nSize: DWORD,
    pdwAttribubutes: PDWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFirmwareEnvironmentVariableExW\0")) ) } )
}
pub fn SetFirmwareEnvironmentVariableA() -> Option<unsafe fn(
    lpName: LPCSTR,
    lpGuid: LPCSTR,
    pValue: PVOID,
    nSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFirmwareEnvironmentVariableA\0")) ) } )
}
pub fn SetFirmwareEnvironmentVariableW() -> Option<unsafe fn(
    lpName: LPCWSTR,
    lpGuid: LPCWSTR,
    pValue: PVOID,
    nSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFirmwareEnvironmentVariableW\0")) ) } )
}
pub fn SetFirmwareEnvironmentVariableExA() -> Option<unsafe fn(
    lpName: LPCSTR,
    lpGuid: LPCSTR,
    pValue: PVOID,
    nSize: DWORD,
    dwAttributes: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFirmwareEnvironmentVariableExA\0")) ) } )
}
pub fn SetFirmwareEnvironmentVariableExW() -> Option<unsafe fn(
    lpName: LPCWSTR,
    lpGuid: LPCWSTR,
    pValue: PVOID,
    nSize: DWORD,
    dwAttributes: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFirmwareEnvironmentVariableExW\0")) ) } )
}
pub fn GetFirmwareType() -> Option<unsafe fn(
    FirmwareType: PFIRMWARE_TYPE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFirmwareType\0")) ) } )
}
pub fn IsNativeVhdBoot() -> Option<unsafe fn(
    NativeVhdBoot: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsNativeVhdBoot\0")) ) } )
}
pub fn FindResourceA() -> Option<unsafe fn(
    hModule: HMODULE,
    lpName: LPCSTR,
    lpType: LPCSTR,
) -> HRSRC> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindResourceA\0")) ) } )
}
pub fn FindResourceExA() -> Option<unsafe fn(
    hModule: HMODULE,
    lpName: LPCSTR,
    lpType: LPCSTR,
    wLanguage: WORD,
) -> HRSRC> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindResourceExA\0")) ) } )
}
pub fn EnumResourceTypesA() -> Option<unsafe fn(
    hModule: HMODULE,
    lpEnumFunc: ENUMRESTYPEPROCA,
    lParam: LONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumResourceTypesA\0")) ) } )
}
pub fn EnumResourceTypesW() -> Option<unsafe fn(
    hModule: HMODULE,
    lpEnumFunc: ENUMRESTYPEPROCW,
    lParam: LONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumResourceTypesW\0")) ) } )
}
pub fn EnumResourceNamesA() -> Option<unsafe fn(
    hModule: HMODULE,
    lpType: LPCSTR,
    lpEnumFunc: ENUMRESNAMEPROCA,
    lParam: LONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumResourceNamesA\0")) ) } )
}
pub fn EnumResourceLanguagesA() -> Option<unsafe fn(
    hModule: HMODULE,
    lpType: LPCSTR,
    lpName: LPCSTR,
    lpEnumFunc: ENUMRESLANGPROCA,
    lParam: LONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumResourceLanguagesA\0")) ) } )
}
pub fn EnumResourceLanguagesW() -> Option<unsafe fn(
    hModule: HMODULE,
    lpType: LPCWSTR,
    lpName: LPCWSTR,
    lpEnumFunc: ENUMRESLANGPROCW,
    lParam: LONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnumResourceLanguagesW\0")) ) } )
}
pub fn BeginUpdateResourceA() -> Option<unsafe fn(
    pFileName: LPCSTR,
    bDeleteExistingResources: BOOL,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BeginUpdateResourceA\0")) ) } )
}
pub fn BeginUpdateResourceW() -> Option<unsafe fn(
    pFileName: LPCWSTR,
    bDeleteExistingResources: BOOL,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BeginUpdateResourceW\0")) ) } )
}
pub fn UpdateResourceA() -> Option<unsafe fn(
    hUpdate: HANDLE,
    lpType: LPCSTR,
    lpName: LPCSTR,
    wLanguage: WORD,
    lpData: LPVOID,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UpdateResourceA\0")) ) } )
}
pub fn UpdateResourceW() -> Option<unsafe fn(
    hUpdate: HANDLE,
    lpType: LPCWSTR,
    lpName: LPCWSTR,
    wLanguage: WORD,
    lpData: LPVOID,
    cb: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UpdateResourceW\0")) ) } )
}
pub fn EndUpdateResourceA() -> Option<unsafe fn(
    hUpdate: HANDLE,
    fDiscard: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EndUpdateResourceA\0")) ) } )
}
pub fn EndUpdateResourceW() -> Option<unsafe fn(
    hUpdate: HANDLE,
    fDiscard: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EndUpdateResourceW\0")) ) } )
}
pub fn GlobalAddAtomA() -> Option<unsafe fn(
    lpString: LPCSTR,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalAddAtomA\0")) ) } )
}
pub fn GlobalAddAtomW() -> Option<unsafe fn(
    lpString: LPCWSTR,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalAddAtomW\0")) ) } )
}
pub fn GlobalAddAtomExA() -> Option<unsafe fn(
    lpString: LPCSTR,
    Flags: DWORD,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalAddAtomExA\0")) ) } )
}
pub fn GlobalAddAtomExW() -> Option<unsafe fn(
    lpString: LPCWSTR,
    Flags: DWORD,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalAddAtomExW\0")) ) } )
}
pub fn GlobalFindAtomA() -> Option<unsafe fn(
    lpString: LPCSTR,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalFindAtomA\0")) ) } )
}
pub fn GlobalFindAtomW() -> Option<unsafe fn(
    lpString: LPCWSTR,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalFindAtomW\0")) ) } )
}
pub fn GlobalGetAtomNameA() -> Option<unsafe fn(
    nAtom: ATOM,
    lpBuffer: LPSTR,
    nSize: c_int,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalGetAtomNameA\0")) ) } )
}
pub fn GlobalGetAtomNameW() -> Option<unsafe fn(
    nAtom: ATOM,
    lpBuffer: LPWSTR,
    nSize: c_int,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GlobalGetAtomNameW\0")) ) } )
}
pub fn AddAtomA() -> Option<unsafe fn(
    lpString: LPCSTR,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAtomA\0")) ) } )
}
pub fn AddAtomW() -> Option<unsafe fn(
    lpString: LPCWSTR,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAtomW\0")) ) } )
}
pub fn FindAtomA() -> Option<unsafe fn(
    lpString: LPCSTR,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindAtomA\0")) ) } )
}
pub fn FindAtomW() -> Option<unsafe fn(
    lpString: LPCWSTR,
) -> ATOM> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindAtomW\0")) ) } )
}
pub fn GetAtomNameA() -> Option<unsafe fn(
    nAtom: ATOM,
    lpBuffer: LPSTR,
    nSize: c_int,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetAtomNameA\0")) ) } )
}
pub fn GetAtomNameW() -> Option<unsafe fn(
    nAtom: ATOM,
    lpBuffer: LPWSTR,
    nSize: c_int,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetAtomNameW\0")) ) } )
}
pub fn GetProfileIntA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpKeyName: LPCSTR,
    nDefault: INT,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProfileIntA\0")) ) } )
}
pub fn GetProfileIntW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpKeyName: LPCWSTR,
    nDefault: INT,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProfileIntW\0")) ) } )
}
pub fn GetProfileStringA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpKeyName: LPCSTR,
    lpDefault: LPCSTR,
    lpReturnedString: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProfileStringA\0")) ) } )
}
pub fn GetProfileStringW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpKeyName: LPCWSTR,
    lpDefault: LPCWSTR,
    lpReturnedString: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProfileStringW\0")) ) } )
}
pub fn WriteProfileStringA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpKeyName: LPCSTR,
    lpString: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WriteProfileStringA\0")) ) } )
}
pub fn WriteProfileStringW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpKeyName: LPCWSTR,
    lpString: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WriteProfileStringW\0")) ) } )
}
pub fn GetProfileSectionA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpReturnedString: LPSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProfileSectionA\0")) ) } )
}
pub fn GetProfileSectionW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpReturnedString: LPWSTR,
    nSize: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProfileSectionW\0")) ) } )
}
pub fn WriteProfileSectionA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpString: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WriteProfileSectionA\0")) ) } )
}
pub fn WriteProfileSectionW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpString: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WriteProfileSectionW\0")) ) } )
}
pub fn GetPrivateProfileIntA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpKeyName: LPCSTR,
    nDefault: INT,
    lpFileName: LPCSTR,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileIntA\0")) ) } )
}
pub fn GetPrivateProfileIntW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpKeyName: LPCWSTR,
    nDefault: INT,
    lpFileName: LPCWSTR,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileIntW\0")) ) } )
}
pub fn GetPrivateProfileStringA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpKeyName: LPCSTR,
    lpDefault: LPCSTR,
    lpReturnedString: LPSTR,
    nSize: DWORD,
    lpFileName: LPCSTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileStringA\0")) ) } )
}
pub fn GetPrivateProfileStringW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpKeyName: LPCWSTR,
    lpDefault: LPCWSTR,
    lpReturnedString: LPWSTR,
    nSize: DWORD,
    lpFileName: LPCWSTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileStringW\0")) ) } )
}
pub fn WritePrivateProfileStringA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpKeyName: LPCSTR,
    lpString: LPCSTR,
    lpFileName: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WritePrivateProfileStringA\0")) ) } )
}
pub fn WritePrivateProfileStringW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpKeyName: LPCWSTR,
    lpString: LPCWSTR,
    lpFileName: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WritePrivateProfileStringW\0")) ) } )
}
pub fn GetPrivateProfileSectionA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpReturnedString: LPSTR,
    nSize: DWORD,
    lpFileName: LPCSTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileSectionA\0")) ) } )
}
pub fn GetPrivateProfileSectionW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpReturnedString: LPWSTR,
    nSize: DWORD,
    lpFileName: LPCWSTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileSectionW\0")) ) } )
}
pub fn WritePrivateProfileSectionA() -> Option<unsafe fn(
    lpAppName: LPCSTR,
    lpString: LPCSTR,
    lpFileName: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WritePrivateProfileSectionA\0")) ) } )
}
pub fn WritePrivateProfileSectionW() -> Option<unsafe fn(
    lpAppName: LPCWSTR,
    lpString: LPCWSTR,
    lpFileName: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WritePrivateProfileSectionW\0")) ) } )
}
pub fn GetPrivateProfileSectionNamesA() -> Option<unsafe fn(
    lpszReturnBuffer: LPSTR,
    nSize: DWORD,
    lpFileName: LPCSTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileSectionNamesA\0")) ) } )
}
pub fn GetPrivateProfileSectionNamesW() -> Option<unsafe fn(
    lpszReturnBuffer: LPWSTR,
    nSize: DWORD,
    lpFileName: LPCWSTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileSectionNamesW\0")) ) } )
}
pub fn GetPrivateProfileStructA() -> Option<unsafe fn(
    lpszSection: LPCSTR,
    lpszKey: LPCSTR,
    lpStruct: LPVOID,
    uSizeStruct: UINT,
    szFile: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileStructA\0")) ) } )
}
pub fn GetPrivateProfileStructW() -> Option<unsafe fn(
    lpszSection: LPCWSTR,
    lpszKey: LPCWSTR,
    lpStruct: LPVOID,
    uSizeStruct: UINT,
    szFile: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateProfileStructW\0")) ) } )
}
pub fn WritePrivateProfileStructA() -> Option<unsafe fn(
    lpszSection: LPCSTR,
    lpszKey: LPCSTR,
    lpStruct: LPVOID,
    uSizeStruct: UINT,
    szFile: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WritePrivateProfileStructA\0")) ) } )
}
pub fn WritePrivateProfileStructW() -> Option<unsafe fn(
    lpszSection: LPCWSTR,
    lpszKey: LPCWSTR,
    lpStruct: LPVOID,
    uSizeStruct: UINT,
    szFile: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WritePrivateProfileStructW\0")) ) } )
}
pub fn Wow64EnableWow64FsRedirection() -> Option<unsafe fn(
    Wow64FsEnableRedirection: BOOLEAN,
) -> BOOLEAN> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("Wow64EnableWow64FsRedirection\0")) ) } )
}
pub fn SetDllDirectoryA() -> Option<unsafe fn(
    lpPathName: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetDllDirectoryA\0")) ) } )
}
pub fn SetDllDirectoryW() -> Option<unsafe fn(
    lpPathName: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetDllDirectoryW\0")) ) } )
}
pub fn GetDllDirectoryA() -> Option<unsafe fn(
    nBufferLength: DWORD,
    lpBuffer: LPSTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetDllDirectoryA\0")) ) } )
}
pub fn GetDllDirectoryW() -> Option<unsafe fn(
    nBufferLength: DWORD,
    lpBuffer: LPWSTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetDllDirectoryW\0")) ) } )
}
pub fn SetSearchPathMode() -> Option<unsafe fn(
    Flags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSearchPathMode\0")) ) } )
}
pub fn CreateDirectoryExA() -> Option<unsafe fn(
    lpTemplateDirectory: LPCSTR,
    lpNewDirectory: LPCSTR,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateDirectoryExA\0")) ) } )
}
pub fn CreateDirectoryExW() -> Option<unsafe fn(
    lpTemplateDirectory: LPCWSTR,
    lpNewDirectory: LPCWSTR,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateDirectoryExW\0")) ) } )
}
pub fn CreateDirectoryTransactedA() -> Option<unsafe fn(
    lpTemplateDirectory: LPCSTR,
    lpNewDirectory: LPCSTR,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateDirectoryTransactedA\0")) ) } )
}
pub fn CreateDirectoryTransactedW() -> Option<unsafe fn(
    lpTemplateDirectory: LPCWSTR,
    lpNewDirectory: LPCWSTR,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateDirectoryTransactedW\0")) ) } )
}
pub fn RemoveDirectoryTransactedA() -> Option<unsafe fn(
    lpPathName: LPCSTR,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RemoveDirectoryTransactedA\0")) ) } )
}
pub fn RemoveDirectoryTransactedW() -> Option<unsafe fn(
    lpPathName: LPCWSTR,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RemoveDirectoryTransactedW\0")) ) } )
}
pub fn GetFullPathNameTransactedA() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    nBufferLength: DWORD,
    lpBuffer: LPSTR,
    lpFilePart: *mut LPSTR,
    hTransaction: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFullPathNameTransactedA\0")) ) } )
}
pub fn GetFullPathNameTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    nBufferLength: DWORD,
    lpBuffer: LPWSTR,
    lpFilePart: *mut LPWSTR,
    hTransaction: HANDLE,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFullPathNameTransactedW\0")) ) } )
}
pub fn DefineDosDeviceA() -> Option<unsafe fn(
    dwFlags: DWORD,
    lpDeviceName: LPCSTR,
    lpTargetPath: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DefineDosDeviceA\0")) ) } )
}
pub fn QueryDosDeviceA() -> Option<unsafe fn(
    lpDeviceName: LPCSTR,
    lpTargetPath: LPSTR,
    ucchMax: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryDosDeviceA\0")) ) } )
}
pub fn CreateFileTransactedA() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    dwCreationDisposition: DWORD,
    dwFlagsAndAttributes: DWORD,
    hTemplateFile: HANDLE,
    hTransaction: HANDLE,
    pusMiniVersion: PUSHORT,
    lpExtendedParameter: PVOID,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateFileTransactedA\0")) ) } )
}
pub fn CreateFileTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    dwCreationDisposition: DWORD,
    dwFlagsAndAttributes: DWORD,
    hTemplateFile: HANDLE,
    hTransaction: HANDLE,
    pusMiniVersion: PUSHORT,
    lpExtendedParameter: PVOID,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateFileTransactedW\0")) ) } )
}
pub fn ReOpenFile() -> Option<unsafe fn(
    hOriginalFile: HANDLE,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    dwFlags: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ReOpenFile\0")) ) } )
}
pub fn SetFileAttributesTransactedA() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    dwFileAttributes: DWORD,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFileAttributesTransactedA\0")) ) } )
}
pub fn SetFileAttributesTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    dwFileAttributes: DWORD,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFileAttributesTransactedW\0")) ) } )
}
pub fn GetFileAttributesTransactedA() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    fInfoLevelId: GET_FILEEX_INFO_LEVELS,
    lpFileInformation: LPVOID,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFileAttributesTransactedA\0")) ) } )
}
pub fn GetFileAttributesTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    fInfoLevelId: GET_FILEEX_INFO_LEVELS,
    lpFileInformation: LPVOID,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFileAttributesTransactedW\0")) ) } )
}
pub fn GetCompressedFileSizeTransactedA() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    lpFileSizeHigh: LPDWORD,
    hTransaction: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCompressedFileSizeTransactedA\0")) ) } )
}
pub fn GetCompressedFileSizeTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    lpFileSizeHigh: LPDWORD,
    hTransaction: HANDLE,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCompressedFileSizeTransactedW\0")) ) } )
}
pub fn DeleteFileTransactedA() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteFileTransactedA\0")) ) } )
}
pub fn DeleteFileTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteFileTransactedW\0")) ) } )
}
pub fn CheckNameLegalDOS8Dot3A() -> Option<unsafe fn(
    lpName: LPCSTR,
    lpOemName: LPSTR,
    OemNameSize: DWORD,
    pbNameContainsSpaces: PBOOL,
    pbNameLegal: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CheckNameLegalDOS8Dot3A\0")) ) } )
}
pub fn CheckNameLegalDOS8Dot3W() -> Option<unsafe fn(
    lpName: LPCWSTR,
    lpOemName: LPSTR,
    OemNameSize: DWORD,
    pbNameContainsSpaces: PBOOL,
    pbNameLegal: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CheckNameLegalDOS8Dot3W\0")) ) } )
}
pub fn FindFirstFileTransactedA() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    fInfoLevelId: FINDEX_INFO_LEVELS,
    lpFindFileData: LPVOID,
    fSearchOp: FINDEX_SEARCH_OPS,
    lpSearchFilter: LPVOID,
    dwAdditionalFlags: DWORD,
    hTransaction: HANDLE,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindFirstFileTransactedA\0")) ) } )
}
pub fn FindFirstFileTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    fInfoLevelId: FINDEX_INFO_LEVELS,
    lpFindFileData: LPVOID,
    fSearchOp: FINDEX_SEARCH_OPS,
    lpSearchFilter: LPVOID,
    dwAdditionalFlags: DWORD,
    hTransaction: HANDLE,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindFirstFileTransactedW\0")) ) } )
}
pub fn CopyFileA() -> Option<unsafe fn(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    bFailIfExists: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CopyFileA\0")) ) } )
}
pub fn CopyFileW() -> Option<unsafe fn(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    bFailIfExists: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CopyFileW\0")) ) } )
}
pub fn CopyFileExA() -> Option<unsafe fn(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    pbCancel: LPBOOL,
    dwCopyFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CopyFileExA\0")) ) } )
}
pub fn CopyFileExW() -> Option<unsafe fn(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    pbCancel: LPBOOL,
    dwCopyFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CopyFileExW\0")) ) } )
}
pub fn CopyFileTransactedA() -> Option<unsafe fn(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    pbCancel: LPBOOL,
    dwCopyFlags: DWORD,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CopyFileTransactedA\0")) ) } )
}
pub fn CopyFileTransactedW() -> Option<unsafe fn(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    pbCancel: LPBOOL,
    dwCopyFlags: DWORD,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CopyFileTransactedW\0")) ) } )
}
pub fn CopyFile2() -> Option<unsafe fn(
    pwszExistingFileName: PCWSTR,
    pwszNewFileName: PCWSTR,
    pExtendedParameters: *mut COPYFILE2_EXTENDED_PARAMETERS,
) -> HRESULT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CopyFile2\0")) ) } )
}
pub fn MoveFileA() -> Option<unsafe fn(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MoveFileA\0")) ) } )
}
pub fn MoveFileW() -> Option<unsafe fn(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MoveFileW\0")) ) } )
}
pub fn MoveFileExA() -> Option<unsafe fn(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MoveFileExA\0")) ) } )
}
pub fn MoveFileExW() -> Option<unsafe fn(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MoveFileExW\0")) ) } )
}
pub fn MoveFileWithProgressA() -> Option<unsafe fn(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MoveFileWithProgressA\0")) ) } )
}
pub fn MoveFileWithProgressW() -> Option<unsafe fn(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MoveFileWithProgressW\0")) ) } )
}
pub fn MoveFileTransactedA() -> Option<unsafe fn(
    lpExistingFileName: LPCSTR,
    lpNewFileName: LPCSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    dwFlags: DWORD,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MoveFileTransactedA\0")) ) } )
}
pub fn MoveFileTransactedW() -> Option<unsafe fn(
    lpExistingFileName: LPCWSTR,
    lpNewFileName: LPCWSTR,
    lpProgressRoutine: LPPROGRESS_ROUTINE,
    lpData: LPVOID,
    dwFlags: DWORD,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MoveFileTransactedW\0")) ) } )
}
pub fn ReplaceFileA() -> Option<unsafe fn(
    lpReplacedFileName: LPCSTR,
    lpReplacementFileName: LPCSTR,
    lpBackupFileName: LPCSTR,
    dwReplaceFlags: DWORD,
    lpExclude: LPVOID,
    lpReserved: LPVOID,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ReplaceFileA\0")) ) } )
}
pub fn ReplaceFileW() -> Option<unsafe fn(
    lpReplacedFileName: LPCWSTR,
    lpReplacementFileName: LPCWSTR,
    lpBackupFileName: LPCWSTR,
    dwReplaceFlags: DWORD,
    lpExclude: LPVOID,
    lpReserved: LPVOID,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ReplaceFileW\0")) ) } )
}
pub fn CreateHardLinkA() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    lpExistingFileName: LPCSTR,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateHardLinkA\0")) ) } )
}
pub fn CreateHardLinkW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    lpExistingFileName: LPCWSTR,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateHardLinkW\0")) ) } )
}
pub fn CreateHardLinkTransactedA() -> Option<unsafe fn(
    lpFileName: LPCSTR,
    lpExistingFileName: LPCSTR,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    hTransaction: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateHardLinkTransactedA\0")) ) } )
}
pub fn CreateHardLinkTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    lpExistingFileName: LPCWSTR,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    hTransaction: HANDLE,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateHardLinkTransactedW\0")) ) } )
}
pub fn FindFirstStreamTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    InfoLevel: STREAM_INFO_LEVELS,
    lpFindStreamData: LPVOID,
    dwFlags: DWORD,
    hTransaction: HANDLE,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindFirstStreamTransactedW\0")) ) } )
}
pub fn FindFirstFileNameTransactedW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    dwFlags: DWORD,
    StringLength: LPDWORD,
    LinkName: PWSTR,
    hTransaction: HANDLE,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindFirstFileNameTransactedW\0")) ) } )
}
pub fn CreateNamedPipeA() -> Option<unsafe fn(
    lpName: LPCSTR,
    dwOpenMode: DWORD,
    dwPipeMode: DWORD,
    nMaxInstances: DWORD,
    nOutBufferSize: DWORD,
    nInBufferSize: DWORD,
    nDefaultTimeOut: DWORD,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateNamedPipeA\0")) ) } )
}
pub fn GetNamedPipeHandleStateA() -> Option<unsafe fn(
    hNamedPipe: HANDLE,
    lpState: LPDWORD,
    lpCurInstances: LPDWORD,
    lpMaxCollectionCount: LPDWORD,
    lpCollectDataTimeout: LPDWORD,
    lpUserName: LPSTR,
    nMaxUserNameSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNamedPipeHandleStateA\0")) ) } )
}
pub fn CallNamedPipeA() -> Option<unsafe fn(
    lpNamedPipeName: LPCSTR,
    lpInBuffer: LPVOID,
    nInBufferSize: DWORD,
    lpOutBuffer: LPVOID,
    nOutBufferSize: DWORD,
    lpBytesRead: LPDWORD,
    nTimeOut: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CallNamedPipeA\0")) ) } )
}
pub fn WaitNamedPipeA() -> Option<unsafe fn(
    lpNamedPipeName: LPCSTR,
    nTimeOut: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WaitNamedPipeA\0")) ) } )
}
pub fn GetNamedPipeClientComputerNameA() -> Option<unsafe fn(
    Pipe: HANDLE,
    ClientComputerName: LPSTR,
    ClientComputerNameLength: ULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNamedPipeClientComputerNameA\0")) ) } )
}
pub fn GetNamedPipeClientProcessId() -> Option<unsafe fn(
    Pipe: HANDLE,
    ClientProcessId: PULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNamedPipeClientProcessId\0")) ) } )
}
pub fn GetNamedPipeClientSessionId() -> Option<unsafe fn(
    Pipe: HANDLE,
    ClientSessionId: PULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNamedPipeClientSessionId\0")) ) } )
}
pub fn GetNamedPipeServerProcessId() -> Option<unsafe fn(
    Pipe: HANDLE,
    ServerProcessId: PULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNamedPipeServerProcessId\0")) ) } )
}
pub fn GetNamedPipeServerSessionId() -> Option<unsafe fn(
    Pipe: HANDLE,
    ServerSessionId: PULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNamedPipeServerSessionId\0")) ) } )
}
pub fn SetVolumeLabelA() -> Option<unsafe fn(
    lpRootPathName: LPCSTR,
    lpVolumeName: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetVolumeLabelA\0")) ) } )
}
pub fn SetVolumeLabelW() -> Option<unsafe fn(
    lpRootPathName: LPCWSTR,
    lpVolumeName: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetVolumeLabelW\0")) ) } )
}
pub fn SetFileBandwidthReservation() -> Option<unsafe fn(
    hFile: HANDLE,
    nPeriodMilliseconds: DWORD,
    nBytesPerPeriod: DWORD,
    bDiscardable: BOOL,
    lpTransferSize: LPDWORD,
    lpNumOutstandingRequests: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFileBandwidthReservation\0")) ) } )
}
pub fn GetFileBandwidthReservation() -> Option<unsafe fn(
    hFile: HANDLE,
    lpPeriodMilliseconds: LPDWORD,
    lpBytesPerPeriod: LPDWORD,
    pDiscardable: LPBOOL,
    lpTransferSize: LPDWORD,
    lpNumOutstandingRequests: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFileBandwidthReservation\0")) ) } )
}
pub fn DeregisterEventSource() -> Option<unsafe fn(
    hEventLog: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("DeregisterEventSource\0")) ) } )
}
pub fn RegisterEventSourceA() -> Option<unsafe fn(
    lpUNCServerName: LPCSTR,
    lpSourceName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("RegisterEventSourceA\0")) ) } )
}
pub fn RegisterEventSourceW() -> Option<unsafe fn(
    lpUNCServerName: LPCWSTR,
    lpSourceName: LPCWSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("RegisterEventSourceW\0")) ) } )
}
pub fn ReportEventA() -> Option<unsafe fn(
    hEventLog: HANDLE,
    wType: WORD,
    wCategory: WORD,
    dwEventID: DWORD,
    lpUserSid: PSID,
    wNumStrings: WORD,
    dwDataSize: DWORD,
    lpStrings: *mut LPCSTR,
    lpRawData: LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("ReportEventA\0")) ) } )
}
pub fn ReportEventW() -> Option<unsafe fn(
    hEventLog: HANDLE,
    wType: WORD,
    wCategory: WORD,
    dwEventID: DWORD,
    lpUserSid: PSID,
    wNumStrings: WORD,
    dwDataSize: DWORD,
    lpStrings: *mut LPCWSTR,
    lpRawData: LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("ReportEventW\0")) ) } )
}
pub fn ReadDirectoryChangesW() -> Option<unsafe fn(
    hDirectory: HANDLE,
    lpBuffer: LPVOID,
    nBufferLength: DWORD,
    bWatchSubtree: BOOL,
    dwNotifyFilter: DWORD,
    lpBytesReturned: LPDWORD,
    lpOverlapped: LPOVERLAPPED,
    lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ReadDirectoryChangesW\0")) ) } )
}
pub fn MapViewOfFileExNuma() -> Option<unsafe fn(
    hFileMappingObject: HANDLE,
    dwDesiredAccess: DWORD,
    dwFileOffsetHigh: DWORD,
    dwFileOffsetLow: DWORD,
    dwNumberOfBytesToMap: SIZE_T,
    lpBaseAddress: LPVOID,
    nndPreferred: DWORD,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MapViewOfFileExNuma\0")) ) } )
}
pub fn IsBadReadPtr() -> Option<unsafe fn(
    lp: *const VOID,
    ucb: UINT_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsBadReadPtr\0")) ) } )
}
pub fn IsBadWritePtr() -> Option<unsafe fn(
    lp: LPVOID,
    ucb: UINT_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsBadWritePtr\0")) ) } )
}
pub fn IsBadHugeReadPtr() -> Option<unsafe fn(
    lp: *const VOID,
    ucb: UINT_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsBadHugeReadPtr\0")) ) } )
}
pub fn IsBadHugeWritePtr() -> Option<unsafe fn(
    lp: LPVOID,
    ucb: UINT_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsBadHugeWritePtr\0")) ) } )
}
pub fn IsBadCodePtr() -> Option<unsafe fn(
    lpfn: FARPROC,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsBadCodePtr\0")) ) } )
}
pub fn IsBadStringPtrA() -> Option<unsafe fn(
    lpsz: LPCSTR,
    ucchMax: UINT_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsBadStringPtrA\0")) ) } )
}
pub fn IsBadStringPtrW() -> Option<unsafe fn(
    lpsz: LPCWSTR,
    ucchMax: UINT_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsBadStringPtrW\0")) ) } )
}
pub fn LookupAccountSidA() -> Option<unsafe fn(
    lpSystemName: LPCSTR,
    Sid: PSID,
    Name: LPSTR,
    cchName: LPDWORD,
    ReferencedDomainName: LPSTR,
    cchReferencedDomainName: LPDWORD,
    peUse: PSID_NAME_USE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LookupAccountSidA\0")) ) } )
}
pub fn LookupAccountSidW() -> Option<unsafe fn(
    lpSystemName: LPCWSTR,
    Sid: PSID,
    Name: LPWSTR,
    cchName: LPDWORD,
    ReferencedDomainName: LPWSTR,
    cchReferencedDomainName: LPDWORD,
    peUse: PSID_NAME_USE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LookupAccountSidW\0")) ) } )
}
pub fn LookupAccountNameA() -> Option<unsafe fn(
    lpSystemName: LPCSTR,
    lpAccountName: LPCSTR,
    Sid: PSID,
    cbSid: LPDWORD,
    ReferencedDomainName: LPCSTR,
    cchReferencedDomainName: LPDWORD,
    peUse: PSID_NAME_USE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LookupAccountNameA\0")) ) } )
}
pub fn LookupAccountNameW() -> Option<unsafe fn(
    lpSystemName: LPCWSTR,
    lpAccountName: LPCWSTR,
    Sid: PSID,
    cbSid: LPDWORD,
    ReferencedDomainName: LPCWSTR,
    cchReferencedDomainName: LPDWORD,
    peUse: PSID_NAME_USE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LookupAccountNameW\0")) ) } )
}
pub fn LookupPrivilegeValueA() -> Option<unsafe fn(
    lpSystemName: LPCSTR,
    lpName: LPCSTR,
    lpLuid: PLUID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LookupPrivilegeValueA\0")) ) } )
}
pub fn LookupPrivilegeValueW() -> Option<unsafe fn(
    lpSystemName: LPCWSTR,
    lpName: LPCWSTR,
    lpLuid: PLUID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LookupPrivilegeValueW\0")) ) } )
}
pub fn LookupPrivilegeNameA() -> Option<unsafe fn(
    lpSystemName: LPCSTR,
    lpLuid: PLUID,
    lpName: LPSTR,
    cchName: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LookupPrivilegeNameA\0")) ) } )
}
pub fn LookupPrivilegeNameW() -> Option<unsafe fn(
    lpSystemName: LPCWSTR,
    lpLuid: PLUID,
    lpName: LPWSTR,
    cchName: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LookupPrivilegeNameW\0")) ) } )
}
pub fn BuildCommDCBA() -> Option<unsafe fn(
    lpDef: LPCSTR,
    lpDCB: LPDCB,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BuildCommDCBA\0")) ) } )
}
pub fn BuildCommDCBW() -> Option<unsafe fn(
    lpDef: LPCWSTR,
    lpDCB: LPDCB,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BuildCommDCBW\0")) ) } )
}
pub fn BuildCommDCBAndTimeoutsA() -> Option<unsafe fn(
    lpDef: LPCSTR,
    lpDCB: LPDCB,
    lpCommTimeouts: LPCOMMTIMEOUTS,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BuildCommDCBAndTimeoutsA\0")) ) } )
}
pub fn BuildCommDCBAndTimeoutsW() -> Option<unsafe fn(
    lpDef: LPCWSTR,
    lpDCB: LPDCB,
    lpCommTimeouts: LPCOMMTIMEOUTS,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BuildCommDCBAndTimeoutsW\0")) ) } )
}
pub fn CommConfigDialogA() -> Option<unsafe fn(
    lpszName: LPCSTR,
    hWnd: HWND,
    lpCC: LPCOMMCONFIG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CommConfigDialogA\0")) ) } )
}
pub fn CommConfigDialogW() -> Option<unsafe fn(
    lpszName: LPCWSTR,
    hWnd: HWND,
    lpCC: LPCOMMCONFIG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CommConfigDialogW\0")) ) } )
}
pub fn GetDefaultCommConfigA() -> Option<unsafe fn(
    lpszName: LPCSTR,
    lpCC: LPCOMMCONFIG,
    lpdwSize: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetDefaultCommConfigA\0")) ) } )
}
pub fn GetDefaultCommConfigW() -> Option<unsafe fn(
    lpszName: LPCWSTR,
    lpCC: LPCOMMCONFIG,
    lpdwSize: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetDefaultCommConfigW\0")) ) } )
}
pub fn SetDefaultCommConfigA() -> Option<unsafe fn(
    lpszName: LPCSTR,
    lpCC: LPCOMMCONFIG,
    dwSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetDefaultCommConfigA\0")) ) } )
}
pub fn SetDefaultCommConfigW() -> Option<unsafe fn(
    lpszName: LPCWSTR,
    lpCC: LPCOMMCONFIG,
    dwSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetDefaultCommConfigW\0")) ) } )
}
pub fn GetComputerNameA() -> Option<unsafe fn(
    lpBuffer: LPSTR,
    nSize: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetComputerNameA\0")) ) } )
}
pub fn GetComputerNameW() -> Option<unsafe fn(
    lpBuffer: LPWSTR,
    nSize: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetComputerNameW\0")) ) } )
}
pub fn DnsHostnameToComputerNameA() -> Option<unsafe fn(
    Hostname: LPCSTR,
    ComputerName: LPCSTR,
    nSize: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DnsHostnameToComputerNameA\0")) ) } )
}
pub fn DnsHostnameToComputerNameW() -> Option<unsafe fn(
    Hostname: LPCWSTR,
    ComputerName: LPWSTR,
    nSize: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DnsHostnameToComputerNameW\0")) ) } )
}
pub fn GetUserNameA() -> Option<unsafe fn(
    lpBuffer: LPSTR,
    pcbBuffer: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("GetUserNameA\0")) ) } )
}
pub fn GetUserNameW() -> Option<unsafe fn(
    lpBuffer: LPWSTR,
    pcbBuffer: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("GetUserNameW\0")) ) } )
}
pub fn LogonUserA() -> Option<unsafe fn(
    lpUsername: LPCSTR,
    lpDomain: LPCSTR,
    lpPassword: LPCSTR,
    dwLogonType: DWORD,
    dwLogonProvider: DWORD,
    phToken: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LogonUserA\0")) ) } )
}
pub fn LogonUserW() -> Option<unsafe fn(
    lpUsername: LPCWSTR,
    lpDomain: LPCWSTR,
    lpPassword: LPCWSTR,
    dwLogonType: DWORD,
    dwLogonProvider: DWORD,
    phToken: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LogonUserW\0")) ) } )
}
pub fn LogonUserExA() -> Option<unsafe fn(
    lpUsername: LPCSTR,
    lpDomain: LPCSTR,
    lpPassword: LPCSTR,
    dwLogonType: DWORD,
    dwLogonProvider: DWORD,
    phToken: PHANDLE,
    ppLogonSid: *mut PSID,
    ppProfileBuffer: *mut PVOID,
    pdwProfileLength: LPDWORD,
    pQuotaLimits: PQUOTA_LIMITS,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LogonUserExA\0")) ) } )
}
pub fn LogonUserExW() -> Option<unsafe fn(
    lpUsername: LPCWSTR,
    lpDomain: LPCWSTR,
    lpPassword: LPCWSTR,
    dwLogonType: DWORD,
    dwLogonProvider: DWORD,
    phToken: PHANDLE,
    ppLogonSid: *mut PSID,
    ppProfileBuffer: *mut PVOID,
    pdwProfileLength: LPDWORD,
    pQuotaLimits: PQUOTA_LIMITS,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("LogonUserExW\0")) ) } )
}
pub fn CreateProcessWithLogonW() -> Option<unsafe fn(
    lpUsername: LPCWSTR,
    lpDomain: LPCWSTR,
    lpPassword: LPCWSTR,
    dwLogonFlags: DWORD,
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: LPSTARTUPINFOW,
    lpProcessInformation: LPPROCESS_INFORMATION,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("CreateProcessWithLogonW\0")) ) } )
}
pub fn CreateProcessWithTokenW() -> Option<unsafe fn(
    hToken: HANDLE,
    dwLogonFlags: DWORD,
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: LPSTARTUPINFOW,
    lpProcessInformation: LPPROCESS_INFORMATION,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("CreateProcessWithTokenW\0")) ) } )
}
pub fn IsTokenUntrusted() -> Option<unsafe fn(
    TokenHandle: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsTokenUntrusted\0")) ) } )
}
pub fn RegisterWaitForSingleObject() -> Option<unsafe fn(
    phNewWaitObject: PHANDLE,
    hObject: HANDLE,
    Callback: WAITORTIMERCALLBACK,
    Context: PVOID,
    dwMilliseconds: ULONG,
    dwFlags: ULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RegisterWaitForSingleObject\0")) ) } )
}
pub fn UnregisterWait() -> Option<unsafe fn(
    WaitHandle: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UnregisterWait\0")) ) } )
}
pub fn BindIoCompletionCallback() -> Option<unsafe fn(
    FileHandle: HANDLE,
    Function: LPOVERLAPPED_COMPLETION_ROUTINE,
    Flags: ULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("BindIoCompletionCallback\0")) ) } )
}
pub fn SetTimerQueueTimer() -> Option<unsafe fn(
    TimerQueue: HANDLE,
    Callback: WAITORTIMERCALLBACK,
    Parameter: PVOID,
    DueTime: DWORD,
    Period: DWORD,
    PreferIo: BOOL,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetTimerQueueTimer\0")) ) } )
}
pub fn CancelTimerQueueTimer() -> Option<unsafe fn(
    TimerQueue: HANDLE,
    Timer: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CancelTimerQueueTimer\0")) ) } )
}
pub fn DeleteTimerQueue() -> Option<unsafe fn(
    TimerQueue: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteTimerQueue\0")) ) } )
}
pub fn CreatePrivateNamespaceA() -> Option<unsafe fn(
    lpPrivateNamespaceAttributes: LPSECURITY_ATTRIBUTES,
    lpBoundaryDescriptor: LPVOID,
    lpAliasPrefix: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreatePrivateNamespaceA\0")) ) } )
}
pub fn OpenPrivateNamespaceA() -> Option<unsafe fn(
    lpBoundaryDescriptor: LPVOID,
    lpAliasPrefix: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenPrivateNamespaceA\0")) ) } )
}
pub fn CreateBoundaryDescriptorA() -> Option<unsafe fn(
    Name: LPCSTR,
    Flags: ULONG,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateBoundaryDescriptorA\0")) ) } )
}
pub fn AddIntegrityLabelToBoundaryDescriptor() -> Option<unsafe fn(
    BoundaryDescriptor: *mut HANDLE,
    IntegrityLabel: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddIntegrityLabelToBoundaryDescriptor\0")) ) } )
}
pub fn GetCurrentHwProfileA() -> Option<unsafe fn(
    lpHwProfileInfo: LPHW_PROFILE_INFOA,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("GetCurrentHwProfileA\0")) ) } )
}
pub fn GetCurrentHwProfileW() -> Option<unsafe fn(
    lpHwProfileInfo: LPHW_PROFILE_INFOW,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_advapi32_fn(obfstr::obfstr!("GetCurrentHwProfileW\0")) ) } )
}
pub fn VerifyVersionInfoA() -> Option<unsafe fn(
    lpVersionInformation: LPOSVERSIONINFOEXA,
    dwTypeMask: DWORD,
    dwlConditionMask: DWORDLONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VerifyVersionInfoA\0")) ) } )
}
pub fn VerifyVersionInfoW() -> Option<unsafe fn(
    lpVersionInformation: LPOSVERSIONINFOEXW,
    dwTypeMask: DWORD,
    dwlConditionMask: DWORDLONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VerifyVersionInfoW\0")) ) } )
}
pub fn GetSystemPowerStatus() -> Option<unsafe fn(
    lpSystemPowerStatus: LPSYSTEM_POWER_STATUS,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSystemPowerStatus\0")) ) } )
}
pub fn SetSystemPowerState() -> Option<unsafe fn(
    fSuspend: BOOL,
    fForce: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSystemPowerState\0")) ) } )
}
pub fn MapUserPhysicalPagesScatter() -> Option<unsafe fn(
    VirtualAddresses: *mut PVOID,
    NumberOfPages: ULONG_PTR,
    PageArray: PULONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MapUserPhysicalPagesScatter\0")) ) } )
}
pub fn CreateJobObjectA() -> Option<unsafe fn(
    lpJobAttributes: LPSECURITY_ATTRIBUTES,
    lpName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateJobObjectA\0")) ) } )
}
pub fn OpenJobObjectA() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    lpName: LPCSTR,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenJobObjectA\0")) ) } )
}
pub fn CreateJobSet() -> Option<unsafe fn(
    NumJob: ULONG,
    UserJobSet: PJOB_SET_ARRAY,
    Flags: ULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateJobSet\0")) ) } )
}
pub fn FindFirstVolumeA() -> Option<unsafe fn(
    lpszVolumeName: LPSTR,
    cchBufferLength: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindFirstVolumeA\0")) ) } )
}
pub fn FindNextVolumeA() -> Option<unsafe fn(
    hFindVolume: HANDLE,
    lpszVolumeName: LPSTR,
    cchBufferLength: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindNextVolumeA\0")) ) } )
}
pub fn FindFirstVolumeMountPointA() -> Option<unsafe fn(
    lpszRootPathName: LPCSTR,
    lpszVolumeMountPoint: LPSTR,
    cchBufferLength: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindFirstVolumeMountPointA\0")) ) } )
}
pub fn FindFirstVolumeMountPointW() -> Option<unsafe fn(
    lpszRootPathName: LPCWSTR,
    lpszVolumeMountPoint: LPWSTR,
    cchBufferLength: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindFirstVolumeMountPointW\0")) ) } )
}
pub fn FindNextVolumeMountPointA() -> Option<unsafe fn(
    hFindVolumeMountPoint: HANDLE,
    lpszVolumeMountPoint: LPSTR,
    cchBufferLength: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindNextVolumeMountPointA\0")) ) } )
}
pub fn FindNextVolumeMountPointW() -> Option<unsafe fn(
    hFindVolumeMountPoint: HANDLE,
    lpszVolumeMountPoint: LPWSTR,
    cchBufferLength: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindNextVolumeMountPointW\0")) ) } )
}
pub fn FindVolumeMountPointClose() -> Option<unsafe fn(
    hFindVolumeMountPoint: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindVolumeMountPointClose\0")) ) } )
}
pub fn SetVolumeMountPointA() -> Option<unsafe fn(
    lpszVolumeMountPoint: LPCSTR,
    lpszVolumeName: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetVolumeMountPointA\0")) ) } )
}
pub fn SetVolumeMountPointW() -> Option<unsafe fn(
    lpszVolumeMountPoint: LPCWSTR,
    lpszVolumeName: LPCWSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetVolumeMountPointW\0")) ) } )
}
pub fn DeleteVolumeMountPointA() -> Option<unsafe fn(
    lpszVolumeMountPoint: LPCSTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteVolumeMountPointA\0")) ) } )
}
pub fn GetVolumeNameForVolumeMountPointA() -> Option<unsafe fn(
    lpszVolumeMountPoint: LPCSTR,
    lpszVolumeName: LPSTR,
    cchBufferLength: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetVolumeNameForVolumeMountPointA\0")) ) } )
}
pub fn GetVolumePathNameA() -> Option<unsafe fn(
    lpszFileName: LPCSTR,
    lpszVolumePathName: LPSTR,
    cchBufferLength: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetVolumePathNameA\0")) ) } )
}
pub fn GetVolumePathNamesForVolumeNameA() -> Option<unsafe fn(
    lpszVolumeName: LPCSTR,
    lpszVolumePathNames: LPCH,
    cchBufferLength: DWORD,
    lpcchReturnLength: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetVolumePathNamesForVolumeNameA\0")) ) } )
}
pub fn CreateActCtxA() -> Option<unsafe fn(
    pActCtx: PCACTCTXA,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateActCtxA\0")) ) } )
}
pub fn CreateActCtxW() -> Option<unsafe fn(
    pActCtx: PCACTCTXW,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateActCtxW\0")) ) } )
}
pub fn AddRefActCtx() -> Option<unsafe fn(
    hActCtx: HANDLE,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddRefActCtx\0")) ) } )
}
pub fn ReleaseActCtx() -> Option<unsafe fn(
    hActCtx: HANDLE,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ReleaseActCtx\0")) ) } )
}
pub fn ZombifyActCtx() -> Option<unsafe fn(
    hActCtx: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ZombifyActCtx\0")) ) } )
}
pub fn ActivateActCtx() -> Option<unsafe fn(
    hActCtx: HANDLE,
    lpCookie: *mut ULONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ActivateActCtx\0")) ) } )
}
pub fn DeactivateActCtx() -> Option<unsafe fn(
    dwFlags: DWORD,
    ulCookie: ULONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeactivateActCtx\0")) ) } )
}
pub fn GetCurrentActCtx() -> Option<unsafe fn(
    lphActCtx: *mut HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentActCtx\0")) ) } )
}
pub fn FindActCtxSectionStringA() -> Option<unsafe fn(
    dwFlags: DWORD,
    lpExtensionGuid: *const GUID,
    ulSectionId: ULONG,
    lpStringToFind: LPCSTR,
    ReturnedData: PACTCTX_SECTION_KEYED_DATA,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindActCtxSectionStringA\0")) ) } )
}
pub fn FindActCtxSectionStringW() -> Option<unsafe fn(
    dwFlags: DWORD,
    lpExtensionGuid: *const GUID,
    ulSectionId: ULONG,
    lpStringToFind: LPCWSTR,
    ReturnedData: PACTCTX_SECTION_KEYED_DATA,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindActCtxSectionStringW\0")) ) } )
}
pub fn FindActCtxSectionGuid() -> Option<unsafe fn(
    dwFlags: DWORD,
    lpExtensionGuid: *const GUID,
    ulSectionId: ULONG,
    lpGuidToFind: *const GUID,
    ReturnedData: PACTCTX_SECTION_KEYED_DATA,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindActCtxSectionGuid\0")) ) } )
}
pub fn QueryActCtxW() -> Option<unsafe fn(
    dwFlags: DWORD,
    hActCtx: HANDLE,
    pvSubInstance: PVOID,
    ulInfoClass: ULONG,
    pvBuffer: PVOID,
    cbBuffer: SIZE_T,
    pcbWrittenOrRequired: *mut SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryActCtxW\0")) ) } )
}
pub fn WTSGetActiveConsoleSessionId() -> Option<unsafe fn() -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WTSGetActiveConsoleSessionId\0")) ) } )
}
pub fn GetActiveProcessorGroupCount() -> Option<unsafe fn() -> WORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetActiveProcessorGroupCount\0")) ) } )
}
pub fn GetMaximumProcessorGroupCount() -> Option<unsafe fn() -> WORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetMaximumProcessorGroupCount\0")) ) } )
}
pub fn GetActiveProcessorCount() -> Option<unsafe fn(
    GroupNumber: WORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetActiveProcessorCount\0")) ) } )
}
pub fn GetMaximumProcessorCount() -> Option<unsafe fn(
    GroupNumber: WORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetMaximumProcessorCount\0")) ) } )
}
pub fn GetNumaProcessorNode() -> Option<unsafe fn(
    Processor: UCHAR,
    NodeNumber: PUCHAR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNumaProcessorNode\0")) ) } )
}
pub fn GetNumaNodeNumberFromHandle() -> Option<unsafe fn(
    hFile: HANDLE,
    NodeNumber: PUSHORT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNumaNodeNumberFromHandle\0")) ) } )
}
pub fn GetNumaProcessorNodeEx() -> Option<unsafe fn(
    Processor: PPROCESSOR_NUMBER,
    NodeNumber: PUSHORT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNumaProcessorNodeEx\0")) ) } )
}
pub fn GetNumaNodeProcessorMask() -> Option<unsafe fn(
    Node: UCHAR,
    ProcessorMask: PULONGLONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNumaNodeProcessorMask\0")) ) } )
}
pub fn GetNumaAvailableMemoryNode() -> Option<unsafe fn(
    Node: UCHAR,
    AvailableBytes: PULONGLONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNumaAvailableMemoryNode\0")) ) } )
}
pub fn GetNumaAvailableMemoryNodeEx() -> Option<unsafe fn(
    Node: USHORT,
    AvailableBytes: PULONGLONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNumaAvailableMemoryNodeEx\0")) ) } )
}
pub fn GetNumaProximityNode() -> Option<unsafe fn(
    ProximityId: ULONG,
    NodeNumber: PUCHAR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNumaProximityNode\0")) ) } )
}
pub fn RegisterApplicationRecoveryCallback() -> Option<unsafe fn(
    pRecoveyCallback: APPLICATION_RECOVERY_CALLBACK,
    pvParameter: PVOID,
    dwPingInterval: DWORD,
    dwFlags: DWORD,
) -> HRESULT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RegisterApplicationRecoveryCallback\0")) ) } )
}
pub fn UnregisterApplicationRecoveryCallback() -> Option<unsafe fn() -> HRESULT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UnregisterApplicationRecoveryCallback\0")) ) } )
}
pub fn RegisterApplicationRestart() -> Option<unsafe fn(
    pwzCommandline: PCWSTR,
    dwFlags: DWORD,
) -> HRESULT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RegisterApplicationRestart\0")) ) } )
}
pub fn UnregisterApplicationRestart() -> Option<unsafe fn() -> HRESULT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UnregisterApplicationRestart\0")) ) } )
}
pub fn GetApplicationRecoveryCallback() -> Option<unsafe fn(
    hProcess: HANDLE,
    pRecoveryCallback: *mut APPLICATION_RECOVERY_CALLBACK,
    ppvParameter: *mut PVOID,
    pdwPingInterval: PDWORD,
    pdwFlags: PDWORD,
) -> HRESULT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetApplicationRecoveryCallback\0")) ) } )
}
pub fn GetApplicationRestartSettings() -> Option<unsafe fn(
    hProcess: HANDLE,
    pwzCommandline: PWSTR,
    pcchSize: PDWORD,
    pdwFlags: PDWORD,
) -> HRESULT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetApplicationRestartSettings\0")) ) } )
}
pub fn ApplicationRecoveryInProgress() -> Option<unsafe fn(
    pbCancelled: PBOOL,
) -> HRESULT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ApplicationRecoveryInProgress\0")) ) } )
}
pub fn ApplicationRecoveryFinished() -> Option<unsafe fn(
    bSuccess: BOOL,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ApplicationRecoveryFinished\0")) ) } )
}
pub fn GetFileInformationByHandleEx() -> Option<unsafe fn(
    hFile: HANDLE,
    FileInformationClass: FILE_INFO_BY_HANDLE_CLASS,
    lpFileInformation: LPVOID,
    dwBufferSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFileInformationByHandleEx\0")) ) } )
}
pub fn OpenFileById() -> Option<unsafe fn(
    hVolumeHint: HANDLE,
    lpFileId: LPFILE_ID_DESCRIPTOR,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    dwFlagsAndAttributes: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenFileById\0")) ) } )
}
pub fn CreateSymbolicLinkA() -> Option<unsafe fn(
    lpSymlinkFileName: LPCSTR,
    lpTargetFileName: LPCSTR,
    dwFlags: DWORD,
) -> BOOLEAN> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateSymbolicLinkA\0")) ) } )
}
pub fn CreateSymbolicLinkW() -> Option<unsafe fn(
    lpSymlinkFileName: LPCWSTR,
    lpTargetFileName: LPCWSTR,
    dwFlags: DWORD,
) -> BOOLEAN> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateSymbolicLinkW\0")) ) } )
}
pub fn QueryActCtxSettingsW() -> Option<unsafe fn(
    dwFlags: DWORD,
    hActCtx: HANDLE,
    settingsNameSpace: PCWSTR,
    settingName: PCWSTR,
    pvBuffer: PWSTR,
    dwBuffer: SIZE_T,
    pdwWrittenOrRequired: *mut SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryActCtxSettingsW\0")) ) } )
}
pub fn CreateSymbolicLinkTransactedA() -> Option<unsafe fn(
    lpSymlinkFileName: LPCSTR,
    lpTargetFileName: LPCSTR,
    dwFlags: DWORD,
    hTransaction: HANDLE,
) -> BOOLEAN> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateSymbolicLinkTransactedA\0")) ) } )
}
pub fn CreateSymbolicLinkTransactedW() -> Option<unsafe fn(
    lpSymlinkFileName: LPCWSTR,
    lpTargetFileName: LPCWSTR,
    dwFlags: DWORD,
    hTransaction: HANDLE,
) -> BOOLEAN> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateSymbolicLinkTransactedW\0")) ) } )
}
pub fn ReplacePartitionUnit() -> Option<unsafe fn(
    TargetPartition: PWSTR,
    SparePartition: PWSTR,
    Flags: ULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ReplacePartitionUnit\0")) ) } )
}
pub fn AddSecureMemoryCacheCallback() -> Option<unsafe fn(
    pfnCallBack: PSECURE_MEMORY_CACHE_CALLBACK,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddSecureMemoryCacheCallback\0")) ) } )
}
pub fn RemoveSecureMemoryCacheCallback() -> Option<unsafe fn(
    pfnCallBack: PSECURE_MEMORY_CACHE_CALLBACK,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RemoveSecureMemoryCacheCallback\0")) ) } )
}
pub fn CopyContext() -> Option<unsafe fn(
    Destination: PCONTEXT,
    ContextFlags: DWORD,
    Source: PCONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CopyContext\0")) ) } )
}
pub fn InitializeContext() -> Option<unsafe fn(
    Buffer: PVOID,
    ContextFlags: DWORD,
    Context: *mut PCONTEXT,
    ContextLength: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("InitializeContext\0")) ) } )
}
pub fn GetEnabledXStateFeatures() -> Option<unsafe fn() -> DWORD64> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetEnabledXStateFeatures\0")) ) } )
}
pub fn GetXStateFeaturesMask() -> Option<unsafe fn(
    Context: PCONTEXT,
    FeatureMask: PDWORD64,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetXStateFeaturesMask\0")) ) } )
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn LocateXStateFeature() -> Option<unsafe fn(
    Context: PCONTEXT,
    FeatureId: DWORD,
    Length: PDWORD,
) -> PVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("LocateXStateFeature\0")) ) } )
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn SetXStateFeaturesMask() -> Option<unsafe fn(
    Context: PCONTEXT,
    FeatureMask: DWORD64,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetXStateFeaturesMask\0")) ) } )
}
pub fn EnableThreadProfiling() -> Option<unsafe fn(
    ThreadHandle: HANDLE,
    Flags: DWORD,
    HardwareCounters: DWORD64,
    PerformanceDataHandle: *mut HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EnableThreadProfiling\0")) ) } )
}
pub fn DisableThreadProfiling() -> Option<unsafe fn(
    PerformanceDataHandle: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DisableThreadProfiling\0")) ) } )
}
pub fn QueryThreadProfiling() -> Option<unsafe fn(
    ThreadHandle: HANDLE,
    Enabled: PBOOLEAN,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryThreadProfiling\0")) ) } )
}
pub fn ReadThreadProfilingData() -> Option<unsafe fn(
    PerformanceDataHandle: HANDLE,
    Flags: DWORD,
    PerformanceData: PPERFORMANCE_DATA,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ReadThreadProfilingData\0")) ) } )
}
