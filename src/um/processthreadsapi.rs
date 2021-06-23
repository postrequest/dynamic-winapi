#![allow(non_snake_case)]
use winapi::ctypes::c_int;
use winapi::shared::basetsd::{DWORD_PTR, PSIZE_T, PULONG_PTR, SIZE_T, ULONG_PTR};
use winapi::shared::guiddef::LPCGUID;
use winapi::shared::minwindef::{
    BOOL, DWORD, FARPROC, LPCVOID, LPDWORD, LPFILETIME, LPVOID, PBOOL, PDWORD, PULONG, UINT
};
use winapi::um::minwinbase::{LPCONTEXT, LPSECURITY_ATTRIBUTES, LPTHREAD_START_ROUTINE};
use winapi::um::winnt::{
    CONTEXT, HANDLE, LPCSTR, LPCWSTR, LPSTR, LPWSTR, PAPCFUNC, PHANDLE, PPROCESSOR_NUMBER,
    PROCESS_MITIGATION_POLICY, PVOID
};
use winapi::um::processthreadsapi::{LPSTARTUPINFOA, LPPROCESS_INFORMATION, LPSTARTUPINFOW, LPPROC_THREAD_ATTRIBUTE_LIST, THREAD_INFORMATION_CLASS, PROCESS_INFORMATION_CLASS};

use crate::get_k32_fn;

pub fn QueueUserAPC() -> Option<unsafe fn(
    pfnAPC: PAPCFUNC,
    hThread: HANDLE,
    dwData: ULONG_PTR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueueUserAPC\0")) ) } )
}
pub fn GetProcessTimes() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpCreationTime: LPFILETIME,
    lpExitTime: LPFILETIME,
    lpKernelTime: LPFILETIME,
    lpUserTime: LPFILETIME,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessTimes\0")) ) } )
}
pub fn GetCurrentProcess() -> Option<unsafe fn() -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentProcess\0")) ) } )
}
pub fn GetCurrentProcessId() -> Option<unsafe fn() -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentProcessId\0")) ) } )
}
pub fn ExitProcess() -> Option<unsafe fn(
    uExitCode: UINT,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ExitProcess\0")) ) } )
}
pub fn TerminateProcess() -> Option<unsafe fn(
    hProcess: HANDLE,
    uExitCode: UINT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TerminateProcess\0")) ) } )
}
pub fn GetExitCodeProcess() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpExitCode: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetExitCodeProcess\0")) ) } )
}
pub fn SwitchToThread() -> Option<unsafe fn() -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SwitchToThread\0")) ) } )
}
pub fn CreateThread() -> Option<unsafe fn(
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: LPDWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateThread\0")) ) } )
}
pub fn CreateRemoteThread() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: LPDWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateRemoteThread\0")) ) } )
}
pub fn GetCurrentThread() -> Option<unsafe fn() -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentThread\0")) ) } )
}
pub fn GetCurrentThreadId() -> Option<unsafe fn() -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentThreadId\0")) ) } )
}
pub fn OpenThread() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwThreadId: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenThread\0")) ) } )
}
pub fn SetThreadPriority() -> Option<unsafe fn(
    hThread: HANDLE,
    nPriority: c_int,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadPriority\0")) ) } )
}
pub fn SetThreadPriorityBoost() -> Option<unsafe fn(
    hThread: HANDLE,
    bDisablePriorityBoost: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadPriorityBoost\0")) ) } )
}
pub fn GetThreadPriorityBoost() -> Option<unsafe fn(
    hThread: HANDLE,
    pDisablePriorityBoost: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadPriorityBoost\0")) ) } )
}
pub fn GetThreadPriority() -> Option<unsafe fn(
    hThread: HANDLE,
) -> c_int> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadPriority\0")) ) } )
}
pub fn ExitThread() -> Option<unsafe fn(
    dwExitCode: DWORD,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ExitThread\0")) ) } )
}
pub fn TerminateThread() -> Option<unsafe fn(
    hThread: HANDLE,
    dwExitCode: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TerminateThread\0")) ) } )
}
pub fn GetExitCodeThread() -> Option<unsafe fn(
    hThread: HANDLE,
    lpExitCode: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetExitCodeThread\0")) ) } )
}
pub fn SuspendThread() -> Option<unsafe fn(
    hThread: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SuspendThread\0")) ) } )
}
pub fn ResumeThread() -> Option<unsafe fn(
    hThread: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ResumeThread\0")) ) } )
}
pub fn TlsAlloc() -> Option<unsafe fn() -> DWORD> { 
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TlsAlloc\0")) ) } )
}
pub fn TlsGetValue() -> Option<unsafe fn(
    dwTlsIndex: DWORD,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TlsGetValue\0")) ) } )
}
pub fn TlsSetValue() -> Option<unsafe fn(
    dwTlsIndex: DWORD,
    lpTlsValue: LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TlsSetValue\0")) ) } )
}
pub fn TlsFree() -> Option<unsafe fn(
    dwTlsIndex: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TlsFree\0")) ) } )
}
pub fn CreateProcessA() -> Option<unsafe fn(
    lpApplicationName: LPCSTR,
    lpCommandLine: LPSTR,
    lpProcessAttributes: LPSECURITY_ATTRIBUTES,
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCSTR,
    lpStartupInfo: LPSTARTUPINFOA,
    lpProcessInformation: LPPROCESS_INFORMATION,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateProcessA\0")) ) } )
}
pub fn CreateProcessW() -> Option<unsafe fn(
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    lpProcessAttributes: LPSECURITY_ATTRIBUTES,
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: LPSTARTUPINFOW,
    lpProcessInformation: LPPROCESS_INFORMATION,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateProcessW\0")) ) } )
}
pub fn SetProcessShutdownParameters() -> Option<unsafe fn(
    dwLevel: DWORD,
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessShutdownParameters\0")) ) } )
}
pub fn GetProcessVersion() -> Option<unsafe fn(
    ProcessId: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessVersion\0")) ) } )
}
pub fn GetStartupInfoW() -> Option<unsafe fn(
    lpStartupInfo: LPSTARTUPINFOW,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetStartupInfoW\0")) ) } )
}
pub fn CreateProcessAsUserW() -> Option<unsafe fn(
    hToken: HANDLE,
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    lpProcessAttributes: LPSECURITY_ATTRIBUTES,
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: LPSTARTUPINFOW,
    lpProcessInformation: LPPROCESS_INFORMATION,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateProcessAsUserW\0")) ) } )
}
pub fn SetThreadToken() -> Option<unsafe fn(
    Thread: PHANDLE,
    Token: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadToken\0")) ) } )
}
pub fn OpenProcessToken() -> Option<unsafe fn(
    ProcessHandle: HANDLE,
    DesiredAccess: DWORD,
    TokenHandle: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenProcessToken\0")) ) } )
}
pub fn OpenThreadToken() -> Option<unsafe fn(
    ThreadHandle: HANDLE,
    DesiredAccess: DWORD,
    OpenAsSelf: BOOL,
    TokenHandle: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenThreadToken\0")) ) } )
}
pub fn SetPriorityClass() -> Option<unsafe fn(
    hProcess: HANDLE,
    dwPriorityClass: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetPriorityClass\0")) ) } )
}
pub fn SetThreadStackGuarantee() -> Option<unsafe fn(
    StackSizeInBytes: PULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadStackGuarantee\0")) ) } )
}
pub fn GetPriorityClass() -> Option<unsafe fn(
    hProcess: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPriorityClass\0")) ) } )
}
pub fn ProcessIdToSessionId() -> Option<unsafe fn(
    dwProcessId: DWORD,
    pSessionId: *mut DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ProcessIdToSessionId\0")) ) } )
}
pub fn GetProcessId() -> Option<unsafe fn(
    Process: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessId\0")) ) } )
}
pub fn GetThreadId() -> Option<unsafe fn(
    Thread: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadId\0")) ) } )
}
pub fn FlushProcessWriteBuffers() -> Option<unsafe fn()> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FlushProcessWriteBuffers\0")) ) } )
}
pub fn GetProcessIdOfThread() -> Option<unsafe fn(
    Thread: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessIdOfThread\0")) ) } )
}
pub fn InitializeProcThreadAttributeList() -> Option<unsafe fn(
    lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
    dwAttributeCount: DWORD,
    dwFlags: DWORD,
    lpSize: PSIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("InitializeProcThreadAttributeList\0")) ) } )
}
pub fn DeleteProcThreadAttributeList() -> Option<unsafe fn(
    lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteProcThreadAttributeList\0")) ) } )
}
pub fn SetProcessAffinityUpdateMode() -> Option<unsafe fn(
    hProcess: HANDLE,
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessAffinityUpdateMode\0")) ) } )
}
pub fn QueryProcessAffinityUpdateMode() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpdwFlags: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryProcessAffinityUpdateMode\0")) ) } )
}
pub fn UpdateProcThreadAttribute() -> Option<unsafe fn(
    lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
    dwFlags: DWORD,
    Attribute: DWORD_PTR,
    lpValue: PVOID,
    cbSize: SIZE_T,
    lpPreviousValue: PVOID,
    lpReturnSize: PSIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UpdateProcThreadAttribute\0")) ) } )
}
pub fn CreateRemoteThreadEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: LPVOID,
    dwCreationFlags: DWORD,
    lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
    lpThreadId: LPDWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateRemoteThreadEx\0")) ) } )
}
pub fn GetCurrentThreadStackLimits() -> Option<unsafe fn(
    LowLimit: PULONG_PTR,
    HighLimit: PULONG_PTR,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentThreadStackLimits\0")) ) } )
}
pub fn GetThreadContext() -> Option<unsafe fn(
    hThread: HANDLE,
    lpContext: LPCONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadContext\0")) ) } )
}
pub fn SetThreadContext() -> Option<unsafe fn(
    hThread: HANDLE,
    lpContext: *const CONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadContext\0")) ) } )
}
pub fn SetProcessMitigationPolicy() -> Option<unsafe fn(
    MitigationPolicy: PROCESS_MITIGATION_POLICY,
    lpBuffer: PVOID,
    dwLength: SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessMitigationPolicy\0")) ) } )
}
pub fn GetProcessMitigationPolicy() -> Option<unsafe fn(
    hProcess: HANDLE,
    MitigationPolicy: PROCESS_MITIGATION_POLICY,
    lpBuffer: PVOID,
    dwLength: SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessMitigationPolicy\0")) ) } )
}
pub fn FlushInstructionCache() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpBaseAddress: LPCVOID,
    dwSize: SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FlushInstructionCache\0")) ) } )
}
pub fn GetThreadTimes() -> Option<unsafe fn(
    hThread: HANDLE,
    lpCreationTime: LPFILETIME,
    lpExitTime: LPFILETIME,
    lpKernelTime: LPFILETIME,
    lpUserTime: LPFILETIME,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadTimes\0")) ) } )
}
pub fn OpenProcess() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenProcess\0")) ) } )
}
pub fn IsProcessorFeaturePresent() -> Option<unsafe fn(
    ProcessorFeature: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsProcessorFeaturePresent\0")) ) } )
}
pub fn GetProcessHandleCount() -> Option<unsafe fn(
    hProcess: HANDLE,
    pdwHandleCount: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessHandleCount\0")) ) } )
}
pub fn GetCurrentProcessorNumber() -> Option<unsafe fn() -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentProcessorNumber\0")) ) } )
}
pub fn SetThreadIdealProcessorEx() -> Option<unsafe fn(
    hThread: HANDLE,
    lpIdealProcessor: PPROCESSOR_NUMBER,
    lpPreviousIdealProcessor: PPROCESSOR_NUMBER,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadIdealProcessorEx\0")) ) } )
}
pub fn GetThreadIdealProcessorEx() -> Option<unsafe fn(
    hThread: HANDLE,
    lpIdealProcessor: PPROCESSOR_NUMBER,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadIdealProcessorEx\0")) ) } )
}
pub fn GetCurrentProcessorNumberEx() -> Option<unsafe fn(
    ProcNumber: PPROCESSOR_NUMBER,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentProcessorNumberEx\0")) ) } )
}
pub fn GetProcessPriorityBoost() -> Option<unsafe fn(
    hProcess: HANDLE,
    pDisablePriorityBoost: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessPriorityBoost\0")) ) } )
}
pub fn SetProcessPriorityBoost() -> Option<unsafe fn(
    hProcess: HANDLE,
    bDisablePriorityBoost: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessPriorityBoost\0")) ) } )
}
pub fn GetThreadIOPendingFlag() -> Option<unsafe fn(
    hThread: HANDLE,
    lpIOIsPending: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadIOPendingFlag\0")) ) } )
}
pub fn GetSystemTimes() -> Option<unsafe fn(
    lpIdleTime: LPFILETIME,
    lpKernelTime: LPFILETIME,
    lpUserTime: LPFILETIME,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSystemTimes\0")) ) } )
}
pub fn GetThreadInformation() -> Option<unsafe fn(
    hThread: HANDLE,
    ThreadInformationClass: THREAD_INFORMATION_CLASS,
    ThreadInformation: LPVOID,
    ThreadInformationSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadInformation\0")) ) } )
}
pub fn SetThreadInformation() -> Option<unsafe fn(
    hThread: HANDLE,
    ThreadInformationClass: THREAD_INFORMATION_CLASS,
    ThreadInformation: LPVOID,
    ThreadInformationSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadInformation\0")) ) } )
}
pub fn IsProcessCritical() -> Option<unsafe fn(
    hProcess: HANDLE,
    Critical: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsProcessCritical\0")) ) } )
}
pub fn SetProtectedPolicy() -> Option<unsafe fn(
    PolicyGuid: LPCGUID,
    PolicyValue: ULONG_PTR,
    OldPolicyValue: PULONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProtectedPolicy\0")) ) } )
}
pub fn QueryProtectedPolicy() -> Option<unsafe fn(
    PolicyGuid: LPCGUID,
    PolicyValue: PULONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryProtectedPolicy\0")) ) } )
}
pub fn SetThreadIdealProcessor() -> Option<unsafe fn(
    hThread: HANDLE,
    dwIdealProcessor: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadIdealProcessor\0")) ) } )
}
pub fn SetProcessInformation() -> Option<unsafe fn(
    hProcess: HANDLE,
    ProcessInformationClass: PROCESS_INFORMATION_CLASS,
    ProcessInformation: LPVOID,
    ProcessInformationSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessInformation\0")) ) } )
}
pub fn GetProcessInformation() -> Option<unsafe fn(
    hProcess: HANDLE,
    ProcessInformationClass: PROCESS_INFORMATION_CLASS,
    ProcessInformation: LPVOID,
    ProcessInformationSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessInformation\0")) ) } )
}
pub fn GetProcessShutdownParameters() -> Option<unsafe fn(
    lpdwLevel: LPDWORD,
    lpdwFlags: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessShutdownParameters\0")) ) } )
}
