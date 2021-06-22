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
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueueUserAPC")) as FARPROC ) } )
}
pub fn GetProcessTimes() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpCreationTime: LPFILETIME,
    lpExitTime: LPFILETIME,
    lpKernelTime: LPFILETIME,
    lpUserTime: LPFILETIME,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessTimes")) as FARPROC ) } )
}
pub fn GetCurrentProcess() -> Option<unsafe fn() -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentProcess")) as FARPROC ) } )
}
pub fn GetCurrentProcessId() -> Option<unsafe fn() -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentProcessId")) as FARPROC ) } )
}
pub fn ExitProcess() -> Option<unsafe fn(
    uExitCode: UINT,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ExitProcess")) as FARPROC ) } )
}
pub fn TerminateProcess() -> Option<unsafe fn(
    hProcess: HANDLE,
    uExitCode: UINT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TerminateProcess")) as FARPROC ) } )
}
pub fn GetExitCodeProcess() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpExitCode: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetExitCodeProcess")) as FARPROC ) } )
}
pub fn SwitchToThread() -> Option<unsafe fn() -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SwitchToThread")) as FARPROC ) } )
}
pub fn CreateThread() -> Option<unsafe fn(
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: LPDWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateThread")) as FARPROC ) } )
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
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateRemoteThread")) as FARPROC ) } )
}
pub fn GetCurrentThread() -> Option<unsafe fn() -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentThread")) as FARPROC ) } )
}
pub fn GetCurrentThreadId() -> Option<unsafe fn() -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentThreadId")) as FARPROC ) } )
}
pub fn OpenThread() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwThreadId: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenThread")) as FARPROC ) } )
}
pub fn SetThreadPriority() -> Option<unsafe fn(
    hThread: HANDLE,
    nPriority: c_int,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadPriority")) as FARPROC ) } )
}
pub fn SetThreadPriorityBoost() -> Option<unsafe fn(
    hThread: HANDLE,
    bDisablePriorityBoost: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadPriorityBoost")) as FARPROC ) } )
}
pub fn GetThreadPriorityBoost() -> Option<unsafe fn(
    hThread: HANDLE,
    pDisablePriorityBoost: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadPriorityBoost")) as FARPROC ) } )
}
pub fn GetThreadPriority() -> Option<unsafe fn(
    hThread: HANDLE,
) -> c_int> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadPriority")) as FARPROC ) } )
}
pub fn ExitThread() -> Option<unsafe fn(
    dwExitCode: DWORD,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ExitThread")) as FARPROC ) } )
}
pub fn TerminateThread() -> Option<unsafe fn(
    hThread: HANDLE,
    dwExitCode: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TerminateThread")) as FARPROC ) } )
}
pub fn GetExitCodeThread() -> Option<unsafe fn(
    hThread: HANDLE,
    lpExitCode: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetExitCodeThread")) as FARPROC ) } )
}
pub fn SuspendThread() -> Option<unsafe fn(
    hThread: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SuspendThread")) as FARPROC ) } )
}
pub fn ResumeThread() -> Option<unsafe fn(
    hThread: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ResumeThread")) as FARPROC ) } )
}
pub fn TlsAlloc() -> Option<unsafe fn() -> DWORD> { 
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TlsAlloc")) as FARPROC ) } )
}
pub fn TlsGetValue() -> Option<unsafe fn(
    dwTlsIndex: DWORD,
) -> LPVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TlsGetValue")) as FARPROC ) } )
}
pub fn TlsSetValue() -> Option<unsafe fn(
    dwTlsIndex: DWORD,
    lpTlsValue: LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TlsSetValue")) as FARPROC ) } )
}
pub fn TlsFree() -> Option<unsafe fn(
    dwTlsIndex: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TlsFree")) as FARPROC ) } )
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
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateProcessA")) as FARPROC ) } )
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
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateProcessW")) as FARPROC ) } )
}
pub fn SetProcessShutdownParameters() -> Option<unsafe fn(
    dwLevel: DWORD,
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessShutdownParameters")) as FARPROC ) } )
}
pub fn GetProcessVersion() -> Option<unsafe fn(
    ProcessId: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessVersion")) as FARPROC ) } )
}
pub fn GetStartupInfoW() -> Option<unsafe fn(
    lpStartupInfo: LPSTARTUPINFOW,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetStartupInfoW")) as FARPROC ) } )
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
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateProcessAsUserW")) as FARPROC ) } )
}
pub fn SetThreadToken() -> Option<unsafe fn(
    Thread: PHANDLE,
    Token: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadToken")) as FARPROC ) } )
}
pub fn OpenProcessToken() -> Option<unsafe fn(
    ProcessHandle: HANDLE,
    DesiredAccess: DWORD,
    TokenHandle: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenProcessToken")) as FARPROC ) } )
}
pub fn OpenThreadToken() -> Option<unsafe fn(
    ThreadHandle: HANDLE,
    DesiredAccess: DWORD,
    OpenAsSelf: BOOL,
    TokenHandle: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenThreadToken")) as FARPROC ) } )
}
pub fn SetPriorityClass() -> Option<unsafe fn(
    hProcess: HANDLE,
    dwPriorityClass: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetPriorityClass")) as FARPROC ) } )
}
pub fn SetThreadStackGuarantee() -> Option<unsafe fn(
    StackSizeInBytes: PULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadStackGuarantee")) as FARPROC ) } )
}
pub fn GetPriorityClass() -> Option<unsafe fn(
    hProcess: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPriorityClass")) as FARPROC ) } )
}
pub fn ProcessIdToSessionId() -> Option<unsafe fn(
    dwProcessId: DWORD,
    pSessionId: *mut DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ProcessIdToSessionId")) as FARPROC ) } )
}
pub fn GetProcessId() -> Option<unsafe fn(
    Process: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessId")) as FARPROC ) } )
}
pub fn GetThreadId() -> Option<unsafe fn(
    Thread: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadId")) as FARPROC ) } )
}
pub fn FlushProcessWriteBuffers() -> Option<unsafe fn()> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FlushProcessWriteBuffers")) as FARPROC ) } )
}
pub fn GetProcessIdOfThread() -> Option<unsafe fn(
    Thread: HANDLE,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessIdOfThread")) as FARPROC ) } )
}
pub fn InitializeProcThreadAttributeList() -> Option<unsafe fn(
    lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
    dwAttributeCount: DWORD,
    dwFlags: DWORD,
    lpSize: PSIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("InitializeProcThreadAttributeList")) as FARPROC ) } )
}
pub fn DeleteProcThreadAttributeList() -> Option<unsafe fn(
    lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteProcThreadAttributeList")) as FARPROC ) } )
}
pub fn SetProcessAffinityUpdateMode() -> Option<unsafe fn(
    hProcess: HANDLE,
    dwFlags: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessAffinityUpdateMode")) as FARPROC ) } )
}
pub fn QueryProcessAffinityUpdateMode() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpdwFlags: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryProcessAffinityUpdateMode")) as FARPROC ) } )
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
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UpdateProcThreadAttribute")) as FARPROC ) } )
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
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateRemoteThreadEx")) as FARPROC ) } )
}
pub fn GetCurrentThreadStackLimits() -> Option<unsafe fn(
    LowLimit: PULONG_PTR,
    HighLimit: PULONG_PTR,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentThreadStackLimits")) as FARPROC ) } )
}
pub fn GetThreadContext() -> Option<unsafe fn(
    hThread: HANDLE,
    lpContext: LPCONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadContext")) as FARPROC ) } )
}
pub fn SetThreadContext() -> Option<unsafe fn(
    hThread: HANDLE,
    lpContext: *const CONTEXT,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadContext")) as FARPROC ) } )
}
pub fn SetProcessMitigationPolicy() -> Option<unsafe fn(
    MitigationPolicy: PROCESS_MITIGATION_POLICY,
    lpBuffer: PVOID,
    dwLength: SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessMitigationPolicy")) as FARPROC ) } )
}
pub fn GetProcessMitigationPolicy() -> Option<unsafe fn(
    hProcess: HANDLE,
    MitigationPolicy: PROCESS_MITIGATION_POLICY,
    lpBuffer: PVOID,
    dwLength: SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessMitigationPolicy")) as FARPROC ) } )
}
pub fn FlushInstructionCache() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpBaseAddress: LPCVOID,
    dwSize: SIZE_T,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FlushInstructionCache")) as FARPROC ) } )
}
pub fn GetThreadTimes() -> Option<unsafe fn(
    hThread: HANDLE,
    lpCreationTime: LPFILETIME,
    lpExitTime: LPFILETIME,
    lpKernelTime: LPFILETIME,
    lpUserTime: LPFILETIME,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadTimes")) as FARPROC ) } )
}
pub fn OpenProcess() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenProcess")) as FARPROC ) } )
}
pub fn IsProcessorFeaturePresent() -> Option<unsafe fn(
    ProcessorFeature: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsProcessorFeaturePresent")) as FARPROC ) } )
}
pub fn GetProcessHandleCount() -> Option<unsafe fn(
    hProcess: HANDLE,
    pdwHandleCount: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessHandleCount")) as FARPROC ) } )
}
pub fn GetCurrentProcessorNumber() -> Option<unsafe fn() -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentProcessorNumber")) as FARPROC ) } )
}
pub fn SetThreadIdealProcessorEx() -> Option<unsafe fn(
    hThread: HANDLE,
    lpIdealProcessor: PPROCESSOR_NUMBER,
    lpPreviousIdealProcessor: PPROCESSOR_NUMBER,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadIdealProcessorEx")) as FARPROC ) } )
}
pub fn GetThreadIdealProcessorEx() -> Option<unsafe fn(
    hThread: HANDLE,
    lpIdealProcessor: PPROCESSOR_NUMBER,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadIdealProcessorEx")) as FARPROC ) } )
}
pub fn GetCurrentProcessorNumberEx() -> Option<unsafe fn(
    ProcNumber: PPROCESSOR_NUMBER,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCurrentProcessorNumberEx")) as FARPROC ) } )
}
pub fn GetProcessPriorityBoost() -> Option<unsafe fn(
    hProcess: HANDLE,
    pDisablePriorityBoost: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessPriorityBoost")) as FARPROC ) } )
}
pub fn SetProcessPriorityBoost() -> Option<unsafe fn(
    hProcess: HANDLE,
    bDisablePriorityBoost: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessPriorityBoost")) as FARPROC ) } )
}
pub fn GetThreadIOPendingFlag() -> Option<unsafe fn(
    hThread: HANDLE,
    lpIOIsPending: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadIOPendingFlag")) as FARPROC ) } )
}
pub fn GetSystemTimes() -> Option<unsafe fn(
    lpIdleTime: LPFILETIME,
    lpKernelTime: LPFILETIME,
    lpUserTime: LPFILETIME,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSystemTimes")) as FARPROC ) } )
}
pub fn GetThreadInformation() -> Option<unsafe fn(
    hThread: HANDLE,
    ThreadInformationClass: THREAD_INFORMATION_CLASS,
    ThreadInformation: LPVOID,
    ThreadInformationSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadInformation")) as FARPROC ) } )
}
pub fn SetThreadInformation() -> Option<unsafe fn(
    hThread: HANDLE,
    ThreadInformationClass: THREAD_INFORMATION_CLASS,
    ThreadInformation: LPVOID,
    ThreadInformationSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadInformation")) as FARPROC ) } )
}
pub fn IsProcessCritical() -> Option<unsafe fn(
    hProcess: HANDLE,
    Critical: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsProcessCritical")) as FARPROC ) } )
}
pub fn SetProtectedPolicy() -> Option<unsafe fn(
    PolicyGuid: LPCGUID,
    PolicyValue: ULONG_PTR,
    OldPolicyValue: PULONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProtectedPolicy")) as FARPROC ) } )
}
pub fn QueryProtectedPolicy() -> Option<unsafe fn(
    PolicyGuid: LPCGUID,
    PolicyValue: PULONG_PTR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryProtectedPolicy")) as FARPROC ) } )
}
pub fn SetThreadIdealProcessor() -> Option<unsafe fn(
    hThread: HANDLE,
    dwIdealProcessor: DWORD,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadIdealProcessor")) as FARPROC ) } )
}
pub fn SetProcessInformation() -> Option<unsafe fn(
    hProcess: HANDLE,
    ProcessInformationClass: PROCESS_INFORMATION_CLASS,
    ProcessInformation: LPVOID,
    ProcessInformationSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessInformation")) as FARPROC ) } )
}
pub fn GetProcessInformation() -> Option<unsafe fn(
    hProcess: HANDLE,
    ProcessInformationClass: PROCESS_INFORMATION_CLASS,
    ProcessInformation: LPVOID,
    ProcessInformationSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessInformation")) as FARPROC ) } )
}
pub fn GetProcessShutdownParameters() -> Option<unsafe fn(
    lpdwLevel: LPDWORD,
    lpdwFlags: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessShutdownParameters")) as FARPROC ) } )
}
