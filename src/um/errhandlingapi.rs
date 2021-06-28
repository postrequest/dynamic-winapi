#![allow(non_snake_case)]
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::minwindef::{BOOL, DWORD, LPDWORD, UINT, ULONG};
use winapi::um::winnt::{
    EXCEPTION_POINTERS, LONG, LPCSTR, LPCWSTR, PCONTEXT, PEXCEPTION_RECORD,
    PVECTORED_EXCEPTION_HANDLER, PVOID,
};
use winapi::um::errhandlingapi::LPTOP_LEVEL_EXCEPTION_FILTER;

use crate::get_k32_fn;

pub fn RaiseException() -> Option<unsafe fn(
    dwExceptionCode: DWORD,
    dwExceptionFlags: DWORD,
    nNumberOfArguments: DWORD,
    lpArguments: *const ULONG_PTR,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RaiseException\0")) ) } )
}
pub fn UnhandledExceptionFilter() -> Option<unsafe fn(
    ExceptionInfo: *mut EXCEPTION_POINTERS,
) -> LONG> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UnhandledExceptionFilter\0")) ) } )
}
pub fn SetUnhandledExceptionFilter() -> Option<unsafe fn(
    lpTopLevelExceptionFilter: LPTOP_LEVEL_EXCEPTION_FILTER,
) -> LPTOP_LEVEL_EXCEPTION_FILTER> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetUnhandledExceptionFilter\0")) ) } )
}
pub fn GetLastError() -> Option<unsafe fn() -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetLastError\0")) ) } )
}
pub fn SetLastError() -> Option<unsafe fn(
    dwErrCode: DWORD,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetLastError\0")) ) } )
}
pub fn GetErrorMode() -> Option<unsafe fn() -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetErrorMode\0")) ) } )
}
pub fn SetErrorMode() -> Option<unsafe fn(
    uMode: UINT,
) -> UINT> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetErrorMode\0")) ) } )
}
pub fn AddVectoredExceptionHandler() -> Option<unsafe fn(
    First: ULONG,
    Handler: PVECTORED_EXCEPTION_HANDLER,
) -> PVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddVectoredExceptionHandler\0")) ) } )
}
pub fn RemoveVectoredExceptionHandler() -> Option<unsafe fn(
    Handle: PVOID,
) -> ULONG> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RemoveVectoredExceptionHandler\0")) ) } )
}
pub fn AddVectoredContinueHandler() -> Option<unsafe fn(
    First: ULONG,
    Handler: PVECTORED_EXCEPTION_HANDLER,
) -> PVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddVectoredContinueHandler\0")) ) } )
}
pub fn RemoveVectoredContinueHandler() -> Option<unsafe fn(
    Handle: PVOID,
) -> ULONG> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RemoveVectoredContinueHandler\0")) ) } )
}
pub fn RaiseFailFastException() -> Option<unsafe fn(
    pExceptionRecord: PEXCEPTION_RECORD,
    pContextRecord: PCONTEXT,
    dwFlags: DWORD,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RaiseFailFastException\0")) ) } )
}
pub fn FatalAppExitA() -> Option<unsafe fn(
    uAction: UINT,
    lpMessageText: LPCSTR,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FatalAppExitA\0")) ) } )
}
pub fn FatalAppExitW() -> Option<unsafe fn(
    uAction: UINT,
    lpMessageText: LPCWSTR,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FatalAppExitW\0")) ) } )
}
pub fn GetThreadErrorMode() -> Option<unsafe fn() -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetThreadErrorMode\0")) ) } )
}
pub fn SetThreadErrorMode() -> Option<unsafe fn(
    dwNewMode: DWORD,
    lpOldMode: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetThreadErrorMode\0")) ) } )
}
