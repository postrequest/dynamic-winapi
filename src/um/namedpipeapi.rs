#![allow(non_snake_case)]
use winapi::shared::minwindef::{BOOL, DWORD, LPDWORD, LPVOID, ULONG};
use winapi::um::minwinbase::{LPOVERLAPPED, LPSECURITY_ATTRIBUTES};
use winapi::um::winnt::{HANDLE, LPCWSTR, LPWSTR, PHANDLE};

use crate::get_k32_fn;

pub fn CreatePipe() -> Option<unsafe fn(
    hReadPipe: PHANDLE,
    hWritePipe: PHANDLE,
    lpPipeAttributes: LPSECURITY_ATTRIBUTES,
    nSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreatePipe\0")) ) } )
}
pub fn ConnectNamedPipe() -> Option<unsafe fn(
    hNamedPipe: HANDLE,
    lpOverlapped: LPOVERLAPPED,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ConnectNamedPipe\0")) ) } )
}
pub fn DisconnectNamedPipe() -> Option<unsafe fn(
    hNamedPipe: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DisconnectNamedPipe\0")) ) } )
}
pub fn SetNamedPipeHandleState() -> Option<unsafe fn(
    hNamedPipe: HANDLE,
    lpMode: LPDWORD,
    lpMaxCollectionCount: LPDWORD,
    lpCollectDataTimeout: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetNamedPipeHandleState\0")) ) } )
}
pub fn PeekNamedPipe() -> Option<unsafe fn(
    hNamedPipe: HANDLE,
    lpBuffer: LPVOID,
    nBufferSize: DWORD,
    lpBytesRead: LPDWORD,
    lpTotalBytesAvail: LPDWORD,
    lpBytesLeftThisMessage: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("PeekNamedPipe\0")) ) } )
}
pub fn TransactNamedPipe() -> Option<unsafe fn(
    hNamedPipe: HANDLE,
    lpInBuffer: LPVOID,
    nInBufferSize: DWORD,
    lpOutBuffer: LPVOID,
    nOutBufferSize: DWORD,
    lpBytesRead: LPDWORD,
    lpOverlapped: LPOVERLAPPED,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("TransactNamedPipe\0")) ) } )
}
pub fn CreateNamedPipeW() -> Option<unsafe fn(
    lpName: LPCWSTR,
    dwOpenMode: DWORD,
    dwPipeMode: DWORD,
    nMaxInstances: DWORD,
    nOutBufferSize: DWORD,
    nInBufferSize: DWORD,
    nDefaultTimeOut: DWORD,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
) -> HANDLE> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateNamedPipeW\0")) ) } )
}
pub fn WaitNamedPipeW() -> Option<unsafe fn(
    lpNamedPipeName: LPCWSTR,
    nTimeOut: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WaitNamedPipeW\0")) ) } )
}
pub fn GetNamedPipeClientComputerNameW() -> Option<unsafe fn(
    Pipe: HANDLE,
    ClientComputerName: LPWSTR,
    ClientComputerNameLength: ULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNamedPipeClientComputerNameW\0")) ) } )
}
pub fn ImpersonateNamedPipeClient() -> Option<unsafe fn(
    hNamedPipe: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ImpersonateNamedPipeClient\0")) ) } )
}
pub fn GetNamedPipeInfo() -> Option<unsafe fn(
    hNamedPipe: HANDLE,
    lpFlags: LPDWORD,
    lpOutBufferSize: LPDWORD,
    lpInBufferSize: LPDWORD,
    lpMaxInstances: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNamedPipeInfo\0")) ) } )
}
pub fn GetNamedPipeHandleStateW() -> Option<unsafe fn(
    hNamedPipe: HANDLE,
    lpState: LPDWORD,
    lpCurInstances: LPDWORD,
    lpMaxCollectionCount: LPDWORD,
    lpCollectDataTimeout: LPDWORD,
    lpUserName: LPWSTR,
    nMaxUserNameSize: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetNamedPipeHandleStateW\0")) ) } )
}
pub fn CallNamedPipeW() -> Option<unsafe fn(
    lpNamedPipeName: LPCWSTR,
    lpInBuffer: LPVOID,
    nInBufferSize: DWORD,
    lpOutBuffer: LPVOID,
    nOutBufferSize: DWORD,
    lpBytesRead: LPDWORD,
    nTimeOut: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CallNamedPipeW\0")) ) } )
}
