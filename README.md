# dynamic-winapi

Provide raw FFI bindings to the Windows API by dynamically loading DLLs and resolving the functions with [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).

This project is not a replacement for the [winapi-rs](https://github.com/retep998/winapi-rs) crate and you will more than likely require it if you use this project.

## Feedback

Feel free to file an issue or make a request for APIs [here](https://github.com/postrequest/dynamic-winapi/issues/new).

## Acknowledgments
[@retep998](https://github.com/retep998) for [winapi-rs](https://github.com/retep998/winapi-rs). This project would not have been possible without this, so if you use `dynamic-winapi` or [winapi-rs](https://github.com/retep998/winapi-rs), please consider supporting [@retep998](https://github.com/retep998) [here](https://patreon.com/retep998).  
