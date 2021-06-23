use ctypes::c_void;
use shared::basetsd::{PSIZE_T, PULONG_PTR, SIZE_T, ULONG64, ULONG_PTR};
use shared::minwindef::{
    BOOL, DWORD, LPCVOID, LPDWORD, LPVOID, PBOOL, PDWORD, PULONG, UINT, ULONG,
};
use um::minwinbase::{LPSECURITY_ATTRIBUTES, PSECURITY_ATTRIBUTES};
use um::winnt::{
    HANDLE, LPCWSTR, PCWSTR, PMEMORY_BASIC_INFORMATION, PVOID, SECTION_ALL_ACCESS,
    SECTION_MAP_EXECUTE_EXPLICIT, SECTION_MAP_READ, SECTION_MAP_WRITE,
};
pub fn VirtualAlloc() -> Option<unsafe fn(
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) -> LPVOID> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualAlloc\0")) ) } )
}
pub fn VirtualProtect() -> Option<unsafe fn(
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flNewProtect: DWORD,
    lpflOldProtect: PDWORD,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualProtect\0")) ) } )
}
pub fn VirtualFree() -> Option<unsafe fn(
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualFree\0")) ) } )
}
pub fn VirtualQuery() -> Option<unsafe fn(
    lpAddress: LPCVOID,
    lpBuffer: PMEMORY_BASIC_INFORMATION,
    dwLength: SIZE_T,
) -> SIZE_T> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualQuery\0")) ) } )
}
pub fn VirtualAllocEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) -> LPVOID> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualAllocEx\0")) ) } )
}
pub fn VirtualFreeEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualFreeEx\0")) ) } )
}
pub fn VirtualProtectEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flNewProtect: DWORD,
    lpflOldProtect: PDWORD,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualProtectEx\0")) ) } )
}
pub fn VirtualQueryEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpAddress: LPCVOID,
    lpBuffer: PMEMORY_BASIC_INFORMATION,
    dwLength: SIZE_T,
) -> SIZE_T> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualQueryEx\0")) ) } )
}
pub fn ReadProcessMemory() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpBaseAddress: LPCVOID,
    lpBuffer: LPVOID,
    nSize: SIZE_T,
    lpNumberOfBytesRead: *mut SIZE_T,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ReadProcessMemory\0")) ) } )
}
pub fn WriteProcessMemory() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpBaseAddress: LPVOID,
    lpBuffer: LPCVOID,
    nSize: SIZE_T,
    lpNumberOfBytesWritten: *mut SIZE_T,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("WriteProcessMemory\0")) ) } )
}
pub fn CreateFileMappingW() -> Option<unsafe fn(
    hFile: HANDLE,
    lpFileMappingAttributes: LPSECURITY_ATTRIBUTES,
    flProtect: DWORD,
    dwMaximumSizeHigh: DWORD,
    dwMaximumSizeLow: DWORD,
    lpName: LPCWSTR,
) -> HANDLE> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateFileMappingW\0")) ) } )
}
pub fn OpenFileMappingW() -> Option<unsafe fn(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    lpName: LPCWSTR,
) -> HANDLE> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenFileMappingW\0")) ) } )
}
pub fn MapViewOfFile() -> Option<unsafe fn(
    hFileMappingObject: HANDLE,
    dwDesiredAccess: DWORD,
    dwFileOffsetHigh: DWORD,
    dwFileOffsetLow: DWORD,
    dwNumberOfBytesToMap: SIZE_T,
) -> LPVOID> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MapViewOfFile\0")) ) } )
}
pub fn MapViewOfFileEx() -> Option<unsafe fn(
    hFileMappingObject: HANDLE,
    dwDesiredAccess: DWORD,
    dwFileOffsetHigh: DWORD,
    dwFileOffsetLow: DWORD,
    dwNumberOfBytesToMap: SIZE_T,
    lpBaseAddress: LPVOID,
) -> LPVOID> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MapViewOfFileEx\0")) ) } )
}
pub fn FlushViewOfFile() -> Option<unsafe fn(
    lpBaseAddress: LPCVOID,
    dwNumberOfBytesToFlush: SIZE_T,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FlushViewOfFile\0")) ) } )
}
pub fn UnmapViewOfFile() -> Option<unsafe fn(
    lpBaseAddress: LPCVOID,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UnmapViewOfFile\0")) ) } )
}
pub fn GetLargePageMinimum() -> Option<unsafe fn() -> SIZE_T> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetLargePageMinimum\0")) ) } )
}
pub fn GetProcessWorkingSetSizeEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpMinimumWorkingSetSize: PSIZE_T,
    lpMaximumWorkingSetSize: PSIZE_T,
    Flags: PDWORD,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetProcessWorkingSetSizeEx\0")) ) } )
}
pub fn SetProcessWorkingSetSizeEx() -> Option<unsafe fn(
    hProcess: HANDLE,
    dwMinimumWorkingSetSize: SIZE_T,
    dwMaximumWorkingSetSize: SIZE_T,
    Flags: DWORD,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetProcessWorkingSetSizeEx\0")) ) } )
}
pub fn VirtualLock() -> Option<unsafe fn(
    lpAddress: LPVOID,
    dwSize: SIZE_T,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualLock\0")) ) } )
}
pub fn VirtualUnlock() -> Option<unsafe fn(
    lpAddress: LPVOID,
    dwSize: SIZE_T,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualUnlock\0")) ) } )
}
pub fn GetWriteWatch() -> Option<unsafe fn(
    dwFlags: DWORD,
    lpBaseAddress: PVOID,
    dwRegionSize: SIZE_T,
    lpAddresses: *mut PVOID,
    lpdwCount: *mut ULONG_PTR,
    lpdwGranularity: LPDWORD,
) -> UINT> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetWriteWatch\0")) ) } )
}
pub fn ResetWriteWatch() -> Option<unsafe fn(
    lpBaseAddress: LPVOID,
    dwRegionSize: SIZE_T,
) -> UINT> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ResetWriteWatch\0")) ) } )
}
pub fn CreateMemoryResourceNotification() -> Option<unsafe fn(
    NotificationType: MEMORY_RESOURCE_NOTIFICATION_TYPE,
) -> HANDLE> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateMemoryResourceNotification\0")) ) } )
}
pub fn QueryMemoryResourceNotification() -> Option<unsafe fn(
    ResourceNotificationHandle: HANDLE,
    ResourceState: PBOOL,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QueryMemoryResourceNotification\0")) ) } )
}
pub fn GetSystemFileCacheSize() -> Option<unsafe fn(
    lpMinimumFileCacheSize: PSIZE_T,
    lpMaximumFileCacheSize: PSIZE_T,
    lpFlags: PDWORD,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSystemFileCacheSize\0")) ) } )
}
pub fn SetSystemFileCacheSize() -> Option<unsafe fn(
    MinimumFileCacheSize: SIZE_T,
    MaximumFileCacheSize: SIZE_T,
    Flags: DWORD,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSystemFileCacheSize\0")) ) } )
}
pub fn CreateFileMappingNumaW() -> Option<unsafe fn(
    hFile: HANDLE,
    lpFileMappingAttributes: LPSECURITY_ATTRIBUTES,
    flProtect: DWORD,
    dwMaximumSizeHigh: DWORD,
    dwMaximumSizeLow: DWORD,
    lpName: LPCWSTR,
    nndPreferred: DWORD,
) -> HANDLE> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateFileMappingNumaW\0")) ) } )
}
pub fn PrefetchVirtualMemory() -> Option<unsafe fn(
    hProcess: HANDLE,
    NumberOfEntries: ULONG_PTR,
    VirtualAddresses: PWIN32_MEMORY_RANGE_ENTRY,
    Flags: ULONG,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("PrefetchVirtualMemory\0")) ) } )
}
pub fn CreateFileMappingFromApp() -> Option<unsafe fn(
    hFile: HANDLE,
    SecurityAttributes: PSECURITY_ATTRIBUTES,
    PageProtection: ULONG,
    MaximumSize: ULONG64,
    Name: PCWSTR,
) -> HANDLE> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateFileMappingFromApp\0")) ) } )
}
pub fn MapViewOfFileFromApp() -> Option<unsafe fn(
    hFileMappingObject: HANDLE,
    DesiredAccess: ULONG,
    FileOffset: ULONG64,
    NumberOfBytesToMap: SIZE_T,
) -> PVOID> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MapViewOfFileFromApp\0")) ) } )
}
pub fn UnmapViewOfFileEx() -> Option<unsafe fn(
    BaseAddress: PVOID,
    UnmapFlags: ULONG,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UnmapViewOfFileEx\0")) ) } )
}
pub fn AllocateUserPhysicalPages() -> Option<unsafe fn(
    hProcess: HANDLE,
    NumberOfPages: PULONG_PTR,
    PageArray: PULONG_PTR,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AllocateUserPhysicalPages\0")) ) } )
}
pub fn FreeUserPhysicalPages() -> Option<unsafe fn(
    hProcess: HANDLE,
    NumberOfPages: PULONG_PTR,
    PageArray: PULONG_PTR,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FreeUserPhysicalPages\0")) ) } )
}
pub fn MapUserPhysicalPages() -> Option<unsafe fn(
    VirtualAddress: PVOID,
    NumberOfPages: ULONG_PTR,
    PageArray: PULONG_PTR,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MapUserPhysicalPages\0")) ) } )
}
pub fn AllocateUserPhysicalPagesNuma() -> Option<unsafe fn(
    hProcess: HANDLE,
    NumberOfPages: PULONG_PTR,
    PageArray: PULONG_PTR,
    nndPreferred: DWORD,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AllocateUserPhysicalPagesNuma\0")) ) } )
}
pub fn VirtualAllocExNuma() -> Option<unsafe fn(
    hProcess: HANDLE,
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
    nndPreferred: DWORD,
) -> LPVOID> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualAllocExNuma\0")) ) } )
}
pub fn GetMemoryErrorHandlingCapabilities() -> Option<unsafe fn(
    Capabilities: PULONG,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetMemoryErrorHandlingCapabilities\0")) ) } )
}
pub fn RegisterBadMemoryNotification() -> Option<unsafe fn(
    Callback: PBAD_MEMORY_CALLBACK_ROUTINE,
) -> PVOID> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RegisterBadMemoryNotification\0")) ) } )
}
pub fn UnregisterBadMemoryNotification() -> Option<unsafe fn(
    RegistrationHandle: PVOID,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UnregisterBadMemoryNotification\0")) ) } )
}
pub fn OfferVirtualMemory() -> Option<unsafe fn(
    VirtualAddress: PVOID,
    Size: SIZE_T,
    Priority: OFFER_PRIORITY,
) -> DWORD> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OfferVirtualMemory\0")) ) } )
}
pub fn ReclaimVirtualMemory() -> Option<unsafe fn(
    VirtualAddress: *const c_void,
    Size: SIZE_T,
) -> DWORD> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ReclaimVirtualMemory\0")) ) } )
}
pub fn DiscardVirtualMemory() -> Option<unsafe fn(
    VirtualAddress: PVOID,
    Size: SIZE_T,
) -> DWORD> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DiscardVirtualMemory\0")) ) } )
}
pub fn VirtualAllocFromApp() -> Option<unsafe fn(
    BaseAddress: PVOID,
    Size: SIZE_T,
    AllocationType: ULONG,
    Protection: ULONG,
) -> PVOID> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualAllocFromApp\0")) ) } )
}
pub fn VirtualProtectFromApp() -> Option<unsafe fn(
    Address: PVOID,
    Size: SIZE_T,
    NewProtection: ULONG,
    OldProtection: PULONG,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("VirtualProtectFromApp\0")) ) } )
}
pub fn OpenFileMappingFromApp() -> Option<unsafe fn(
    DesiredAccess: ULONG,
    InheritHandle: BOOL,
    Name: PCWSTR,
) -> HANDLE> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("OpenFileMappingFromApp\0")) ) } )
}
pub fn UnmapViewOfFile2() -> Option<unsafe fn(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    UnmapFlags: ULONG,
) -> BOOL> {
	Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("UnmapViewOfFile2\0")) ) } )
}
