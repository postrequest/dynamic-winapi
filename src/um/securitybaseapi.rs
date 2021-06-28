#![allow(non_snake_case)]
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::{
    BOOL, BYTE, DWORD, LPBOOL, LPDWORD, LPVOID, PBOOL, PDWORD, PUCHAR, PULONG, UCHAR, ULONG
};
use winapi::um::minwinbase::LPSECURITY_ATTRIBUTES;
use winapi::um::winnt::{
    ACL_INFORMATION_CLASS, AUDIT_EVENT_TYPE, BOOLEAN, HANDLE, LONG, LPCWSTR, LPWSTR, PACL,
    PCLAIM_SECURITY_ATTRIBUTES_INFORMATION, PCWSTR, PGENERIC_MAPPING, PHANDLE, PLUID,
    PLUID_AND_ATTRIBUTES, POBJECT_TYPE_LIST, PPRIVILEGE_SET, PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR_CONTROL, PSID, PSID_AND_ATTRIBUTES, PSID_IDENTIFIER_AUTHORITY,
    PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PVOID, SECURITY_DESCRIPTOR_CONTROL,
    SECURITY_IMPERSONATION_LEVEL, SECURITY_INFORMATION, TOKEN_INFORMATION_CLASS, TOKEN_TYPE,
    WELL_KNOWN_SID_TYPE
};

use crate::get_k32_fn;

pub fn AccessCheck() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    ClientToken: HANDLE,
    DesiredAccess: DWORD,
    GenericMapping: PGENERIC_MAPPING,
    PrivilegeSet: PPRIVILEGE_SET,
    PrivilegeSetLength: LPDWORD,
    GrantedAccess: LPDWORD,
    AccessStatus: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AccessCheck\0")) ) } )
}
pub fn AccessCheckAndAuditAlarmW() -> Option<unsafe fn(
    SubsystemName: LPCWSTR,
    HandleId: LPVOID,
    ObjectTypeName: LPWSTR,
    ObjectName: LPWSTR,
    SecurityDescriptor: PSECURITY_DESCRIPTOR,
    DesiredAccess: DWORD,
    GenericMapping: PGENERIC_MAPPING,
    ObjectCreation: BOOL,
    GrantedAccess: LPDWORD,
    AccessStatus: LPBOOL,
    pfGenerateOnClose: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AccessCheckAndAuditAlarmW\0")) ) } )
}
pub fn AccessCheckByType() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    PrincipalSelfSid: PSID,
    ClientToken: HANDLE,
    DesiredAccess: DWORD,
    ObjectTypeList: POBJECT_TYPE_LIST,
    ObjectTypeListLength: DWORD,
    GenericMapping: PGENERIC_MAPPING,
    PrivilegeSet: PPRIVILEGE_SET,
    PrivilegeSetLength: LPDWORD,
    GrantedAccess: LPDWORD,
    AccessStatus: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AccessCheckByType\0")) ) } )
}
pub fn AccessCheckByTypeResultList() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    PrincipalSelfSid: PSID,
    ClientToken: HANDLE,
    DesiredAccess: DWORD,
    ObjectTypeList: POBJECT_TYPE_LIST,
    ObjectTypeListLength: DWORD,
    GenericMapping: PGENERIC_MAPPING,
    PrivilegeSet: PPRIVILEGE_SET,
    PrivilegeSetLength: LPDWORD,
    GrantedAccessList: LPDWORD,
    AccessStatusList: LPDWORD,
    ) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AccessCheckByTypeResultList\0")) ) } )
}
pub fn AccessCheckByTypeAndAuditAlarmW() -> Option<unsafe fn(
    SubsystemName: LPCWSTR,
    HandleId: LPVOID,
    ObjectTypeName: LPWSTR,
    ObjectName: LPCWSTR,
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    PrincipalSelfSid: PSID,
    DesiredAccess: DWORD,
    AuditType: AUDIT_EVENT_TYPE,
    Flags: DWORD,
    ObjectTypeList: POBJECT_TYPE_LIST,
    ObjectTypeListLength: DWORD,
    GenericMapping: PGENERIC_MAPPING,
    ObjectCreation: BOOL,
    GrantedAccess: LPDWORD,
    AccessStatus: LPBOOL,
    pfGenerateOnClose: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AccessCheckByTypeAndAuditAlarmW\0")) ) } )
}
pub fn AccessCheckByTypeResultListAndAuditAlarmW() -> Option<unsafe fn(
    SubsystemName: LPCWSTR,
    HandleId: LPVOID,
    ObjectTypeName: LPCWSTR,
    ObjectName: LPCWSTR,
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    PrincipalSelfSid: PSID,
    DesiredAccess: DWORD,
    AuditType: AUDIT_EVENT_TYPE,
    Flags: DWORD,
    ObjectTypeList: POBJECT_TYPE_LIST,
    ObjectTypeListLength: DWORD,
    GenericMapping: PGENERIC_MAPPING,
    ObjectCreation: BOOL,
    GrantedAccess: LPDWORD,
    AccessStatusList: LPDWORD,
    pfGenerateOnClose: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AccessCheckByTypeResultListAndAuditAlarmW\0")) ) } )
}
pub fn AccessCheckByTypeResultListAndAuditAlarmByHandleW() -> Option<unsafe fn(
    SubsystemName: LPCWSTR,
    HandleId: LPVOID,
    ClientToken: HANDLE,
    ObjectTypeName: LPCWSTR,
    ObjectName: LPCWSTR,
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    PrincipalSelfSid: PSID,
    DesiredAccess: DWORD,
    AuditType: AUDIT_EVENT_TYPE,
    Flags: DWORD,
    ObjectTypeList: POBJECT_TYPE_LIST,
    ObjectTypeListLength: DWORD,
    GenericMapping: PGENERIC_MAPPING,
    ObjectCreation: BOOL,
    GrantedAccess: LPDWORD,
    AccessStatusList: LPDWORD,
    pfGenerateOnClose: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AccessCheckByTypeResultListAndAuditAlarmByHandleW\0")) ) } )
}
pub fn AddAccessAllowedAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AccessMask: DWORD,
    pSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAccessAllowedAce\0")) ) } )
}
pub fn AddAccessAllowedAceEx() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AceFlags: DWORD,
    AccessMask: DWORD,
    pSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAccessAllowedAceEx\0")) ) } )
}
pub fn AddAccessAllowedObjectAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AceFlags: DWORD,
    AccessMask: DWORD,
    ObjectTypeGuid: *mut GUID,
    InheritedObjectTypeGuid: *mut GUID,
    pSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAccessAllowedObjectAce\0")) ) } )
}
pub fn AddAccessDeniedAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AccessMask: DWORD,
    pSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAccessDeniedAce\0")) ) } )
}
pub fn AddAccessDeniedAceEx() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AceFlags: DWORD,
    AccessMask: DWORD,
    pSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAccessDeniedAceEx\0")) ) } )
}
pub fn AddAccessDeniedObjectAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AceFlags: DWORD,
    AccessMask: DWORD,
    ObjectTypeGuid: *mut GUID,
    InheritedObjectTypeGuid: *mut GUID,
    pSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAccessDeniedObjectAce\0")) ) } )
}
pub fn AddAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    dwStartingAceIndex: DWORD,
    pAceList: LPVOID,
    nAceListLength: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAce\0")) ) } )
}
pub fn AddAuditAccessAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    dwAccessMask: DWORD,
    pSid: PSID,
    bAuditSuccess: BOOL,
    bAuditFailure: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAuditAccessAce\0")) ) } )
}
pub fn AddAuditAccessAceEx() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AceFlags: DWORD,
    dwAccessMask: DWORD,
    pSid: PSID,
    bAuditSuccess: BOOL,
    bAuditFailure: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAuditAccessAceEx\0")) ) } )
}
pub fn AddAuditAccessObjectAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AceFlags: DWORD,
    AccessMask: DWORD,
    ObjectTypeGuid: *mut GUID,
    InheritedObjectTypeGuid: *mut GUID,
    pSid: PSID,
    bAuditSuccess: BOOL,
    bAuditFailure: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddAuditAccessObjectAce\0")) ) } )
}
pub fn AddMandatoryAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AceFlags: DWORD,
    MandatoryPolicy: DWORD,
    pLabelSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddMandatoryAce\0")) ) } )
}
pub fn AddResourceAttributeAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AceFlags: DWORD,
    AccessMask: DWORD,
    pSid: PSID,
    pAttributeInfo: PCLAIM_SECURITY_ATTRIBUTES_INFORMATION,
    pReturnLength: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddResourceAttributeAce\0")) ) } )
}
pub fn AddScopedPolicyIDAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceRevision: DWORD,
    AceFlags: DWORD,
    AccessMask: DWORD,
    pSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AddScopedPolicyIDAce\0")) ) } )
}
pub fn AdjustTokenGroups() -> Option<unsafe fn(
    TokenHandle: HANDLE,
    ResetToDefault: BOOL,
    NewState: PTOKEN_GROUPS,
    BufferLength: DWORD,
    PreviousState: PTOKEN_GROUPS,
    ReturnLength: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AdjustTokenGroups\0")) ) } )
}
pub fn AdjustTokenPrivileges() -> Option<unsafe fn(
    TokenHandle: HANDLE,
    DisableAllPrivileges: BOOL,
    NewState: PTOKEN_PRIVILEGES,
    BufferLength: DWORD,
    PreviousState: PTOKEN_PRIVILEGES,
    ReturnLength: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AdjustTokenPrivileges\0")) ) } )
}
pub fn AllocateAndInitializeSid() -> Option<unsafe fn(
    pIdentifierAuthoirity: PSID_IDENTIFIER_AUTHORITY,
    nSubAuthorityCount: BYTE,
    dwSubAuthority0: DWORD,
    dwSubAuthority1: DWORD,
    dwSubAuthority2: DWORD,
    dwSubAuthority3: DWORD,
    dwSubAuthority4: DWORD,
    dwSubAuthority5: DWORD,
    dwSubAuthority6: DWORD,
    dwSubAuthority7: DWORD,
    pSid: *mut PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AllocateAndInitializeSid\0")) ) } )
}
pub fn AllocateLocallyUniqueId() -> Option<unsafe fn(
    Luid: PLUID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AllocateLocallyUniqueId\0")) ) } )
}
pub fn AreAllAccessesGranted() -> Option<unsafe fn(
    GrantedAccess: DWORD,
    DesiredAccess: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AreAllAccessesGranted\0")) ) } )
}
pub fn AreAnyAccessesGranted() -> Option<unsafe fn(
    GrantedAccess: DWORD,
    DesiredAccess: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("AreAnyAccessesGranted\0")) ) } )
}
pub fn CheckTokenMembership() -> Option<unsafe fn(
    TokenHandle: HANDLE,
    SidToCheck: PSID,
    IsMember: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CheckTokenMembership\0")) ) } )
}
pub fn CheckTokenCapability() -> Option<unsafe fn(
    TokenHandle: HANDLE,
    CapabilitySidToCheck: PSID,
    HasCapability: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CheckTokenCapability\0")) ) } )
}
pub fn GetAppContainerAce() -> Option<unsafe fn(
    Acl: PACL,
    StartingAceIndex: DWORD,
    AppContainerAce: *mut PVOID,
    AppContainerAceIndex: *mut DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetAppContainerAce\0")) ) } )
}
pub fn CheckTokenMembershipEx() -> Option<unsafe fn(
    TokenHandle: HANDLE,
    SidToCheck: PSID,
    Flags: DWORD,
    IsMember: PBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CheckTokenMembershipEx\0")) ) } )
}
pub fn ConvertToAutoInheritPrivateObjectSecurity() -> Option<unsafe fn(
    ParentDescriptor: PSECURITY_DESCRIPTOR,
    CurrentSecurityDescriptor: PSECURITY_DESCRIPTOR,
    NewSecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
    ObjectType: *mut GUID,
    IsDirectoryObject: BOOLEAN,
    GenericMapping: PGENERIC_MAPPING,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ConvertToAutoInheritPrivateObjectSecurity\0")) ) } )
}
pub fn CopySid() -> Option<unsafe fn(
    nDestinationSidLength: DWORD,
    pDestinationSid: PSID,
    pSourceSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CopySid\0")) ) } )
}
pub fn CreatePrivateObjectSecurity() -> Option<unsafe fn(
    ParentDescriptor: PSECURITY_DESCRIPTOR,
    CreatorDescriptor: PSECURITY_DESCRIPTOR,
    NewDescriptor: *mut PSECURITY_DESCRIPTOR,
    IsDirectoryObject: BOOL,
    Token: HANDLE,
    GenericMapping: PGENERIC_MAPPING,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreatePrivateObjectSecurity\0")) ) } )
}
pub fn CreatePrivateObjectSecurityEx() -> Option<unsafe fn(
    ParentDescriptor: PSECURITY_DESCRIPTOR,
    CreatorDescriptor: PSECURITY_DESCRIPTOR,
    NewSecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
    ObjectType: *mut GUID,
    IsContainerObject: BOOL,
    AutoInheritFlags: ULONG,
    Token: HANDLE,
    GenericMapping: PGENERIC_MAPPING,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreatePrivateObjectSecurityEx\0")) ) } )
}
pub fn CreatePrivateObjectSecurityWithMultipleInheritance() -> Option<unsafe fn(
    ParentDescriptor: PSECURITY_DESCRIPTOR,
    CreatorDescriptor: PSECURITY_DESCRIPTOR,
    NewSecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
    ObjectTypes: *mut *mut GUID,
    GuidCount: ULONG,
    IsContainerObject: BOOL,
    AutoInheritFlags: ULONG,
    Token: HANDLE,
    GenericMapping: PGENERIC_MAPPING,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreatePrivateObjectSecurityWithMultipleInheritance\0")) ) } )
}
pub fn CreateRestrictedToken() -> Option<unsafe fn(
    ExistingTokenHandle: HANDLE,
    Flags: DWORD,
    DisableSidCount: DWORD,
    SidsToDisable: PSID_AND_ATTRIBUTES,
    DeletePrivilegeCount: DWORD,
    PrivilegesToDelete: PLUID_AND_ATTRIBUTES,
    RestrictedSidCount: DWORD,
    SidsToRestrict: PSID_AND_ATTRIBUTES,
    NewTokenHandle: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateRestrictedToken\0")) ) } )
}
pub fn CreateWellKnownSid() -> Option<unsafe fn(
    WellKnownSidType: WELL_KNOWN_SID_TYPE,
    DomainSid: PSID,
    pSid: PSID,
    cbSid: *mut DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CreateWellKnownSid\0")) ) } )
}
pub fn EqualDomainSid() -> Option<unsafe fn(
    pSid1: PSID,
    pSid2: PSID,
    pfEqual: *mut BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EqualDomainSid\0")) ) } )
}
pub fn DeleteAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceIndex: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeleteAce\0")) ) } )
}
pub fn DestroyPrivateObjectSecurity() -> Option<unsafe fn(
    ObjectDescriptor: *mut PSECURITY_DESCRIPTOR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DestroyPrivateObjectSecurity\0")) ) } )
}
pub fn DuplicateToken() -> Option<unsafe fn(
    ExistingTokenHandle: HANDLE,
    ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
    DuplicateTokenHandle: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DuplicateToken\0")) ) } )
}
pub fn DuplicateTokenEx() -> Option<unsafe fn(
    hExistingToken: HANDLE,
    dwDesiredAccess: DWORD,
    lpTokenAttributes: LPSECURITY_ATTRIBUTES,
    ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
    TokenType: TOKEN_TYPE,
    phNewToken: PHANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DuplicateTokenEx\0")) ) } )
}
pub fn EqualPrefixSid() -> Option<unsafe fn(
    pSid1: PSID,
    pSid2: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EqualPrefixSid\0")) ) } )
}
pub fn EqualSid() -> Option<unsafe fn(
    pSid1: PSID,
    pSid2: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("EqualSid\0")) ) } )
}
pub fn FindFirstFreeAce() -> Option<unsafe fn(
    pAcl: PACL,
    pAce: *mut LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FindFirstFreeAce\0")) ) } )
}
pub fn FreeSid() -> Option<unsafe fn(
    pSid: PSID,
) -> PVOID> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("FreeSid\0")) ) } )
}
pub fn GetAce() -> Option<unsafe fn(
    pAcl: PACL,
    dwAceIndex: DWORD,
    pAce: *mut LPVOID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetAce\0")) ) } )
}
pub fn GetAclInformation() -> Option<unsafe fn(
    pAcl: PACL,
    pAclInformtion: LPVOID,
    nAclInformationLength: DWORD,
    dwAclInformationClass: ACL_INFORMATION_CLASS,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetAclInformation\0")) ) } )
}
pub fn GetFileSecurityW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    RequestedInformation: SECURITY_INFORMATION,
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    nLength: DWORD,
    lpnLengthNeeded: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetFileSecurityW\0")) ) } )
}
pub fn GetKernelObjectSecurity() -> Option<unsafe fn(
    Handle: HANDLE,
    RequestedInformation: SECURITY_INFORMATION,
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    nLength: DWORD,
    lpnLengthNeeded: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetKernelObjectSecurity\0")) ) } )
}
pub fn GetLengthSid() -> Option<unsafe fn(
    pSid: PSID,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetLengthSid\0")) ) } )
}
pub fn GetPrivateObjectSecurity() -> Option<unsafe fn(
    ObjectDescriptor: PSECURITY_DESCRIPTOR,
    SecurityInformation: SECURITY_INFORMATION,
    ResultantDescriptor: PSECURITY_DESCRIPTOR,
    DescriptorLength: DWORD,
    ReturnLength: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetPrivateObjectSecurity\0")) ) } )
}
pub fn GetSecurityDescriptorControl() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    pControl: PSECURITY_DESCRIPTOR_CONTROL,
    lpdwRevision: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSecurityDescriptorControl\0")) ) } )
}
pub fn GetSecurityDescriptorDacl() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    lpbDaclPresent: LPBOOL,
    pDacl: *mut PACL,
    lpbDaclDefaulted: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSecurityDescriptorDacl\0")) ) } )
}
pub fn GetSecurityDescriptorGroup() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    pGroup: *mut PSID,
    lpbGroupDefaulted: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSecurityDescriptorGroup\0")) ) } )
}
pub fn GetSecurityDescriptorLength() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSecurityDescriptorLength\0")) ) } )
}
pub fn GetSecurityDescriptorOwner() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    pOwner: *mut PSID,
    lpbOwnerDefaulted: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSecurityDescriptorOwner\0")) ) } )
}
pub fn GetSecurityDescriptorRMControl() -> Option<unsafe fn(
    SecurityDescriptor: PSECURITY_DESCRIPTOR,
    RMControl: PUCHAR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSecurityDescriptorRMControl\0")) ) } )
}
pub fn GetSecurityDescriptorSacl() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    lpbSaclPresent: LPBOOL,
    pSacl: *mut PACL,
    lpbSaclDefaulted: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSecurityDescriptorSacl\0")) ) } )
}
pub fn GetSidIdentifierAuthority() -> Option<unsafe fn(
    pSid: PSID,
) -> PSID_IDENTIFIER_AUTHORITY> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSidIdentifierAuthority\0")) ) } )
}
pub fn GetSidLengthRequired() -> Option<unsafe fn(
    nSubAuthorityCount: UCHAR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSidLengthRequired\0")) ) } )
}
pub fn GetSidSubAuthority() -> Option<unsafe fn(
    pSid: PSID,
    nSubAuthority: DWORD,
) -> PDWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSidSubAuthority\0")) ) } )
}
pub fn GetSidSubAuthorityCount() -> Option<unsafe fn(
    pSid: PSID,
) -> PUCHAR> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetSidSubAuthorityCount\0")) ) } )
}
pub fn GetTokenInformation() -> Option<unsafe fn(
    TokenHandle: HANDLE,
    TokenInformationClass: TOKEN_INFORMATION_CLASS,
    TokenInformation: LPVOID,
    TokenInformationLength: DWORD,
    ReturnLength: PDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetTokenInformation\0")) ) } )
}
pub fn GetWindowsAccountDomainSid() -> Option<unsafe fn(
    pSid: PSID,
    pDomainSid: PSID,
    cbDomainSid: *mut DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetWindowsAccountDomainSid\0")) ) } )
}
pub fn ImpersonateAnonymousToken() -> Option<unsafe fn(
    ThreadHandle: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ImpersonateAnonymousToken\0")) ) } )
}
pub fn ImpersonateLoggedOnUser() -> Option<unsafe fn(
    hToken: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ImpersonateLoggedOnUser\0")) ) } )
}
pub fn ImpersonateSelf() -> Option<unsafe fn(
    ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ImpersonateSelf\0")) ) } )
}
pub fn InitializeAcl() -> Option<unsafe fn(
    pAcl: PACL,
    nAclLength: DWORD,
    dwAclRevision: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("InitializeAcl\0")) ) } )
}
pub fn InitializeSecurityDescriptor() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    dwRevision: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("InitializeSecurityDescriptor\0")) ) } )
}
pub fn InitializeSid() -> Option<unsafe fn(
    Sid: PSID,
    pIdentifierAuthority: PSID_IDENTIFIER_AUTHORITY,
    nSubAuthorityCount: BYTE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("InitializeSid\0")) ) } )
}
pub fn IsTokenRestricted() -> Option<unsafe fn(
    TokenHandle: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsTokenRestricted\0")) ) } )
}
pub fn IsValidAcl() -> Option<unsafe fn(
    pAcl: PACL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsValidAcl\0")) ) } )
}
pub fn IsValidSecurityDescriptor() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsValidSecurityDescriptor\0")) ) } )
}
pub fn IsValidSid() -> Option<unsafe fn(
    pSid: PSID,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsValidSid\0")) ) } )
}
pub fn IsWellKnownSid() -> Option<unsafe fn(
    pSid: PSID,
    WellKnownSidType: WELL_KNOWN_SID_TYPE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("IsWellKnownSid\0")) ) } )
}
pub fn MakeAbsoluteSD() -> Option<unsafe fn(
    pSelfRelativeSD: PSECURITY_DESCRIPTOR,
    pAbsoluteSD: PSECURITY_DESCRIPTOR,
    lpdwAbsoluteSDSize: LPDWORD,
    pDacl: PACL,
    lpdwDaclSize: LPDWORD,
    pSacl: PACL,
    lpdwSaclSize: LPDWORD,
    pOwner: PSID,
    lpdwOwnerSize: LPDWORD,
    pPrimaryGroup: PSID,
    lpdwPrimaryGroupSize: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MakeAbsoluteSD\0")) ) } )
}
pub fn MakeSelfRelativeSD() -> Option<unsafe fn(
    pAbsoluteSD: PSECURITY_DESCRIPTOR,
    pSelfRelativeSD: PSECURITY_DESCRIPTOR,
    lpdwBufferLength: LPDWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MakeSelfRelativeSD\0")) ) } )
}
pub fn MapGenericMask() -> Option<unsafe fn(
    AccessMask: PDWORD,
    GenericMapping: PGENERIC_MAPPING,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("MapGenericMask\0")) ) } )
}
pub fn ObjectCloseAuditAlarmW() -> Option<unsafe fn(
    SubsystemName: LPCWSTR,
    HandleId: LPVOID,
    GenerateOnClose: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ObjectCloseAuditAlarmW\0")) ) } )
}
pub fn ObjectDeleteAuditAlarmW() -> Option<unsafe fn(
    SubsystemName: LPCWSTR,
    HandleId: LPVOID,
    GenerateOnClose: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ObjectDeleteAuditAlarmW\0")) ) } )
}
pub fn ObjectOpenAuditAlarmW() -> Option<unsafe fn(
    SubsystemName: LPCWSTR,
    HandleId: LPVOID,
    ObjectTypeName: LPWSTR,
    ObjectName: LPWSTR,
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    ClientToken: HANDLE,
    DesiredAccess: DWORD,
    GrantedAccess: DWORD,
    Privileges: PPRIVILEGE_SET,
    ObjectCreation: BOOL,
    AccessGranted: BOOL,
    GenerateOnClose: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ObjectOpenAuditAlarmW\0")) ) } )
}
pub fn ObjectPrivilegeAuditAlarmW() -> Option<unsafe fn(
    SubsystemName: LPCWSTR,
    HandleId: LPVOID,
    ClientToken: HANDLE,
    DesiredAccess: DWORD,
    Privileges: PPRIVILEGE_SET,
    AccessGranted: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("ObjectPrivilegeAuditAlarmW\0")) ) } )
}
pub fn PrivilegeCheck() -> Option<unsafe fn(
    ClientToken: HANDLE,
    RequiredPrivileges: PPRIVILEGE_SET,
    pfResult: LPBOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("PrivilegeCheck\0")) ) } )
}
pub fn PrivilegedServiceAuditAlarmW() -> Option<unsafe fn(
    SubsystemName: LPCWSTR,
    ServiceName: LPCWSTR,
    ClientToken: HANDLE,
    Privileges: PPRIVILEGE_SET,
    AccessGranted: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("PrivilegedServiceAuditAlarmW\0")) ) } )
}
pub fn QuerySecurityAccessMask() -> Option<unsafe fn(
    SecurityInformation: SECURITY_INFORMATION,
    DesiredAccess: LPDWORD,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("QuerySecurityAccessMask\0")) ) } )
}
pub fn RevertToSelf() -> Option<unsafe fn() -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("RevertToSelf(\0")) ) } )
}
pub fn SetAclInformation() -> Option<unsafe fn(
    pAcl: PACL,
    pAclInformation: LPVOID,
    nAclInformationLength: DWORD,
    dwAclInfomrationClass: ACL_INFORMATION_CLASS,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetAclInformation\0")) ) } )
}
pub fn SetFileSecurityW() -> Option<unsafe fn(
    lpFileName: LPCWSTR,
    SecurityInformation: SECURITY_INFORMATION,
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetFileSecurityW\0")) ) } )
}
pub fn SetKernelObjectSecurity() -> Option<unsafe fn(
    Handle: HANDLE,
    SecurityInformation: SECURITY_INFORMATION,
    SecurityDescriptor: PSECURITY_DESCRIPTOR,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetKernelObjectSecurity\0")) ) } )
}
pub fn SetPrivateObjectSecurity() -> Option<unsafe fn(
    SecurityInformation: SECURITY_INFORMATION,
    ModificationDescriptor: PSECURITY_DESCRIPTOR,
    ObjectsSecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
    GenericMapping: PGENERIC_MAPPING,
    Token: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetPrivateObjectSecurity\0")) ) } )
}
pub fn SetPrivateObjectSecurityEx() -> Option<unsafe fn(
    SecurityInformation: SECURITY_INFORMATION,
    ModificationDescriptor: PSECURITY_DESCRIPTOR,
    ObjectsSecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
    AutoInheritFlags: ULONG,
    GenericMapping: PGENERIC_MAPPING,
    Token: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetPrivateObjectSecurityEx\0")) ) } )
}
pub fn SetSecurityAccessMask() -> Option<unsafe fn(
    SecurityInformation: SECURITY_INFORMATION,
    DesiredAccess: LPDWORD,
)> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSecurityAccessMask\0")) ) } )
}
pub fn SetSecurityDescriptorControl() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    ControlBitsOfInterest: SECURITY_DESCRIPTOR_CONTROL,
    ControlBitsToSet: SECURITY_DESCRIPTOR_CONTROL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSecurityDescriptorControl\0")) ) } )
}
pub fn SetSecurityDescriptorDacl() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    bDaclPresent: BOOL,
    pDacl: PACL,
    bDaclDefaulted: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSecurityDescriptorDacl\0")) ) } )
}
pub fn SetSecurityDescriptorGroup() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    pGroup: PSID,
    bGroupDefaulted: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSecurityDescriptorGroup\0")) ) } )
}
pub fn SetSecurityDescriptorOwner() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    pOwner: PSID,
    bOwnerDefaulted: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSecurityDescriptorOwner\0")) ) } )
}
pub fn SetSecurityDescriptorRMControl() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    RMControl: PUCHAR,
) -> DWORD> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSecurityDescriptorRMControl\0")) ) } )
}
pub fn SetSecurityDescriptorSacl() -> Option<unsafe fn(
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,
    bSaclPresent: BOOL,
    pSacl: PACL,
    bSaclDefaulted: BOOL,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetSecurityDescriptorSacl\0")) ) } )
}
pub fn SetTokenInformation() -> Option<unsafe fn(
    TokenHandle: HANDLE,
    TokenInformationClass: TOKEN_INFORMATION_CLASS,
    TokenInformation: LPVOID,
    TokenInformationLength: DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetTokenInformation\0")) ) } )
}
pub fn SetCachedSigningLevel() -> Option<unsafe fn(
    SourceFiles: PHANDLE,
    SourceFileCount: ULONG,
    Flags: ULONG,
    TargetFile: HANDLE,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("SetCachedSigningLevel\0")) ) } )
}
pub fn GetCachedSigningLevel() -> Option<unsafe fn(
    File: HANDLE,
    Flags: PULONG,
    SigningLevel: PULONG,
    Thumbprint: PUCHAR,
    ThumbprintSize: PULONG,
    ThumbprintAlgorithm: PULONG,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("GetCachedSigningLevel\0")) ) } )
}
pub fn CveEventWrite() -> Option<unsafe fn(
    CveId: PCWSTR,
    AdditionalDetails: PCWSTR,
) -> LONG> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("CveEventWrite\0")) ) } )
}
pub fn DeriveCapabilitySidsFromName() -> Option<unsafe fn(
    CapName: LPCWSTR,
    CapabilityGroupSids: *mut *mut PSID,
    CapabilityGroupSidCount: *mut DWORD,
    CapabilitySids: *mut *mut PSID,
    CapabilitySidCount: *mut DWORD,
) -> BOOL> {
    Some( unsafe { std::mem::transmute( get_k32_fn(obfstr::obfstr!("DeriveCapabilitySidsFromName\0")) ) } )
}
