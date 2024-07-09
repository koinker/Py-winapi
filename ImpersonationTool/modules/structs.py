import ctypes

from ctypes.wintypes import DWORD, LPVOID, BOOL, HANDLE, WORD, LPWSTR, LPBYTE

class STARTUPINFO(ctypes.Structure):
    #params
    _fields_ = [                    
        ("cb",DWORD),
        ("lpReserved",LPWSTR),
        ("lpDesktop",LPWSTR),
        ("lpTitle",LPWSTR),
        ("dwX",DWORD),
        ("dwY",DWORD),
        ("dwXSize",DWORD),
        ("dwYSize",DWORD),
        ("dwXCountChars",DWORD),
        ("dwYCountChars",DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",DWORD),
        ("wShowWindow",WORD),
        ("cbReserved2",WORD),
        ("lpReserved2",LPBYTE),
        ("hStdInput",HANDLE),
        ("hStdOutput",HANDLE),
        ("hStdError",HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    #create list of parameters
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL),
        
    ]


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", DWORD),
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]

class PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Control", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES)
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES)
    ]

class TokenRights(ctypes.Structure):
    _fields_ = [
        ("STANDARD_RIGHTS_REQUIRED", DWORD),
        ("STANDARD_RIGHTS_READ", DWORD),
        ("TOKEN_ASSIGN_PRIMARY", DWORD),
        ("TOKEN_DUPLICATE", DWORD),
        ("TOKEN_IMPERSONATION", DWORD),
        ("TOKEN_QUERY", DWORD),
        ("TOKEN_QUERY_SOURCE", DWORD),
        ("TOKEN_ADJUST_PRIVILEGES", DWORD),
        ("TOKEN_ADJUST_GROUPS", DWORD),
        ("TOKEN_ADJUST_DEFAULT", DWORD),
        ("TOKEN_ADJUST_SESSIONID", DWORD),
        ("TOKEN_READ", DWORD),
        ("TOKEN_ALL_ACCESS", DWORD),
    ]

TokenRights.STANDARD_RIGHTS_REQUIRED = 0x000F0000
TokenRights.STANDARD_RIGHTS_READ = 0x00020000
TokenRights.TOKEN_ASSIGN_PRIMARY = 0x0001
TokenRights.TOKEN_DUPLICATE = 0x0002
TokenRights.TOKEN_IMPERSONATION = 0x0004
TokenRights.TOKEN_QUERY = 0x0008
TokenRights.TOKEN_QUERY_SOURCE = 0x0010
TokenRights.TOKEN_ADJUST_PRIVILEGES = 0x0020
TokenRights.TOKEN_ADJUST_GROUPS = 0x0040
TokenRights.TOKEN_ADJUST_DEFAULT = 0x0080
TokenRights.TOKEN_ADJUST_SESSIONID = 0x0100
TokenRights.TOKEN_READ = (TokenRights.STANDARD_RIGHTS_READ | TokenRights.TOKEN_QUERY)
TokenRights.TOKEN_ALL_ACCESS = (
    TokenRights.STANDARD_RIGHTS_REQUIRED |
    TokenRights.TOKEN_ASSIGN_PRIMARY |
    TokenRights.TOKEN_DUPLICATE |
    TokenRights.TOKEN_IMPERSONATION |
    TokenRights.TOKEN_QUERY |
    TokenRights.TOKEN_QUERY_SOURCE |
    TokenRights.TOKEN_ADJUST_PRIVILEGES |
    TokenRights.TOKEN_ADJUST_GROUPS |
    TokenRights.TOKEN_ADJUST_DEFAULT |
    TokenRights.TOKEN_ADJUST_SESSIONID
)