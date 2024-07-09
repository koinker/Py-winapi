import ctypes

from ctypes.wintypes import DWORD

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