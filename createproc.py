import ctypes
from ctypes.wintypes import HANDLE, DWORD, LPWSTR,WORD,LPBYTE

k_handle = ctypes.WinDLL("Kernel32.dll")
u_handle = ctypes.WinDLL("User32.dll")


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

#set flag values
lpApplicationName = "C:\\Windows\\System32\\cmd.exe"
lpCommandLine = None
lpProcessAttributes = None
lpThreadAttributes = None
lpEnvironment = None
lpCurrentDirectory = None
#create seperate console
dwCreationFlags = 0x00000010
bInheritHandle = False
lpProcessInformation = PROCESS_INFORMATION()
lpStartupInfo = STARTUPINFO()
#show window
lpStartupInfo.wShowWindow = 0x1
lpStartupInfo.dwFlags = 0x1
#create process params
execute = k_handle.CreateProcessW(
    lpApplicationName,
    lpCommandLine,
    lpProcessAttributes,
    lpThreadAttributes,
    bInheritHandle,
    dwCreationFlags,
    lpEnvironment,
    lpCurrentDirectory,

    ctypes.byref(lpStartupInfo),
    ctypes.byref(lpProcessInformation)
)

if execute > 0:
    print("Process is running")
else:
    print("Create Process failed with error code: {0}".format(k_handle.GetLastError()))

