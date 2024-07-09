import ctypes 

from modules.structs import LUID, LUID_AND_ATTRIBUTES, PRIVILEGE_SET, TOKEN_PRIVILEGES

#load dlls
u_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("Kernel32.dll")
a_handle = ctypes.WinDLL("Advapi32.dll")

#access rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0X00100000 | 0xFFF)

SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_DISABLED = 0x00000000


# Token Access Rights
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
					TOKEN_ASSIGN_PRIMARY     |
					TOKEN_DUPLICATE          |
					TOKEN_IMPERSONATION      |
					TOKEN_QUERY              |
					TOKEN_QUERY_SOURCE       |
					TOKEN_ADJUST_PRIVILEGES  |
					TOKEN_ADJUST_GROUPS      |
					TOKEN_ADJUST_DEFAULT     |
					TOKEN_ADJUST_SESSIONID)






lpWindowName = ctypes.c_char_p(input("Enter Window Name To Hook Into: ").encode('utf-8'))
hWnd = u_handle.FindWindowA(None, lpWindowName)

if hWnd == 0:
    print("Gain Window Handle filed with error code{0}".format(k_handle.GetLastError()))
else:
    print("[*] Gain Handle Successful...")

lpdwProcessId = ctypes.c_ulong()
pid = u_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))

if pid == 0:
    print("Get process pid failed with error code: {0}".format(k_handle.GetLastError()))
else:
    print("[*] Process Id: {0}".format(pid))


dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProccessId = lpdwProcessId

hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProccessId)

if hProcess <= 0:
    print("[!] Gain privileged handle failed with error code {0}".format(k_handle.GetLastError()))
else:
    print("[*] Privileged handle opened successfully...")

ProcessHandle = hProcess
DesiredAccess = TOKEN_ALL_ACCESS
TokenHandle = ctypes.c_void_p()

res = k_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

if res > 0:
    print("[*] Open Token Handle Successful...")
else:
    print("[!] Open privileged token handle failed eith error code {0}".format(k_handle.GetLastError()))
    
lpSystemName = None
lpName = input("Privilege to Modify: ")
lpLuid = LUID()

res = a_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(lpLuid))

if res > 0:
    print("[*] LUID found successfully...")
else:
    print("[!] Find LUID failed eith error code {0}".format(k_handle.GetLastError()))

print("[INFO] LUID High: {0} LUID Low: {1}".format(lpLuid.HighPart, lpLuid.LowPart))


requiredPrivs = PRIVILEGE_SET()
requiredPrivs.PrivilegeCount = 1
requiredPrivs.Privileges = LUID_AND_ATTRIBUTES()
requiredPrivs.Privileges.Luid = lpLuid
requiredPrivs.Privileges.Attributes = SE_PRIVILEGE_ENABLED

pfResult = ctypes.c_long()
res = a_handle.PrivilegeCheck(TokenHandle, ctypes.byref(requiredPrivs), ctypes.byref(pfResult))

if res > 0:
    print("[*] Privilege check sccessful...")
else:
    print("[!] Privilege check failed eith error code {0}".format(k_handle.GetLastError()))

if pfResult:
    print("[*] Privilege enabled: {0}".format(lpName))
    requiredPrivs.Privileges.Attributes = SE_PRIVILEGE_DISABLED
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

res = a_handle.AdjustTokenPrivileges(
    TokenHandle,
    DisableAllPrivileges,
    ctypes.byref(NewState),
    BufferLength,
    ctypes.byref(PreviousState),
    ctypes.byref(ReturnLength)
)

if res > 0:
    print("[*] Token Privileges Changed Successfully... ")
else:
    print("Token Privileges Change failed with error code {0}".format(k_handle.GetLastError()))