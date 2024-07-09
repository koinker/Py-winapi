import ctypes

pid = input("Process Id: ")

k_handle = ctypes.WinDLL("Kernel32.dll")

PROCESS_ALL_ACCESS = (0x000F0000 | 0X00100000 | 0xFFF)

dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProccessId = int(pid)

execute = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProccessId)

print(execute)

if execute <= 0:
    print("Handle was not created!")

else:
    print("Handle created successfully :)")
