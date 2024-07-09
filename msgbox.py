import ctypes #interface with win32 api


#handle to libs
user_handle = ctypes.WinDLL("User32.dll")
k_handle = ctypes.WinDLL("Kernel32.dll")

#null window handle
hwnd = None

#msgbox text
lptext = "hello world"

#title of msgbox
lpcaption= "test"

#button option
utype = 0x00000001

#calling msgbox function
response = user_handle.MessageBoxW(hwnd, lptext, lpcaption, utype)

err = k_handle.GetLastError()

#check for errors
if err !=0:
    print("Error Code:{0}". format(err))
    exit(1)