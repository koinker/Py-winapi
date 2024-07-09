import ctypes
import argparse

#constants
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
uExitCode = 0x1

#parse args
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--pid', type=int, help='PID of process')
parser.add_argument('-w', '--window', type=str, help='Name of window')
args = parser.parse_args()

#load dlls
k_handle = ctypes.WinDLL("Kernel32.dll")
u_handle = ctypes.WinDLL("User32.dll")

#Function to terminate process based on window name or pid
def terminate_process(window_name=None, pid=None):
    if window_name:
        #provided window name
        lpWindowName = ctypes.c_char_p(window_name.encode('utf-8'))
        hWnd = u_handle.FindWindowA(None, lpWindowName)
        
        if hWnd == 0:
            print("Failed to find window '{0}'. Error code: {1}".format(window_name, k_handle.GetLastError()))
            return False
        else:
            print('Found window: {0}'.format(window_name))
        
        #Get pid
        lpdwProcessId = ctypes.c_ulong()
        u_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))
        pid = lpdwProcessId.value
        
        if pid == 0:
            print("Failed to retrieve process ID for window '{0}'".format(window_name))
            return False
        else:
            print('Window ProcessId: {0}'.format(pid))
    
    if pid:
        #provided pid
        dwDesiredAccess = PROCESS_ALL_ACCESS
        bInheritHandle = False
        hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, pid)
        
        #todo find window name by its pid
        
        if hProcess <= 0:
            print('Failed to gain privileged handle for PID {0}. Error code: {1}'.format(pid, k_handle.GetLastError()))
            return False
        
        else:
            print('Gained privileged handle for PID {0}'.format(pid))
        
        #terminate the process
        if k_handle.TerminateProcess(hProcess, uExitCode):
            print('Successfully terminated process with PID {0}'.format(pid))
        else:
            print('Failed to terminate process with PID {0}. Error code: {1}'.format(pid, k_handle.GetLastError()))
        
        #close handle
        k_handle.CloseHandle(hProcess)
        
        return True

    return False

#perform based on arguments
if args.window or args.pid:
    terminate_process(window_name=args.window, pid=args.pid)
else:
    print("Error: Either --window or --pid argument is required.")
    parser.print_help()
