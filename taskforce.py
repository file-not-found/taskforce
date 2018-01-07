from ctypes import *
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-s", "--step", type=int, default=4,
    help="brute-force step width")
parser.add_argument("-m", "--max", type=int, default=10000,
    help="max PID")
parser.add_argument("-k", "--kill", type=int,
    help="PID to kill")
parser.add_argument("--xp", action="store_true",
    help="run on xp")
parser.add_argument("--system", action="store_true",
    help="elevate to LocalSystem")
args=parser.parse_args()

max_pid = args.max
step = args.step
xp = args.xp
system = args.system
kill_pid = args.kill

kernel32 = windll.kernel32
psapi = windll.psapi
advapi32 = windll.advapi32

LPVOID = c_void_p
PVOID = LPVOID
PSID = PVOID
DWORD = c_uint32
LPSTR = c_char_p
HANDLE      = LPVOID
INVALID_HANDLE_VALUE = c_void_p(-1).value
LONG        = c_long
WORD        = c_uint16

PROCESS_TERMINATE = 0x1
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
TOKEN_QUERY             = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020

class LUID(Structure):
    _fields_ = [
        ("LowPart",     DWORD),
        ("HighPart",    LONG),
    ]

class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid",        LUID),
        ("Attributes",  DWORD),
    ]

class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount",  DWORD),
        ("Privileges",      LUID_AND_ATTRIBUTES),
    ]

if system:
    hToken = HANDLE(INVALID_HANDLE_VALUE)

    advapi32.OpenProcessToken( kernel32.GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(hToken) )
    privilege_id = LUID()
    advapi32.LookupPrivilegeValueA(None, "SeDebugPrivilege", byref(privilege_id))
    SE_PRIVILEGE_ENABLED = 0x00000002
    laa = LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
    tp  = TOKEN_PRIVILEGES(1, laa)

    advapi32.AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None) 

if kill_pid:
    print("Terminating %d" % kill_pid)

    h_process = kernel32.OpenProcess(PROCESS_TERMINATE, False, kill_pid)
    kernel32.TerminateProcess(h_process,0)

else:
    pidlist=(c_int*1024)()
    r=0

    psapi.EnumProcesses(pidlist, 4096, r)

    for pid in xrange(0,max_pid,step):
        if xp:
            h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, False, pid)
        else:
            h_process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        
        if h_process != 0:
            if pid in pidlist:
                print("[%d]\t" % pid),
            else:
                print("<%d>\t" % pid),
            
            buffer="\0"*200
            l = psapi.GetProcessImageFileNameA(h_process, buffer, 200)
            if l != 0:
                print("%s" % buffer.strip("\0").split('\\')[-1])
            else:
                print("<unknown file>")
        elif kernel32.GetLastError() ==5:
            if pid in pidlist:
                print("[%d]\t" % pid),
            else:
                print("<%d>\t" % pid),
            print("<access denied>")
