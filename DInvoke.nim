# https://github.com/S3cur3Th1sSh1t/Nim_DInvoke

import winim
import tables
import strformat
import algorithm

when defined(WIN64):
  const
    PEB_OFFSET* = 0x30
else:
  const
    PEB_OFFSET* = 0x60


const
  LdrLoadDll_SW2 * = #[1676890403]# "LdrLoadDll"
  MZ* = 0x5A4D

const
  NTDLL_DLL* = "ntdll.dll"

type
  LdrLoadDll_t* = proc (PathToFile: PWCHAR, Flags: ULONG, ModuleFileName: PUNICODE_STRING, ModuleHandle: PHANDLE): NTSTATUS {.stdcall.}
  
type
  ND_LDR_DATA_TABLE_ENTRY* {.bycopy.} = object
    InMemoryOrderLinks*: LIST_ENTRY
    InInitializationOrderLinks*: LIST_ENTRY
    DllBase*: PVOID
    EntryPoint*: PVOID
    SizeOfImage*: ULONG
    FullDllName*: UNICODE_STRING
    BaseDllName*: UNICODE_STRING

  PND_LDR_DATA_TABLE_ENTRY* = ptr ND_LDR_DATA_TABLE_ENTRY
  ND_PEB_LDR_DATA* {.bycopy.} = object
    Length*: ULONG
    Initialized*: UCHAR
    SsHandle*: PVOID
    InLoadOrderModuleList*: LIST_ENTRY
    InMemoryOrderModuleList*: LIST_ENTRY
    InInitializationOrderModuleList*: LIST_ENTRY

  PND_PEB_LDR_DATA* = ptr ND_PEB_LDR_DATA
  ND_PEB* {.bycopy.} = object
    Reserved1*: array[2, BYTE]
    BeingDebugged*: BYTE
    Reserved2*: array[1, BYTE]
    Reserved3*: array[2, PVOID]
    Ldr*: PND_PEB_LDR_DATA

  PND_PEB* = ptr ND_PEB

proc djb2(str: cstring): uint64 =
    var hash: uint64 = 2821

    for i in str.items:
        hash = ((hash shl 5) + hash) + uint64(i)
    return hash and uint64(0xFFFFFFFF)

proc GetPPEB(p: culong): P_PEB {. 
    header: 
        """#include <windows.h>
           #include <winnt.h>""", 
    importc: "__readgsqword"
.}

template RVA*(atype: untyped, base_addr: untyped, rva: untyped): untyped = cast[atype](cast[ULONG_PTR](cast[ULONG_PTR](base_addr) + cast[ULONG_PTR](rva)))

template RVASub*(atype: untyped, base_addr: untyped, rva: untyped): untyped = cast[atype](cast[ULONG_PTR](cast[ULONG_PTR](base_addr) - cast[ULONG_PTR](rva)))

template RVA2VA(casttype, dllbase, rva: untyped): untyped =
  cast[casttype](cast[ULONG_PTR](dllbase) + rva)

proc `+`[T](a: ptr T, b: int): ptr T =
    cast[ptr T](cast[uint](a) + cast[uint](b * a[].sizeof))

proc `-`[T](a: ptr T, b: int): ptr T =
    cast[ptr T](cast[uint](a) - cast[uint](b * a[].sizeof))


### Alternative for PEB x64 only

#[

type
  LDR_DATA_TABLE_ENTRY* {.bycopy.} = object
    InLoadOrderModuleList*: LIST_ENTRY
    InMemoryOrderModuleList*: LIST_ENTRY
    InInitializationOrderModuleList*: LIST_ENTRY
    DllBase*: PVOID
    EntryPoint*: PVOID
    SizeOfImage*: ULONG        ##  in bytes
    FullDllName*: UNICODE_STRING
    BaseDllName*: UNICODE_STRING
    Flags*: ULONG              ##  LDR_*
    LoadCount*: USHORT
    TlsIndex*: USHORT
    HashLinks*: LIST_ENTRY
    SectionPointer*: PVOID
    CheckSum*: ULONG
    TimeDateStamp*: ULONG ##     PVOID			LoadedImports;					// seems they are exist only on XP !!!
                        ##     PVOID			EntryPointActivationContext;	// -same-
  PLDR_DATA_TABLE_ENTRY* = ptr LDR_DATA_TABLE_ENTRY

  PEB_LDR_DATA* {.bycopy.} = object
    Length*: ULONG
    Initialized*: BOOLEAN
    SsHandle*: PVOID
    InLoadOrderModuleList*: LIST_ENTRY
    InMemoryOrderModuleList*: LIST_ENTRY
    InInitializationOrderModuleList*: LIST_ENTRY

  PPEB_LDR_DATA* = ptr PEB_LDR_DATA

  RTL_DRIVE_LETTER_CURDIR* {.bycopy.} = object
    Flags*: USHORT
    Length*: USHORT
    TimeStamp*: ULONG
    DosPath*: UNICODE_STRING

  RTL_USER_PROCESS_PARAMETERS* {.bycopy.} = object
    MaximumLength*: ULONG
    Length*: ULONG
    Flags*: ULONG
    DebugFlags*: ULONG
    ConsoleHandle*: PVOID
    ConsoleFlags*: ULONG
    StdInputHandle*: HANDLE
    StdOutputHandle*: HANDLE
    StdErrorHandle*: HANDLE
    CurrentDirectoryPath*: UNICODE_STRING
    CurrentDirectoryHandle*: HANDLE
    DllPath*: UNICODE_STRING
    ImagePathName*: UNICODE_STRING
    CommandLine*: UNICODE_STRING
    Environment*: PVOID
    StartingPositionLeft*: ULONG
    StartingPositionTop*: ULONG
    Width*: ULONG
    Height*: ULONG
    CharWidth*: ULONG
    CharHeight*: ULONG
    ConsoleTextAttributes*: ULONG
    WindowFlags*: ULONG
    ShowWindowFlags*: ULONG
    WindowTitle*: UNICODE_STRING
    DesktopName*: UNICODE_STRING
    ShellInfo*: UNICODE_STRING
    RuntimeData*: UNICODE_STRING
    DLCurrentDirectory*: array[0x20, RTL_DRIVE_LETTER_CURDIR]

  PEB* {.bycopy.} = object
    InheritedAddressSpace*: BOOLEAN
    ReadImageFileExecOptions*: BOOLEAN
    BeingDebugged*: BOOLEAN
    Spare*: BOOLEAN
    Mutant*: HANDLE
    ImageBaseAddress*: PVOID
    Ldr*: PPEB_LDR_DATA
    ProcessParameters*: PRTL_USER_PROCESS_PARAMETERS
    SubSystemData*: PVOID
    ProcessHeap*: PVOID
    FastPebLock*: PVOID
    FastPebLockRoutine*: PVOID
    FastPebUnlockRoutine*: PVOID
    EnvironmentUpdateCount*: ULONG
    KernelCallbackTable*: PVOID
    EventLogSection*: PVOID
    EventLog*: PVOID
    FreeList*: PVOID
    TlsExpansionCounter*: ULONG
    TlsBitmap*: PVOID
    TlsBitmapBits*: array[0x2, ULONG]
    ReadOnlySharedMemoryBase*: PVOID
    ReadOnlySharedMemoryHeap*: PVOID
    ReadOnlyStaticServerData*: PVOID
    AnsiCodePageData*: PVOID
    OemCodePageData*: PVOID
    UnicodeCaseTableData*: PVOID
    NumberOfProcessors*: ULONG
    NtGlobalFlag*: ULONG
    Spare2*: array[0x4, BYTE]
    CriticalSectionTimeout*: LARGE_INTEGER
    HeapSegmentReserve*: ULONG
    HeapSegmentCommit*: ULONG
    HeapDeCommitTotalFreeThreshold*: ULONG
    HeapDeCommitFreeBlockThreshold*: ULONG
    NumberOfHeaps*: ULONG
    MaximumNumberOfHeaps*: ULONG
    ProcessHeaps*: ptr PVOID
    GdiSharedHandleTable*: PVOID
    ProcessStarterHelper*: PVOID
    GdiDCAttributeList*: PVOID
    LoaderLock*: PVOID
    OSMajorVersion*: ULONG
    OSMinorVersion*: ULONG
    OSBuildNumber*: ULONG
    OSPlatformId*: ULONG
    ImageSubSystem*: ULONG
    ImageSubSystemMajorVersion*: ULONG
    ImageSubSystemMinorVersion*: ULONG
    GdiHandleBuffer*: array[0x22, ULONG]
    PostProcessInitRoutine*: ULONG
    TlsExpansionBitmap*: ULONG
    TlsExpansionBitmapBits*: array[0x80, BYTE]
    SessionId*: ULONG

  PPEB* = ptr PEB

{.passC:"-masm=intel".}

proc GetPEBAsm64*(): PPEB {.asmNoStackFrame.} =
    # GetPEBAsm64 proc
    asm """
        push rbx
        xor rbx,rbx
        xor rax,rax
        mov rbx, qword ptr gs:[0x30]
        mov rax, rbx
        pop rbx
        ret
    """
    # GetPEBAsm64 endp
]#
## Alternative end

proc is_dll*(hLibrary: PVOID): BOOL
proc get_library_address*(LibName: LPWSTR; DoLoad: BOOL): HANDLE
proc get_function_address*(hLibrary: HMODULE; fname: cstring; ordinal: int, specialCase: BOOL): PVOID

proc is_dll*(hLibrary: PVOID): BOOL =
  var dosHeader: PIMAGE_DOS_HEADER
  var ntHeader: PIMAGE_NT_HEADERS
  if (hLibrary == nil):
    when not defined(release):
        echo "[-] hLibrary == 0, exiting"
    return FALSE
  dosHeader = cast[PIMAGE_DOS_HEADER](hLibrary)
  #echo "Got dos Header"
  ##  check the MZ magic bytes
  if dosHeader.e_magic != MZ:
    when not defined(release):
        echo "[-] No Magic bytes found"
    return FALSE
  ntHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](hLibrary) + dosHeader.e_lfanew)
  #echo "Got NT Headers"
  ##  check the NT_HEADER signature
  if ntHeader.Signature != IMAGE_NT_SIGNATURE:
    when not defined(release):
        echo "[-] Nt Header signature wrong, exiting"
    return FALSE
  var Characteristics: USHORT = ntHeader.FileHeader.Characteristics
  if (Characteristics and IMAGE_FILE_DLL) != IMAGE_FILE_DLL:
    when not defined(release):
        echo "[-] Characteristics shows this is not an DLL, exiting"
    return FALSE
  #echo "Everything fine, this is indeed a DLL"
  return TRUE


##
##  Get the base address of a DLL
##


proc get_library_address*(LibName: LPWSTR; DoLoad: BOOL): HANDLE =
  echo "\r\n[*] Parsing the PEB to search for the target DLL\r\n"
  var Peb: PPEB = GetPPEB(PEB_OFFSET)
  var Ldr = Peb.Ldr
  var FirstEntry: PVOID = addr(Ldr.InMemoryOrderModuleList.Flink)
  var Entry: PND_LDR_DATA_TABLE_ENTRY = cast[PND_LDR_DATA_TABLE_ENTRY](Ldr.InMemoryOrderModuleList.Flink)
  while true:
    # lstrcmpiW is not case sensitive, lstrcmpW is case sensitive
    var compare: int = lstrcmpiW(LibName,cast[LPWSTR](Entry.BaseDllName.Buffer))
    if(compare == 0):
      #echo "DLL names equal"
        echo "\r\n[+] Found the DLL!\r\n"
        return cast[HANDLE](Entry.DllBase)
    Entry = cast[PND_LDR_DATA_TABLE_ENTRY](Entry.InMemoryOrderLinks.Flink)
    if not (Entry != FirstEntry):
        echo "DLL not found for the current proc, loading."
        break
  if (DoLoad == FALSE):
    echo "Exit, loading is not appreciated"
    return 0
  
  var MyLdrLoadDll: LdrLoadDll_t = cast[LdrLoadDll_t](cast[LPVOID](get_function_address(cast[HMODULE](get_library_address(NTDLL_DLL, FALSE)), LdrLoadDll_SW2, 0, TRUE)))
  
  if MyLdrLoadDll == nil:
    echo "[-] Address of LdrLoadDll not found"
    return 0

  var ModuleFileName: UNICODE_STRING
  
  var hLibrary: HANDLE = 0
  
  RtlInitUnicodeString(&ModuleFileName, LibName)
  ##  load the library
  var status: NTSTATUS = MyLdrLoadDll(nil, 0, &ModuleFileName, &hLibrary)
  
  if (status != 0):
    echo fmt"[-] Failed to load {Libname}, status: {status}\n"
    if (hLibrary == 0):
        echo "HLibrary still null"
    return 0
  else:
    echo fmt"Loaded {LibName} successfully!"
  echo fmt"[+] Loaded {LibName} at {hLibrary}"
  return hLibrary


##
##  Find an export in a DLL
##

proc get_function_address*(hLibrary: HMODULE; fname: cstring; ordinal: int, specialCase: BOOL): PVOID =
  var dos: PIMAGE_DOS_HEADER
  var nt: PIMAGE_NT_HEADERS
  #var data: PIMAGE_DATA_DIRECTORY
  var data: array[0..15, IMAGE_DATA_DIRECTORY]
  var exp: PIMAGE_EXPORT_DIRECTORY
  var exp_size: DWORD
  var adr: PDWORD
  var ord: PDWORD
  var functionAddress: PVOID
  var toCheckLibrary: PVOID = cast[PVOID](hLibrary)
  if (is_dll(toCheckLibrary) == FALSE):
    echo "[-] Exiting, not a DLL"
    return nil
  dos = cast[PIMAGE_DOS_HEADER](hLibrary)
  nt = RVA(PIMAGE_NT_HEADERS, cast[PVOID](hLibrary), dos.e_lfanew)
  
  data = nt.OptionalHeader.DataDirectory
  
  if (data[0].Size == 0 or data[0].VirtualAddress == 0):
    echo "[-] Data size == 0 or no VirtualAddress"
    return nil
  exp = RVA(PIMAGE_EXPORT_DIRECTORY, hLibrary, data[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
  exp_size = data[0].Size

  adr = RVA2VA(PDWORD, cast[DWORD_PTR](hLibrary), exp.AddressOfFunctions)
  ord = RVA2VA(PDWORD, cast[DWORD_PTR](hLibrary), exp.AddressOfNameOrdinals)
  
  functionAddress = nil

  var numofnames = cast[DWORD](exp.NumberOfNames)
  var functions = RVA2VA(PDWORD, cast[PVOID](hLibrary), exp.AddressOfFunctions)
  var addressOfFunctionsvalue = RVA2VA(PDWORD, cast[PVOID](hLibrary), exp.AddressOfFunctions)[]
  var names = RVA2VA(PDWORD, cast[PVOID](hLibrary), exp.AddressOfNames)[]

  echo "\r\n[*] Checking DLL's Export Directory for the target function\r\n"
    
  ##  iterate over all the exports
  #var i: DWORD = 0

  for i in 0 ..< numofnames:
        echo "Inside GetFunctionAddress For Loop!\n"
        echo "Number of Names: ", numofnames
    # Getting the function name value
        var funcname = RVA2VA(cstring, cast[PVOID](hLibrary), names)
        echo "Function name: ", funcname
        var finalfunctionAddress = RVA(PVOID, cast[PVOID](hLibrary), addressOfFunctionsvalue)
        echo "Calculating address: ", repr finalfunctionAddress
      # We are comparing against function names, which include "." because for some reason all function names in this loop also contain references to other DLLs, e.g. "api-ms-win-core-libraryloader-l1-1-0.AddDllDirectory" in kernel32.dll
        var test = StrRChrIA(cast[LPCSTR](funcname), nil, cast[WORD]('.'))
        echo "Variable test value is: ", test
        echo "Dot comparison happened!\n"
        if test != NULL:
        # As we found a trash (indirect reference, normally this is in the address field and not in the names field) function, we have to increase this value -> Not an official function
            numofnames = numofnames + 1
            echo "numofnames variable increased by 1"
        else:
            echo "functions variable increased by 1"
            functions = functions + 1
            addressOfFunctionsvalue = functions[]
        echo "Relative Address: ", toHex(functions[])
        names += cast[DWORD](len(funcname) + 1)
        #echo "Comparing ", cast[string](hash), " with Current Function Hash: ", djb2(funcname)
        if fname == funcname:
        
        # So many edge cases, have to investigate
            if (funcname == "CreateFileW"):
                functions = functions - 1
            if (funcname == "SetFileInformationByHandle"):
                functions = functions - 1
            if (funcname == "CloseHandle"):
                functions = functions - 1
            if (funcname == "GetModuleFileNameW"):
                functions = functions - 1

            echo "\r\n[+] Found API call: ", funcname
            echo "\r\n"
        else:
            continue
        # Strange. For ntdll functions the following is needed, but for kernel32 functions it's not. Don't ask me why. This is a workaround for the moment. Need to troubleshoot.
        if (specialCase):
          # Why?
          echo "This is a special case, subtract one function"
          finalfunctionAddress = RVA(PVOID, cast[PVOID](hLibrary), addressOfFunctionsvalue)

        echo "Relative Address: ", toHex(functions[])
        functions = functions - 1
        echo "Relative Address one before: ", toHex(functions[])
        functions = functions + 2
        echo "Relative Address one after: ", toHex(functions[])
        functionAddress = finalfunctionAddress
        break
  if functionAddress == nil:
    return nil
  else:
    return functionAddress
