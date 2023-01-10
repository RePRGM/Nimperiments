# https://github.com/S3cur3Th1sSh1t/Nim_DInvoke

import winim
import tables
import strformat
import algorithm

const GetProcAddress_str = "GetProcAddress"

type
  GetProcAddress_t* = proc(hModule: HMODULE, lpProcName: LPCSTR): FARPROC {.stdcall.}

var GetProcAddress_p*: GetProcAddress_t

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

const KERNEL32_DLL* = "kernel32.dll"

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

proc get_library_address*(): HANDLE
proc get_function_address*(hLibrary: HMODULE; fname: cstring): PVOID

##
##  Get the base address of a DLL
##


proc get_library_address*(): HANDLE =
  echo "\r\n[*] Parsing the PEB to search for the target DLL\r\n"
  var Peb: PPEB = GetPPEB(PEB_OFFSET)
  var Ldr = Peb.Ldr
  var FirstEntry: PVOID = addr(Ldr.InMemoryOrderModuleList.Flink)
  var Entry: PND_LDR_DATA_TABLE_ENTRY = cast[PND_LDR_DATA_TABLE_ENTRY](Ldr.InMemoryOrderModuleList.Flink)
  while true:
    # lstrcmpiW is not case sensitive, lstrcmpW is case sensitive
    var compare: int = lstrcmpiW("kernel32.dll", cast[LPWSTR](Entry.BaseDllName.Buffer))
    if compare == 0:
      #echo "DLL names equal"
        echo "\r\n[+] Found the DLL!\r\n"
        return cast[HANDLE](Entry.DllBase)
    Entry = cast[PND_LDR_DATA_TABLE_ENTRY](Entry.InMemoryOrderLinks.Flink)
    if not (Entry != FirstEntry):
        echo "DLL not found for the current proc!"
        break

##
##  Find an export in a DLL
##

proc get_function_address*(hLibrary: HMODULE; fname: cstring): PVOID =
  var dos: PIMAGE_DOS_HEADER
  var nt: PIMAGE_NT_HEADERS
  var data: array[0..15, IMAGE_DATA_DIRECTORY]
  var exp: PIMAGE_EXPORT_DIRECTORY
  var exp_size: DWORD
  var adr: PDWORD
  var ord: PDWORD
  var functionAddress: PVOID

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

  for i in 0 ..< numofnames:
        #echo "Inside GetFunctionAddress For Loop!\n"
        #echo "Number of Names: ", numofnames
    # Getting the function name value
        var funcname = RVA2VA(cstring, cast[PVOID](hLibrary), names)
        #echo "Function name: ", funcname
        var finalfunctionAddress = RVA(PVOID, cast[PVOID](hLibrary), addressOfFunctionsvalue)
        #echo "Calculating address: ", repr finalfunctionAddress
      # We are comparing against function names, which include "." because for some reason all function names in this loop also contain references to other DLLs, e.g. "api-ms-win-core-libraryloader-l1-1-0.AddDllDirectory" in kernel32.dll
        var test = StrRChrIA(cast[LPCSTR](funcname), nil, cast[WORD]('.'))
        #echo "Variable test value is: ", test
        #echo "Dot comparison happened!\n"
        if test != NULL: # If dot was found
        # As we found a trash (indirect reference, normally this is in the address field and not in the names field) function, we have to increase this value -> Not an official function
            numofnames = numofnames + 1
            #echo "numofnames variable increased by 1"
        else: # If dot was not found
            #echo "functions variable increased by 1"
            functions = functions + 1
            addressOfFunctionsvalue = functions[]
        #echo "Relative Address: ", toHex(functions[])
        names += cast[DWORD](len(funcname) + 1)
        #echo "Comparing ", cast[string](hash), " with Current Function Hash: ", djb2(funcname)
        if fname == funcname:
            echo "\r\n[+] Found API call: ", funcname
            echo "\r\n"
            echo "Calculating address: ", repr finalfunctionAddress
            #echo "Address again: ", repr addressOfFunctionsvalue
            functionAddress = finalfunctionAddress
            break
        #functionAddress = finalfunctionAddress
    
  if functionAddress == nil:
    return nil
  else:
    return functionAddress

echo "Kernel32 is located at: ", toHex(get_library_address())
discard readLine(stdin)
#[var k32Addr = get_library_address() 
GetProcAddress_p = cast[GetProcAddress_t](cast[LPVOID](get_function_address(cast[HMODULE](k32Addr), GetProcAddress_str)))

var WPM_addr = GetProcAddress_p(cast[HMODULE](k32Addr), "WriteProcessMemory")
echo "Is this it? ", repr WPM_addr
]#
var consoleInput = readLine(stdin)
