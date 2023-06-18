{.passC:"-masm=intel".}
import 
    winim,
    std/tables,
    std/strutils,
    ptr_math

# 64-bit only
const 
    PEB_OFFSET* = 0x60
    NTDLL = "ntdll.dll"

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

var 
    si: STARTUPINFOA
    pi: PROCESS_INFORMATION
    mi: MODULEINFO
    currentProc: HANDLE = -1
    syscallInfo = initTable[string, seq[string]]() # Key: Function Name, @[SSN, Syscall instruction address]
    ntcfSSN: DWORD
    ntcfAddr: ByteAddress

proc GetPPEB(p: culong): P_PEB {. 
    header: 
        """#include <windows.h>
           #include <winnt.h>""", 
    importc: "__readgsqword"
.}

proc retNtLibAddress*(): HANDLE =
  #echo "\r\n[*] Parsing the PEB to search for the target DLL\r\n"
  var Peb: PPEB = GetPPEB(PEB_OFFSET)
  var Ldr = Peb.Ldr
  var FirstEntry: PVOID = addr(Ldr.InMemoryOrderModuleList.Flink)
  var Entry: PND_LDR_DATA_TABLE_ENTRY = cast[PND_LDR_DATA_TABLE_ENTRY](Ldr.InMemoryOrderModuleList.Flink)
  while true:
    # lstrcmpiW is not case sensitive, lstrcmpW is case sensitive
    var compare: int = lstrcmpiW(NTDLL, cast[LPWSTR](Entry.BaseDllName.Buffer))
    echo NTDLL, ":", cast[LPWSTR](Entry.BaseDllName.Buffer)
    if compare == 0:
        #echo "DLL names equal"
        #echo "\r\n[+] Found the DLL!\r\n"
        return cast[HANDLE](Entry.DllBase)
    Entry = cast[PND_LDR_DATA_TABLE_ENTRY](Entry.InMemoryOrderLinks.Flink)
    if not (Entry != FirstEntry):
        #echo "DLL not found for the current proc!"
        break

proc RVAtoRawOffset(RVA: DWORD_PTR, section: PIMAGE_SECTION_HEADER): PVOID =
    return cast[PVOID](RVA - section.VirtualAddress + section.PointerToRawData)

proc toString(bytes: cstring): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc toString(bytes: openArray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc getSyscallInfo(): void =
    ZeroMemory(addr si, sizeof(si))
    ZeroMemory(addr pi, sizeof(PROCESS_INFORMATION))

    var 
        notepadProc = CreateProcessA(r"C:\Windows\System32\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, addr si, addr pi)
        ntAddr: HANDLE = retNtLibAddress()
        dwRead: SIZE_T
        DOSHead: PIMAGE_DOS_HEADER
        NTHead: PIMAGE_NT_HEADERS 

    echo "NTDLL located at: 0x", toHex(cast[int](ntAddr))

    if notepadProc == 0:
        echo "Error creating process!"
        quit(1)

    var modInfo = GetModuleInformation(currentProc, cast[HMODULE](ntAddr), addr mi, cast[DWORD](sizeof(mi)))

    if modInfo == 0:
        echo "Error getting module info!"
        quit(1)

    var pntdll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage)
    var isRead = ReadProcessMemory(pi.hProcess, mi.lpBaseOfDll, pntdll, mi.SizeOfImage, addr dwRead)

    echo "Heap at: 0x", toHex(cast[int](pntdll))
    if isRead != TRUE:
        echo "Error reading proc mem!"
        quit(1)

    TerminateProcess(pi.hProcess, 0)

    DOSHead = cast[PIMAGE_DOS_HEADER](pntdll)
    NTHead = cast[PIMAGE_NT_HEADERS](cast[DWORD64](pntdll) + DOSHead.e_lfanew)

    var
        # Relative Address (offset) of IMAGE_EXPORT_DIRECTORY
        exportDirRVA: DWORD = NTHead.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        section: PIMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(NTHead)
        textSection: PIMAGE_SECTION_HEADER = section
        rdataSection: PIMAGE_SECTION_HEADER = section

    let 
        low: uint16 = 0
        low2: int = 0

    echo "Finding .rdata section"
    for Section in low ..< NTHead.FileHeader.NumberOfSections:
        var ntdllSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(NTHead)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
        #if cmp("2E7264617461", toHex(toString(ntdllSectionHeader.Name))) == 0:

        if ".rdata" in toString(ntdllSectionHeader.Name):
            rdataSection = ntdllSectionHeader
            echo "Found .rdata section"
            echo "Compared .rdata to ", toString(ntdllSectionHeader.Name)

    #var exportDirectory: PIMAGE_EXPORT_DIRECTORY = cast[PIMAGE_EXPORT_DIRECTORY](RVAtoRawOffset(cast[DWORD_PTR](pntdll + exportDirRVA), rdataSection))

    var exportDirectory: PIMAGE_EXPORT_DIRECTORY = cast[PIMAGE_EXPORT_DIRECTORY](cast[DWORD_PTR](pntdll + exportDirRVA))

    #var addressOfNames: PDWORD = cast[PDWORD](RVAtoRawOffset(cast[DWORD_PTR](pntdll + exportDirectory.AddressOfNames), rdataSection))
    var addressOfNames: PDWORD = cast[PDWORD](cast[DWORD_PTR](pntdll + exportDirectory.AddressOfNames))

    #var addressOfFunctions: PDWORD = cast[PDWORD](RVAtoRawOffset(cast[DWORD_PTR](pntdll) + cast[DWORD_PTR](exportDirectory.AddressOfFunctions), rdataSection))
    var addressOfFunctions: PDWORD = cast[PDWORD](cast[DWORD_PTR](pntdll) + cast[DWORD_PTR](exportDirectory.AddressOfFunctions))

    echo "Going through exports!"
    for low2 in 0 ..< exportDirectory.NumberOfNames:
        #var functionNameVA: DWORD_PTR = cast[DWORD_PTR](RVAtoRawOffset(cast[DWORD_PTR](pntdll) + addressOfNames[low2], rdataSection))
        var functionNameVA: DWORD_PTR = cast[DWORD_PTR]((cast[DWORD_PTR](pntdll) + addressOfNames[low2]))
        #echo "Function Name located at: 0x", functionNameVA.toHex
        #var functionVA: DWORD_PTR = cast[DWORD_PTR](RVAtoRawOffset(cast[DWORD_PTR](pntdll) + addressOfFunctions[low2 + 1], textSection))
        var functionVA: DWORD_PTR = cast[DWORD_PTR]((cast[DWORD_PTR](pntdll) + addressOfFunctions[low2 + 1]))
        var functionNameResolved: LPCSTR = cast[LPCSTR](functionNameVA)

        #echo functionNameResolved, " function located at: 0x", functionVA.toHex 
        syscallInfo[$functionNameResolved] = @[(cast[ptr DWORD](functionVA + 4)[].toHex(2)), $(functionVA + 0x12).toHex]
    echo "Functions added to hash table!"

proc myNtCreateFile(FileHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, IoStatusBlock: PIO_STATUS_BLOCK, AllocationSize: PLARGE_INTEGER, FileAttributes: ULONG, ShareAccess: ULONG, CreateDisposition: ULONG, CreateOptions: ULONG, EaBuffer: PVOID, EaLength: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        mov r10, rcx
        mov eax, `(ntcfSSN)`
        jmp QWORD PTR `(ntcfAddr)`
        ret
    """

proc main(): void =
    getSyscallInfo()
    #echo syscallInfo
    echo syscallInfo["NtCreateEvent"] #48h
 
    ntcfSSN = cast[DWORD](syscallInfo["NtCreateFile"][0])
    ntcfAddr = cast[ByteAddress](syscallInfo["NtCreateFile"][1])
    var
        oa: OBJECT_ATTRIBUTES
        fileHandle: HANDLE = cast[HANDLE](NULL)
        status: NTSTATUS
        fileName: UNICODE_STRING
        osb: IO_STATUS_BLOCK

    #[proc makeSyscall(syscallName: string): void {.asmNoStackFrame.} =
        asm """
            mov r10, rcx
            mov eax, `(syscallInfo[syscallName])`
            jmp QWORD PTR `[syscallInfo[syscallName]]`
            ret
        """
    ]#

    RtlInitUnicodeString(addr fileName, cast[PCWSTR]("\\??\\c:\\temp\\test.txt"))
    ZeroMemory(addr osb, sizeof(IO_STATUS_BLOCK))
    InitializeObjectAttributes(addr oa, addr fileName, OBJ_CASE_INSENSITIVE, cast[HANDLE](NULL), NULL)
    status = myNtCreateFile(addr fileHandle, FILE_GENERIC_WRITE, addr oa, addr osb, cast[PLARGE_INTEGER](0), FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)

    #[if status == STATUS_SUCCESS:
        echo "All good in the hood. Check Temp for test.txt"
    else:
        echo "Error calling the syscall. Expected. Quitting"
        quit(1)
    ]#
    discard readLine(stdin)

when isMainModule:
    main()
