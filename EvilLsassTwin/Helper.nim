import 
    std/[dynlib],
    winim

type
    USTRING* = object
        Length*: DWORD
        MaximumLength*: DWORD
        Buffer*: PVOID

    NtQuerySystemInformation_t = proc(SystemInformationClass: ULONG, SystemInformation: PVOID, SystemInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
    NtDuplicateObject_t = proc(SourceProcessHandle: HANDLE, SourceHandle: HANDLE, TargetProcessHandle: HANDLE, TargetHandle: PHANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Options: ULONG): NTSTATUS {.stdcall.}
    NtCreateProcessEx_t = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ParentProcess: HANDLE, Flags: ULONG, SectionHandle: HANDLE, DebugPort: HANDLE, ExceptionPort: HANDLE, InJob: BOOLEAN): NTSTATUS {.stdcall.}
    NtGetNextProcess_t = proc(ProcessHandle: HANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Flags: ULONG, NewProcessHandle: PHANDLE): NTSTATUS {.stdcall.}    
    NtQueryVirtualMemory_t = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, MemoryInformationClass: int32, MemoryInformation: PVOID, MemoryInformationLength: SIZE_T, ReturnLength: PSIZE_T): NTSTATUS {.stdcall.}
    NtQueryInformationProcess_t = proc(ProcessHandle: HANDLE, ProcessInformationClass: PROCESSINFOCLASS, ProcessInformation: PVOID, ProcessInformatinLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
    RTLGetVersion_t = proc(lpVersionInformation: ptr RTL_OSVERSIONINFOEXW): NTSTATUS {.stdcall.}
    NtReadVirtualMemory_t = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, NumberOfBytesRead: PSIZE_T): NTSTATUS {.stdcall.}
    NtSetInformationProcess_t = proc (ProcessHandle: HANDLE, ProcessInformationClass: PROCESSINFOCLASS, ProcessInformation: PVOID, ProcessInformationLength: ULONG): NTSTATUS{.stdcall.}

var 
    status*: NTSTATUS
    hNtdll = loadLib("ntdll.dll")

var
    NtReadVirtualMemory* = cast[NtReadVirtualMemory_t](hNtdll.symAddr("NtReadVirtualMemory"))
    NtCreateProcessEx* = cast[NtCreateProcessEx_t](hNtdll.symAddr("NtCreateProcessEx"))
    NtGetNextProcess* = cast[NtGetNextProcess_t](hNtdll.symAddr("NtGetNextProcess"))
    NtQueryVirtualMemory* = cast[NtQueryVirtualMemory_t](hNtdll.symAddr("NtQueryVirtualMemory"))
    RtlGetVersion* = cast[RTLGetVersion_t](hNtdll.symAddr("RtlGetVersion"))
    NtDuplicateObject* = cast[NtDuplicateObject_t](hNtdll.symAddr("NtDuplicateObject"))
    NtSetInformationProcess* = cast[NtSetInformationProcess_t](hNtdll.symAddr("NtSetInformationProcess"))

func toString*(bytes: openArray[byte]): string {.inline.} =
  ## Converts a byte sequence to the corresponding string.
  let length = bytes.len
  if length > 0:
    result = newString(length)
    copyMem(result.cstring, bytes[0].unsafeAddr, length)

proc toString*(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))

proc GetProcessByName*(process_name: string): DWORD =
    var
        pid: DWORD = 0
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    
    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toString == process_name:
                pid = entry.th32ProcessID
                break
    CloseHandle(hSnapshot)
    return pid

proc SystemFunction032*(memoryRegion: pointer, keyPointer: pointer): NTSTATUS {.discardable, stdcall, dynlib: "Advapi32", importc: "SystemFunction032".}
