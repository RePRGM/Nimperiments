import 
    winim,
    hash, gmh, str

proc getProcAddressHash*(hModule: HMODULE, apiNameHash: uint32): FARPROC {.inline.} =
  var 
    pBase = hModule
    pImgDosHdr = cast[PIMAGE_DOS_HEADER](pBase)
    pImgNtHdr = cast[PIMAGE_NT_HEADERS](cast[int](pBase) + pImgDosHdr.e_lfanew)

  if (pImgDosHdr.e_magic != IMAGE_DOS_SIGNATURE) or (pImgNtHdr.Signature != IMAGE_NT_SIGNATURE):
    return cast[FARPROC](0)

  var
    imgOptHdr = cast[IMAGE_OPTIONAL_HEADER](pImgNtHdr.OptionalHeader)
    dwImgExportTableSize = imgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size
    pImgExportDir = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](pBase) + imgOptHdr.DataDirectory[0].VirtualAddress)
    funcNameArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfNames)
    funcAddressArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfFunctions)
    funcOrdinalArray = cast[ptr UncheckedArray[WORD]](cast[int](pBase) + pImgExportDir.AddressOfNameOrdinals)
  
  for i in 0 ..< pImgExportDir.NumberOfFunctions:
    var 
      pFunctionName = cast[cstring](cast[PCHAR](cast[int](pBase) + funcNameArray[i]))
      pFunctionAddress = cast[int](pBase) + funcAddressArray[funcOrdinalArray[i]]

    if apiNameHash == hashStrA(pFunctionName):
      # Check if Forwarded function
      if (cast[int](pFunctionAddress) >= cast[int](pImgExportDir)) and (cast[int](pFunctionAddress) < cast[int](pImgExportDir) + dwImgExportTableSize):
        var 
          forwarderName: array[MAX_PATH, char]
          dotOffset: int
          lenForwarderName = strlenA(pFunctionAddress)
        # save the forwarder string into our ForwarderName Buffer 
        copyMem(forwarderName[0].addr, cast[pointer](pFunctionAddress), lenForwarderName)

        for i in 0 ..< lenForwarderName:
          if cast[ptr byte](cast[int](forwarderName[0].addr) + i)[] == '.'.byte:
            dotOffset = i
            cast[ptr byte](cast[int](forwarderName[0].addr) + i)[] = '\0'.byte
            break

        var 
          functionModule = cast[PCHAR](cast[int](forwarderName[0].addr))
          functionName = cast[PCHAR](cast[int](forwarderName[0].addr) + dotOffset + 1)
          pLoadLibraryA = cast[typeof(LoadLibraryA)](getProcAddressHash(gmh("KERNEL32.DLL"), static(hashStrA("LoadLibraryA".cstring))))

        return cast[FARPROC](getProcAddressHash(pLoadLibraryA(functionModule), hashStrA(cast[cstring](functionName))))
      # Not forwarded function
      else:
        return cast[FARPROC](pFunctionAddress)
  return cast[FARPROC](0)

template gpa*[T](h: HANDLE, p: string, t: T): T =
  cast[typeof(t)](getProcAddressHash(h, static(hashStrA(p.cstring))))
