import winim
import hash

template gpa*[T](h: HANDLE, p: string, t: T): T =
  cast[typeof(t)](getProcAddressHash(h, static(hashStrA(p.cstring))))

proc getProcAddressHash*(hModule: HMODULE, apiNameHash: uint32): FARPROC {.inline, noSideEffect.} =
  var 
    pBase = hModule
    pImgDosHdr = cast[PIMAGE_DOS_HEADER](pBase)
    pImgNtHdr = cast[PIMAGE_NT_HEADERS](cast[int](pBase) + pImgDosHdr.e_lfanew)

  if (pImgDosHdr.e_magic != IMAGE_DOS_SIGNATURE) or (pImgNtHdr.Signature != IMAGE_NT_SIGNATURE):
    return cast[FARPROC](0)

  var
    imgOptHdr = cast[IMAGE_OPTIONAL_HEADER](pImgNtHdr.OptionalHeader)
    pImgExportDir = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](pBase) + imgOptHdr.DataDirectory[0].VirtualAddress)
    funcNameArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfNames)
    funcAddressArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfFunctions)
    funcOrdinalArray = cast[ptr UncheckedArray[WORD]](cast[int](pBase) + pImgExportDir.AddressOfNameOrdinals)
  
  for i in 0 ..< pImgExportDir.NumberOfFunctions:
    var pFunctionName = cast[cstring](cast[PCHAR](cast[int](pBase) + funcNameArray[i]))

    if apiNameHash == hashStrA(pFunctionName):
      return cast[FARPROC](cast[int](pBase) + funcAddressArray[funcOrdinalArray[i]])
    
  return cast[FARPROC](0)