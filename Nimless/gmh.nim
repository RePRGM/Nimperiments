import 
    winim,
    hash

template doWhile(a, b: untyped): untyped =
  b
  while a:
    b

template gmh*(s: string): HANDLE =
  getModuleHandleH(static(hashStrA(s.cstring)))

proc getModuleHandleH*(hash: uint32): HMODULE =
  var pPeb: PPEB

  asm """
    xor rax, rax
    mov rax, 0x10
    imul rax, rax, 6
    mov rax, qword ptr gs:[rax]
    :"=r"(`pPeb`)
  """

  let
    pLdr: PPEB_LDR_DATA = pPeb.Ldr
    pListHead: LIST_ENTRY = pPeb.Ldr.InMemoryOrderModuleList

  var
    pDte: PLDR_DATA_TABLE_ENTRY = cast[PLDR_DATA_TABLE_ENTRY](pLdr.InMemoryOrderModuleList.Flink)
    pListNode: PLIST_ENTRY = pListHead.Flink
    
  doWhile cast[int](pListNode) != cast[int](pListHead):
    if pDte.FullDllName.Length != 0:
      if hash == hashStrW(pDte.FullDllName.Buffer):
        return cast[HMODULE](pDte.Reserved2[0])
    pDte = cast[PLDR_DATA_TABLE_ENTRY](pListNode.Flink)
    pListNode = cast[PLIST_ENTRY](pListNode.Flink)
  return cast[HMODULE](0)