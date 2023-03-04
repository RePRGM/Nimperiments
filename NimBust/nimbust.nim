import std/[
  os,
  httpclient,
  strutils,
  terminal,
  strformat,
  threadpool,
  sequtils,
  times
]

from std/net import newContext, SslCVerifyMode

# params[0] = url
# params[1] = wordlist
# params[2] = number of threads

var 
  params = commandLineParams()
  nimbust = extractFilename(getAppFilename())
  fullList: seq[string]

proc parseWordList(wordlist: string, thrNum: int): seq[seq[string]] =
  try:
    for line in wordlist.lines: 
      if line.startsWith("#") or line == "": continue
      fullList.add(line)
  except: stdout.styledWriteLine(fgRed, fmt "Cannot open {wordlist}")
  return fullList.distribute(thrNum)

proc bruteForce(wordlist: seq[string], baseUrl: string): void {.gcsafe.} =
  var 
    url: string
    response: Response
  
  let client = newHttpClient(userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0", sslContext=newContext(verifyMode=CVerifyPeer), timeout=10000)
  
  for word in wordlist:
    try:
      #if not word.endsWith('/'): url = fmt "{baseUrl}/{word}/"
      #else: url = fmt "{baseUrl}/{word}"
      
      url = fmt "{baseUrl}/{word}"
      response = client.request(url, HttpHead)
      defer: client.close()
      
      if "200" in response.status: stdout.styledWriteLine(fgGreen, fmt "({response.status.splitWhitespace()[0]})", fgWhite, fmt "\t/{word}")
        
      elif "201" in response.status: stdout.styledWriteLine(fgGreen, fmt "({response.status.splitWhitespace()[0]})", fgWhite, fmt "\t/{word}")
        
      elif "301" in response.status: stdout.styledWriteLine(fgYellow, fmt "({response.status.splitWhitespace()[0]})", fgWhite, fmt "\t/{word}")
        
      elif "302" in response.status: stdout.styledWriteLine(fgYellow, fmt "({response.status.splitWhitespace()[0]})", fgWhite, fmt "\t/{word}")
        
      elif "307" in response.status: stdout.styledWriteLine(fgYellow, fmt "({response.status.splitWhitespace()[0]})", fgWhite, fmt "\t/{word}")
        
      elif "308" in response.status: stdout.styledWriteLine(fgYellow, fmt "({response.status.splitWhitespace()[0]})", fgWhite, fmt "\t/{word}")
        
      elif "404" notin response.status: stdout.styledWriteLine(fgRed, fmt "({response.status.splitWhitespace()[0]})", fgWhite, fmt "\t/{word}")
        
    except: 
      var error = getCurrentException()
      stdout.styledWriteLine(fgRed, fmt "/{word}: {error.msg}")
    #if wordlist.len > 50: sleep(1000)
    
proc main(): void = 
  echo fmt"""
+=======================================================================================+
NimBust v1.0.0
by Eric Holloway (@RePRGM)
+=======================================================================================+"""
  echo "[*] Domain: ", params[0]
  echo "[*] Wordlist: ", params[1]
  echo "[*] Threads: ", params[2]
  echo "[*] Hidden: 404"
  echo "[*] Timeout: 10s"
  stdout.styledWriteLine(fgWhite, "[*] Status Codes: [", fgGreen, "200, 201, ", fgYellow, "301, 302, 307, 308, ", fgRed, "401, 403, 405, 410", fgWhite, "]")
  
  var subWordLists = parseWordList(params[1], parseInt(params[2]))
  echo fmt """
+=======================================================================================+
Starting NimBust: {getDateStr()} at {getClockStr()}
+=======================================================================================+"""
  for i in 0 ..< parseInt(params[2]): spawn bruteForce(subWordLists[i], params[0])
  sync()
  echo fmt """
+=======================================================================================+
Finished NimBust: {getDateStr()} at {getClockStr()}
+=======================================================================================+"""
  
when isMainModule:
  if params.len != 3:
    echo fmt "Usage: {nimbust} <url> <wordlist> <threads>"
    quit(1)
  else: main()
 
