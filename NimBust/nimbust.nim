import argparse
import std/[
  os,
  httpclient,
  strutils,
  terminal,
  strformat,
  sequtils,
  times,
  locks,
  sugar
]

from std/net import newContext, SslCVerifyMode
from std/httpcore import HttpHeaderValues, contains
from std/uri import encodeUrl
from std/osproc import execCmd

type ThreadData = tuple[doAppend: bool, wordlist: seq[string], baseUrl: string, extension: seq[string], output: string, rDelay: float, timeout: int, userAgent: string, quietMode: bool, recursion: bool]

const version = "0.2.0"
var 
  L: Lock
  
L.initLock()

proc parseWordList(wordlist: string, thrNum: int): seq[seq[string]]
proc bruteForce(options: tuple): void {.thread.}
proc main(options: tuple): void

when isMainModule:
  var p = newParser:
    flag("-a", "--append", help="Append / to every request")
    flag("-r", "--recursion", help="Turn recursion on")
    flag("-q", "--quiet", help="Turn off printing to stdout")
    option("-t", "--threads", help="Specify number of threads to use. If value is under 5, option is ignored and single thread mode is enabled! ", default=some("10"))
    option("-w", "--wordlist", help="Specify path to wordlist", required=true)
    option("-u", "--url", help="Specify URL", required=true)
    option("-o", "--output", help="Specify an output file", default=some("stdout"))
    option("-x", "--extension", help="Specify extension to append to wordlist", multiple=true)
    option("--dt", help="Specify delay between creation of each thread  in seconds", default=some("0"))
    option("--dr", help="Specify delay between each HTTP request in seconds", default=some("1"))
    option("--ua", help="Specify a user agent", default=some("NimBust/"&version))
    option("--timeout", help="Specify HTTP request timeout in seconds", default=some("10"))
  
  var cmdLineOpt: tuple[doAppend: bool, threads: int, wordlist: string, url: string, output: string, extension: seq[string], tDelay: int, rDelay: float, timeout: int, userAgent: string, quietMode: bool, recursion: bool]
  
  try:
    var opts = p.parse()
    cmdLineOpt = (doAppend: opts.append, 
      threads: opts.threads.parseInt, 
      wordlist: opts.wordlist, 
      url: opts.url, 
      output: opts.output, 
      extension: opts.extension, 
      tDelay: opts.dt.parseInt, 
      rDelay: opts.dr.parseFloat, 
      timeout: opts.timeout.parseInt, 
      userAgent: opts.ua,
      quietMode: opts.quiet,
      recursion: opts.recursion)
  except ShortCircuit as err:
    if err.flag == "argparse_help":
        echo p.help
        quit(1)
  except UsageError:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)
  except ValueError:
    stdout.writeLine "Error: ", getCurrentExceptionMsg()
    quit(1)
  except:
    stdout.writeLine "Error: ", getCurrentExceptionMsg()
    quit(1)
    
  var threads = newSeq[Thread[ThreadData]](cmdLineOpt.threads)
  main(cmdLineOpt)

proc parseWordList(wordlist: string, thrNum: int): seq[seq[string]] =  
  var completeList: seq[string]
  try: 
    completeList = wordlist.lines.toSeq.filterIt(
       not it.startsWith("#") and not it.isEmptyOrWhitespace
      )
  except IOError:
    stdout.styledWriteLine(fgRed, "(Error)", fgDefault, fmt "Cannot open {wordlist}")
    quit(1)
  return completeList.distribute(thrNum)
  
proc bruteForce(options: tuple): void =
  var 
    url: string
    encodedWord: string
    appendedWord: string
    response: Response
    baseDirectories: seq[string]
  
  let client = newHttpClient(
    userAgent=options.userAgent,
    timeout=options.timeout*1000 # timeout in milliseconds
    ) 

  proc saveToFile(value: string): void =
    try:
      acquire(L)
      var outputFile = open(options.output, fmAppend)
      outputFile.writeLine(value)
      outputFile.close()
      release(L)
    except: 
      var error = getCurrentException()
      stdout.styledWriteLine(fgRed, fmt "(Error)", fgDefault, fmt "\t({error.msg})")  
  
  proc doRequest(urlString: string, word: string): void =
    try:
      response = client.head(urlString)
      defer: client.close()

      if not options.quietMode:
        if response.status.contains(@["200", "201"].HttpHeaderValues): 
          stdout.styledWriteLine(fgGreen, fmt "({response.status.splitWhitespace()[0]})", fgDefault, fmt "\t/{word}")
      
        elif response.status.contains(@["301", "302", "307", "308"].HttpHeaderValues): 
          stdout.styledWriteLine(fgYellow, fmt "({response.status.splitWhitespace()[0]})", fgDefault, fmt "\t/{word}")
        
        elif "404" notin response.status and "400" notin response.status: 
          stdout.styledWriteLine(fgRed, fmt "({response.status.splitWhitespace()[0]})", fgDefault, fmt "\t/{word}")    
    except CatchableError:
      var error = getCurrentException()
      if error.name == "TimeoutError":
        stdout.styledWriteLine(fgRed, fmt "(Error)", fgDefault, fmt "\t(Connection timed out!)\t(/{word})")
    except: 
      var error = getCurrentException()
      stdout.styledWriteLine(fgRed, fmt "(Error)", fgDefault, fmt "\t({error.name})\t({error.msg})")
    if options.output != "stdout" and "404" notin response.status: saveToFile(fmt "({response.status.splitWhitespace()[0]})\t/{word}")
        
  # Create new wordlist  
  if options.extension.len != 0:
    var newList: seq[string]
    for word in options.wordlist:
      encodedWord = if options.doAppend: word.encodeUrl & "/" else: word.encodeUrl
      newList.add(encodedWord)
      for extension in options.extension:
        let appendedWord = if extension.startsWith("."): encodedWord & extension else: encodedWord & "." & extension
        newList.add(appendedWord)
    
    for word in newList:
      doRequest(fmt "{options.baseUrl}/{word}", fmt "{word}")
      if options.recursion and "404" notin response.status:
        baseDirectories.add(word)
      sleep(int(options.rDelay*1000))
  else:
    for word in options.wordlist:
      encodedWord = if options.doAppend: word.encodeUrl & "/" else: word.encodeUrl
      doRequest(fmt "{options.baseUrl}/{word}", fmt "{word}")
      if options.recursion and "404" notin response.status:
        baseDirectories.add(word)
      sleep(int(options.rDelay*1000))
    if options.recursion:
      for baseDirectory in baseDirectories:
        for word in options.wordlist:
          doRequest(fmt "{options.baseUrl}/{baseDirectory}/{word}", fmt "{baseDirectory}/{word}")
    
proc main(options: tuple): void = 
  echo fmt"""
+=======================================================================================+
NimBust v{version}
by Eric Holloway (@RePRGM)
+=======================================================================================+"""
  echo "[*] Domain: ", options.url
  echo "[*] Wordlist: ", options.wordlist
  echo "[*] Threads: ", options.threads
  echo fmt"[*] Timeout: {options.timeout}s"
  stdout.styledWriteLine(fgDefault, "[*] Status Codes: [", fgGreen, "200, 201, ", fgYellow, "301, 302, 307, 308, ", fgRed, "401, 403, 405, 410", fgDefault, "]")
  echo "[*] Hide Status Code: 400, 404"
  
  if options.extension.len != 0:
    stdout.write("[*] Extensions: ")
    for extension in options.extension: stdout.write(extension & " ")
    stdout.write("\n")
  
  if options.output != "stdout": 
    echo "[*] Output File: ", options.output
    discard execCmd("echo \"NimBust Results\nUrl: $1\" > $2" % [options.url, options.output])
    
  if options.quietMode: echo "[*] Quiet Mode: Enabled"
  if options.tDelay != 0: echo "[*] Thread Delay: ", options.tDelay
  if options.recursion: echo "[*] Recursion: Enabled"

  echo "[*] Request Delay: ", options.rDelay, "s"
  echo "[*] User Agent: ", options.userAgent
  
  var subWordLists = parseWordList(options.wordlist, options.threads)
  echo fmt """
+=======================================================================================+
Starting NimBust: {getDateStr()} at {getClockStr()}
+=======================================================================================+"""
  if subWordLists.len < 5:
    echo "(Notice)\t(Less than 5 sublists created!)\t(Single thread mode enabled!)"
  elif subWordLists[0].len < 1000:
    echo "(Notice)\t (Small word list detected!)\t(Single thread mode enabled!)"
    for i in 0 ..< subWordLists.len:
      bruteForce((doAppend: options.doAppend, wordlist: subWordLists[i], baseUrl: options.url, extension: options.extension, output: options.output, rDelay: options.rDelay, timeout: options.timeout, userAgent: options.userAgent, quietMode: options.quietMode, recursion: options.recursion))
  else:
    for i in 0 ..< options.threads: 
      createThread(threads[i], bruteForce, (doAppend: options.doAppend, wordlist: subWordLists[i], baseUrl: options.url, extension: options.extension, output: options.output, rDelay: options.rDelay, timeout: options.timeout, userAgent: options.userAgent, quietMode: options.quietMode, recursion: options.recursion))
      sleep(options.tDelay*1000)
  joinThreads(threads)

  echo fmt """
+=======================================================================================+
Finished NimBust: {getDateStr()} at {getClockStr()}
+=======================================================================================+"""
  deinitLock(L)
