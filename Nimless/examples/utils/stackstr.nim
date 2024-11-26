import std/[macros]

from std/parseutils import parseInt
from std/random import initRand, rand
from std/bitops import rotateRightBits

proc updateHash(): uint {.compileTime.} =
  var seed: int = 0
  when system.hostOS == "windows":
      discard parseInt(staticExec("powershell.exe Get-Random -Maximum 99999999 -Minimum 10000000"), seed, 0)
  else:
      discard parseInt(staticExec("bash -c 'echo $SRANDOM'"), seed, 0)
  var rng = initRand(seed)
  result = rng.rand(int.high).uint

proc assignChars(smt: NimNode, varName: NimNode, varValue: string, wide: bool, key: uint) {.compileTime.} =
  var
    asnNode:        NimNode
    bracketExpr:    NimNode
    dotExpr:        NimNode
    castIdent:      NimNode
  for i in 0 ..< varValue.len():
    asnNode     = newNimNode(nnkAsgn)
    bracketExpr = newNimNode(nnkBracketExpr)
    dotExpr     = newNimNode(nnkDotExpr)
    castIdent   =
      if wide:    ident"uint16"
      else:       ident"uint8"
    bracketExpr.add(varName)
    bracketExpr.add(newIntLitNode(i))
    dotExpr.add(newLit(
      (ord(varValue[i]).byte xor cast[byte](key.rotateRightBits(i))).char
    ))
    dotExpr.add(castIdent)
    asnNode.add bracketExpr
    asnNode.add dotExpr
    smt.add asnNode
  asnNode     = newNimNode(nnkAsgn)
  bracketExpr = newNimNode(nnkBracketExpr)
  dotExpr     = newNimNode(nnkDotExpr)
  bracketExpr.add(varName)
  bracketExpr.add(newIntLitNode(varValue.len()))
  dotExpr.add(newLit(0))
  dotExpr.add(castIdent)
  asnNode.add bracketExpr
  asnNode.add dotExpr
  smt.add asnNode

proc makeBracketExpression(s: string, wide: static bool): NimNode =
  result = newNimNode(nnkBracketExpr)
  result.add ident"array"
  result.add newIntLitNode(s.len() + 1)
  if wide:    result.add ident"uint16"
  else:       result.add ident"byte"

proc complexXor*[I,T](buf: var array[I, T], key: uint) {.inline, codegenDecl: "__attribute__((always_inline)) $# $#$#".} = 
  var i: int = 0
  while buf[i] != '\0'.T:
    buf[i] = (key.rotateRightBits(i) and 0xff).T xor buf[i]
    i.inc

macro stackStringA*(sect) =
  var globalHash = updateHash()
  template doXor(str, key: untyped): untyped = 
    {.noRewrite.}:
      complexXor(str, key)
  
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, false)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, false, globalHash)
  result.add(getAst(doXor(def[0], globalHash)))

macro stackStringW*(sect) =
  var globalHash = updateHash()
  template doXor(str, key: untyped): untyped = 
    {.noRewrite.}:
      complexXor(str, key)
  
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, true)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, true, globalHash)
  result.add(getAst(doXor(def[0], globalHash)))

template CPTR*(a: untyped): cstring =
  cast[cstring](a[0].addr)

template CWPTR*(a: untyped): ptr uint16 = 
  cast[ptr uint16](a[0].addr)