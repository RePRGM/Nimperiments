proc strlenA*(s: int): int =
  var sPtr = cast[ptr byte](s)
  while sPtr[] != 0.byte:
    sPtr = cast[ptr byte](cast[int](sPtr) + 1)
    result.inc
