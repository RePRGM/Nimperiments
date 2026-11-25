#!/bin/sh
# Usage: tests/run.sh [--native]   (needs `nimony` on PATH)
cd "$(dirname "$0")"
BACKEND="$1"
fail=0
for t in tdiff tapi; do
  nimony c $BACKEND -r $t.nim 2>&1 | grep -v Warning > $t.out
  if diff -q $t.out $t.expected > /dev/null; then echo "PASS $t"; else echo "FAIL $t"; fail=1; fi
done
for f in compile_errors/*.nim; do
  if nimony c "$f" > /dev/null 2>&1; then echo "FAIL $f compiled"; fail=1
  else echo "PASS $f: $(nimony c "$f" 2>&1 | grep -m1 Error | sed 's/.*Error: //')"; fi
done
exit $fail
