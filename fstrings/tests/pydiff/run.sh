#!/usr/bin/env bash
# Differential test against CPython: python3 gen.py writes diffcheck.nim and
# expected.txt (CPython's own output); we compile with Nimony and compare.
# Usage: ./run.sh [c|n|l]   (C, native, or LLVM backend; default c)
set -e
cd "$(dirname "$0")"
backend=${1:-c}
python3 gen.py
nimony "$backend" -r diffcheck.nim 2>/dev/null > got_$backend.txt
python3 cmp.py got_$backend.txt
