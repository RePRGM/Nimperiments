#
# NimScript build file for NimBust
# Run with "nim build"
#

switch("verbosity", "1")
switch("warnings", "off")
switch("hints", "off")

task build, "Build NimBust":
    echo "Building NimBust..."
    exec "nim c -d:danger -d:ssl --threads:on --mm:arc -d:strip -d:release --cpu:amd64 nimbust.nim"
    echo "Done!"
