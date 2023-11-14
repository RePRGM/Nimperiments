#
# NimScript build file for EvilLsassTwin
# Run with "nim build" or "nim dependencies"
#

switch("verbosity", "1")
switch("warnings", "off")
switch("hints", "off")

task build, "Build Evil Lsass Twin":
    echo "Building Evil Lsass Twin..."
    exec "nim c -d:noRes -d:release --cpu:amd64 -d:danger -d:mingw --gc:orc -d:strip --opt:none --passL:-Wl,--dynamicbase -o=EvilLsassTwin.exe EvilLsassTwin.nim"
    exec "nim c -d:release --cpu:amd64 -d:danger --gc:orc -d:strip EvilTwinServer.nim"

task dependencies, "Install Dependencies":
    echo "Installing Dependencies..."

    echo "Installing Winim"
    exec "nimble install winim"

    echo "Installing ptr_math"
    exec "nimble install ptr_math"
