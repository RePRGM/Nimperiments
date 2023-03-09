# NimBust

NimBust is a directory brute force tool (or, as I guess we're calling it now, a "content discovery" tool) written in (you guessed it) Nim! It is a compiled, threaded application with most of the basic features one would expect from a directory brute force tool implemented. NimBust makes use of multithreading and evenly distributed workloads to be as fast as possible, however, it is also possible to slow NimBust down as needed. _We wouldn't want to cause a DOS, afterall_. 

As Nim 2.0 approaches, it is worth mentioning this project was built upon Nim 1.6.10 which, at the time of writing, is the current stable version of Nim.

# Dependencies 
At present, there are only two dependencies: OpenSSL. Install with your system package manager if it is not already installed. You will also need the argparse Nim module. This can be installed through Nimble e.g. `nimble install argparse`

# Installation
Once all dependencies are met, clone the repo and simply run `nim build` to create the project. 

# Usage
`nimbust -h` or `nimbust --help` will display the help menu. Everything should be self-explanatory. 
