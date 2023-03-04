# NimBust
NimBust is a directory brute-forcer written in, you guessed it, Nim! This project takes inspiration from both FeroxBuster and GoBuster and is meant to showcases the performance advantage compiled programming languages have over interpreted languages. In this case, that is through the use of multithreading with each thread being given an equal workload. NimBust is also meant to showcase Nim's simple, Python inspired-syntax giving developers the best of both worlds!

At present, the project only does directory brute forcing. Outputting to file, appending extensions, and recursion is currently not supported but may be added in the future.

# Dependencies 
At present, there is only a single dependency: OpenSSL.

# Installation
Once all dependencies are met, simply run `nim build` to create the project. 

# Usage
`nimbust <url> <wordlist> <threads>
