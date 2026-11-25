import sys
exec(open("gen.py").read().split("nim = [")[0])  # reuse spec/value lists
labels=[]
for s in ispecs: labels += [(s,v) for v in ints if (s!="c" or 32<=v<=126)]
for s in fspecs: labels += [(s,v) for v in floats]
for s in sspecs: labels += [(s,v) for v in strs]
e=open("expected.txt").read().splitlines(); g=open(sys.argv[1]).read().splitlines()
bad=[(l,a,b) for l,a,b in zip(labels,e,g) if a!=b]
print(len(bad),"mismatches of",len(e))
for (s,v),a,b in bad[:int(sys.argv[2]) if len(sys.argv)>2 else 60]: print(f"{s!r:10} {v!r:24} py={a:28} us={b}")
