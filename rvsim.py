#!/usr/bin/env python3
import sys, tinyrv
if len(sys.argv) < 2: print(f'usage: {sys.argv[0]} file.bin [(32|64) [start PC in hex [run limit]]]'); exit(1)
xlen = 32 if len(sys.argv) < 3 else int(sys.argv[2])
mem = tinyrv.rvmem(xlen=xlen)
mem.read(sys.argv[1], base=0)
rv = tinyrv.rvsim(mem, xlen=xlen, misaligned_exceptions=False)
rv.pc = 0 if len(sys.argv) < 4 else int(sys.argv[3], 16)
rv.run(0 if len(sys.argv) < 5 else int(sys.argv[4]))