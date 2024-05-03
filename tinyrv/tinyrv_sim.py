#!/usr/bin/env python3
import sys, pathlib, tinyrv

def main():
    if len(sys.argv) < 2: print(f'usage: {pathlib.Path(sys.argv[0]).name} file.bin [(32|64) [run limit in decimal [start PC in hex]]]'); exit(1)
    xlen = 32 if len(sys.argv) < 3 else int(sys.argv[2])
    limit = 0 if len(sys.argv) < 4 else int(sys.argv[3])
    pc = 0 if len(sys.argv) < 5 else int(sys.argv[4], 16)
    rv = tinyrv.sim(xlen=xlen, trap_misaligned=False)
    rv.copy_in(0, open(sys.argv[1], 'rb').read())
    rv.pc = pc
    rv.run(limit)

if __name__ == '__main__': main()