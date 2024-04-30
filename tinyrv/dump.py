#!/usr/bin/env python3
import sys, pathlib, tinyrv

def main():
    if len(sys.argv) < 2: print(f'usage {pathlib.Path(sys.argv[0]).name} (file.bin | hex [hex ...])'); exit(1)
    for op in tinyrv.decoder(*sys.argv[1:]):
        print(f'{tinyrv.zext(64,op.addr):08x}: {str(op):40} # {", ".join(op.extension) if op.valid() else "INVALID data=" + hex(op.data)}')

if __name__ == '__main__': main()