import os, array, sys, pathlib, struct, tinyrv
from .common import decode

def rvsplitter(*data, base=0, lower16=0):  # yields addresses and 32-bit/16-bit(compressed) RISC-V instruction words.
    for addr, instr in enumerate(struct.iter_unpack('<H', open(data[0],'rb').read() if isinstance(data[0],str) and os.path.isfile(data[0]) else array.array('I',[int(d,16) if isinstance(d,str) else d for d in (data[0] if hasattr(data[0], '__iter__') and not isinstance(data[0],str) else data)]))):
        if lower16: yield int(base)+(addr-1)*2, (instr[0]<<16)|lower16; lower16 = 0
        elif instr[0]&3 == 3: lower16 = instr[0]  # Two LSBs set: 32-bit instruction
        else: yield int(base)+addr*2, instr[0]

def decoder(*data, base=0):  # yields decoded instructions.
    for addr, instr in rvsplitter(*data, base=base):
        if instr != 0: yield decode(instr, addr)

def main():
    if len(sys.argv) < 2: print(f'usage {pathlib.Path(sys.argv[0]).name} (file.bin | hex [hex ...])'); exit(1)
    for op in tinyrv.decoder(*sys.argv[1:]):
        print(f'{tinyrv.zext(64,op.addr):08x}: {str(op):40} # {", ".join(op.extension) if op.valid() else "INVALID data=" + hex(op.data)}')

if __name__ == '__main__': main()