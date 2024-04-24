#!/usr/bin/env python3
import subprocess
from tinyrv import rvmem, rvsim

subprocess.run('riscv64-unknown-elf-objcopy -O binary my.elf my.bin'.split(' '))

syms = dict((fields[-1], int(fields[0],16)) for fields in [line.decode().strip().split(' ') for line in subprocess.Popen(['riscv64-unknown-elf-objdump', '-t', 'my.elf'], stdout=subprocess.PIPE).stdout.readlines()] if len(fields) > 2 and fields[1] in ('l', 'g'))

mem = rvmem(xlen=32)  # xlen just for output formatting
mem.load('my.bin', base=syms['.text.init'])
rv = rvsim(mem, xlen=32)
rv.pc = syms['.text.init']
rv.step(40000, bpts={syms['rvtest_code_end']})

with open('DUT-tinyrv.signature', 'w') as f:
    for addr in range(syms['begin_signature'], syms['end_signature'], 4):
        f.write(f'{mem.l(addr,"I"):08x}\n')
    if rv.op.addr != syms['rvtest_code_end']:
        #f.write('test unfinished!\n')
        print(f'test unfinished? {rv.op.addr:016x} {syms["rvtest_code_end"]:016x}')
