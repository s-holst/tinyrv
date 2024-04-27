#!/usr/bin/env python3
import sys, subprocess
from tinyrv import rvsim

xlen = int(sys.argv[1])

subprocess.run('riscv64-unknown-elf-objcopy -O binary my.elf my.bin'.split(' '))

syms = dict((fields[-1], int(fields[0],16)) for fields in [line.decode().strip().split(' ') for line in subprocess.Popen(['riscv64-unknown-elf-objdump', '-t', 'my.elf'], stdout=subprocess.PIPE).stdout.readlines()] if len(fields) > 2 and fields[1] in ('l', 'g'))

rv = rvsim(xlen=xlen)
rv.read_bin('my.bin', base=syms['.text.init'])
rv.pc = syms['.text.init']
rv.run(16000, bpts={syms['rvtest_code_end']})

with open('DUT-tinyrv.signature', 'w') as f:
    for addr in range(syms['begin_signature'], syms['end_signature'], 4):
        f.write(f'{rv.load(addr,"I"):08x}\n')
    if rv.op.addr != syms['rvtest_code_end']:
        print(f'test unfinished? {rv.op.addr:016x} {syms["rvtest_code_end"]:016x}')
