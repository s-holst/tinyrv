#!/usr/bin/env python3
import subprocess
from pathlib import Path

from tinyrv import rvsim

# git clone https://github.com/riscv-software-src/riscv-tests.git
# cd riscv-tests
# autoconf
# ./configure
# make

class rvsim2(rvsim):
    def _ecall(self, **_):
        if self.x[self.a7] == 93 and self.x[self.a0] == 0:
            rv.passed = True
        else:
            print(f'test failed ({self.x[self.a0]})')

for f in Path('riscv-tests/isa').glob('rv??ui-p-*'):
    if '.' in str(f): continue
    subprocess.run(f'riscv64-unknown-elf-objcopy -O binary {str(f)} {str(f)}.bin'.split(' ')) 
    print('running', f)
    rv = rvsim2(xlen=64 if 'rv64' in str(f) else 32, misaligned_exceptions=False)
    rv.read_bin(str(f)+'.bin', base=0)
    rv.passed = False
    rv.run(2000, trace=False)
    if not rv.passed:
        print(f'test failed!!! {f}')
        exit(1)
