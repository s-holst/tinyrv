#!/usr/bin/env python3
import tinyrv, struct
from tinyrv.system import uart8250

class fwsim(tinyrv.sim):
    def __init__(self, xlen=64, trap_misaligned=True):
        super().__init__(xlen, trap_misaligned)
        self.uart = uart8250(self)
    def _custom0   (self, **_): self.pc+=4
    def notify_stored(self, addr):
        if addr == 0x10000000: self.uart[0] = struct.unpack_from('B', *self.page_and_offset(addr))[0]

def main():
    rv = fwsim(xlen=32, trap_misaligned=False)
    rv.copy_in(0, open('tinyrv-test-blobs/picorv32_fw/firmware.bin', 'rb').read())
    rv.pc = 0
    rv.run(10, trace=False)
    rv.run(0, bpts={0x3e0}, trace=False)

if __name__ == '__main__': main()