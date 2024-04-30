#!/usr/bin/env python3
import time, struct, gzip, threading, queue
import readchar
from tinyrv import sim, zext, sext

# Heavily based on https://github.com/cnlohr/mini-rv32ima Big thanks to CNLohr!
class rvlinux(sim):
    def __init__(self, image, dtb, ram_size, command_line):
        super().__init__(xlen=32, trap_misaligned=False)
        self.ram_size = ram_size
        self.ram_base = 0x8000_0000

        # load kernel image
        self.copy_in(image, self.ram_base)

        # load and patch DTB
        dtb_addr = self.ram_base+self.ram_size
        self.copy_in(dtb, dtb_addr)
        struct.pack_into('>I', *self.page_and_offset(dtb_addr+0x13c), ram_size)
        struct.pack_into('54s', *self.page_and_offset(dtb_addr+0xc0), command_line.encode())

        # set up initial vm state
        self.pc = self.ram_base
        self.x[self.a0] = 0  # hart ID
        self.x[self.a1] = dtb_addr
        self.wfi = False
        self.flux_capacitor = 0  # for time travel

        # start thread for capturing user key presses
        self.input = queue.Queue()
        def add_input(input):
            while True: input.put(readchar.readchar())
        threading.Thread(target=add_input, args=(self.input,), daemon=True).start()

    def copy_in(self, bytes, base=0):
        for po in range(0, len(bytes), self.mem_psize):
            page, pa = self.page_and_offset(base+po)
            assert pa == 0, f"base must be aligned to page size ({self.mem_psize})."
            nbytes = min(len(bytes)-po, self.mem_psize)
            page[0:nbytes] = bytes[po:po+nbytes]

    def hook_csr(self, csr, reqval):
        if csr == 0x139: char = chr(reqval); print(char, end='')  # console output
        elif csr == 0x140: return super().hook_csr(csr, -1 if self.input.empty() else ord(self.input.get()))  # console input
        return super().hook_csr(csr, reqval)

    def timer_fired(self):
        # multiplier should actually be *1_000_000. clock runs 1000x slower than real-time to avoid kernel panic.
        current_time = zext(64, int(time.perf_counter()*1000 + self.flux_capacitor))
        match_time = self.load('Q', 0x1100_4000, notify=False)
        self.store('Q', 0x1100bff8, current_time, notify=False)
        if current_time >= match_time: self.csr[self.mip] |= 1<<7  # timer expired
        else: self.csr[self.mip] &= ~(1<<7)
        if (self.csr[self.mstatus]&0x8) and (self.csr[self.mie]&self.csr[self.mip]&(1<<7)):
            self.mtrap(0, sext(32, 0x8000_0007))
            self.current_mode = 3
            self.wfi = False
            return True
        return False

    def hook_exec(self):
        if (self.cycle % 1000) == 0 and self.timer_fired(): return False  # don't execute current op
        while self.wfi:
            time.sleep(0.005); self.flux_capacitor += 5000  # when waiting, no harm in running clock close to real-time.
            if self.timer_fired(): return False  # done waiting. don't execute current op
        return super().hook_exec()  # continue normally

    def _wfi(self, **_): self.pc += 4; self.csr[self.mstatus] |= 0x8; self.wfi = True

if __name__ == '__main__':
    linux = rvlinux(gzip.open('Image.gz', 'rb').read(), open('sixtyfourmb.dtb', 'rb').read(), ram_size=64*1024*1024, command_line='console=hvc0')
    print('booting linux...')
    linux.run(0, trace=False)