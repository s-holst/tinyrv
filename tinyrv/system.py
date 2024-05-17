#!/usr/bin/env python3
import time, struct, pickle, threading, queue, argparse, datetime, readchar, tinyrv

def walk_nodes(dts, strings, name=''):
    out = [struct.pack(f'>I{((len(name)+4)//4)*4}s', 1, name.encode())]  # FDT_BEGIN_NODE
    for k, v in dts.items():
        if isinstance(v, dict): out += walk_nodes(v, strings, name=k); continue
        if isinstance(v, int): extra = struct.pack('>I', v)
        elif isinstance(v, tuple): extra = struct.pack(f'>{len(v)}I', *v)
        elif isinstance(v, str): extra = struct.pack(f'{len(v)+1}s', v.encode())
        elif isinstance(v, list): extra = b''.join([struct.pack(f'{len(e)+1}s', e.encode()) if isinstance(e, str) else struct.pack('B', e) for e in v])
        strings[k] = strings.get(k, sum([len(n)+1 for n in strings]))
        out += [struct.pack('>III', 3, len(extra), strings[k]), extra + b'\x00'*(((len(extra)+3)//4)*4-len(extra))]  # FDT_PROP
    return out + [struct.pack('>I', 2)]  # FDT_END_NODE

def make_dtb(dts, boot_cpuid_phys=0):
    dt_struct = b''.join(walk_nodes(dts, strings := {}) + [struct.pack('>I', 9)]) # FDT_END
    dt_strings = b''.join([struct.pack(f'{len(s)+1}s', s.encode()) for s in strings])
    mem_rsvmap = struct.pack('>2Q', 0, 0)  # we don't have reserved memory
    off_dt_struct = 40+len(mem_rsvmap)
    off_dt_strings = off_dt_struct + len(dt_struct)
    dt_header = struct.pack('>10I', 0xd00dfeed, off_dt_strings+len(dt_strings), off_dt_struct, off_dt_strings, 40, 17, 16, boot_cpuid_phys, len(dt_strings), len(dt_struct))
    return b''.join([dt_header, mem_rsvmap, dt_struct, dt_strings])

class uart8250:  # Reference: INS8250 datasheet
    def __init__(self, system):
        self.system, self.size = system, 0x100
        self.reg_names = {i: n for i, n in enumerate('RBR_THR_DLL,IER_DLM,IIR,LCR,MCR,LSR,MSR,SCR'.split(','))}
        self.r, self.divisor, self.rxbuf = [0, 0, 0, 1, 0, 0, 0b0110_0000, 0, 0], 1, []  # reset values
    def __setitem__(self, addr, value):
        rname = self.reg_names.get(addr, 'ILLEGAL')
        if addr == 0:
            if self.r[3] & 0x80: rname = 'DLL'; self.divisor = self.divisor & ~0xff | (value&0xff)
            else: rname = 'THR'; print(chr(value), end='', flush=True)
        elif addr == 1:
            if self.r[3] & 0x80: rname = 'DLM'; self.divisor = self.divisor & 0xff | ((value&0xff)<<8)
            else: rname = 'IER'; self.r[1] = value & 0x0f
        elif addr in {3, 4, 6, 7}: self.r[addr] = value & (0x1f if addr==4 else 0xff)
        if self.system.trace_log is not None: self.system.trace_log.append(f'{{uart write {rname}}}')
    def __getitem__(self, addr):
        rname = self.reg_names.get(addr, 'ILLEGAL')
        self.r[2] = 0b100 if (self.r[1] & 0b001) and len(self.rxbuf) > 0 else 0b010 if self.r[1] & 0b010 else 0b001
        self.r[5] = 0b0110_0000 + (len(self.rxbuf) > 0)
        rval = self.r[addr]
        if addr == 0:
            if self.r[3] & 0x80: rname = 'DLL'; rval = self.divisor & 0xff
            else: rname = 'RBR'; rval = self.rxbuf.pop(0) if len(self.rxbuf) > 0 else 0
        elif addr == 1:
            if self.r[3] & 0x80: rname = 'DLM'; rval = (self.divisor>>8) & 0xff
            else: rname = 'IER'
        if self.system.trace_log is not None: self.system.trace_log.append(f'{{uart read {rname}}}')
        return rval
    def has_pending_irq(self): return (self.r[1] & 0b010) or ((self.r[1] & 0b001) and len(self.rxbuf) > 0)

class plic:  # FIXME very incomplete! Reference: https://static.dev.sifive.com/U54-MC-RVCoreIP.pdf
    def __init__(self, system) -> None:
        self.system, self.size = system, 0x600000
        self.pending, self.claimed_irq, self.next_to_claim = 0, -1, 0
        self.devices = []
    def add_device(self, irq, has_pending_irq_fn): self.devices.append((irq, has_pending_irq_fn))
    def update(self):
        for irq, pending_fn in self.devices:
            is_pending = pending_fn()
            if is_pending:
                if self.pending&(1<<irq) or irq==self.claimed_irq: return  # ignore (already pending or currently claimed)
                self.pending |= (1<<irq)
                self.next_to_claim = irq  # always next, since we only have one irq source (UART)
            else:
                self.pending &= ~(1<<irq)
                self.next_to_claim = 0  # we are the only one.
        if self.has_pending_irq(): self.system.csr[self.system.csr_mip] |= 1<<11  # set MEIP, machine external interrupt
        else: self.system.csr[self.system.csr_mip] &= ~(1<<11)
    def __setitem__(self, addr, value):
        if addr == 0x20_0004:  # complete
            if self.system.trace_log is not None: self.system.trace_log.append(f'{{plic complete}}')
            self.claimed_irq = -1  # written irq id is ignored by PLIC
            self.update()
    def __getitem__(self, addr):
        if addr == 0x20_0004: # claim
            if self.system.trace_log is not None: self.system.trace_log.append(f'{{plic claim}}')
            self.claimed_irq = self.next_to_claim
            self.pending &= ~(1<<self.claimed_irq)
            self.next_to_claim = 0
            if self.has_pending_irq(): self.system.csr[self.system.csr_mip] |= 1<<11  # set MEIP, machine external interrupt
            else: self.system.csr[self.system.csr_mip] &= ~(1<<11)
            return self.claimed_irq
        return 0
    def has_pending_irq(self): return self.next_to_claim != 0

class clint:  # eastwood(?) Core Local Interruptor. Reference: https://static.dev.sifive.com/U54-MC-RVCoreIP.pdf
    def __init__(self, system) -> None:
        self.system, self.size, self.mtimecmp = system, 0x10000, 0
    def mtime(self): return tinyrv.zext(64, self.system.get_host_clock()//self.system.flux_factor + self.system.flux_capacitor)
    def __getitem__(self, addr): return self.mtime() if addr == 0xbff8 else 0
    def __setitem__(self, addr, value):
        if addr == 0x4000: self.mtimecmp = value
    def has_pending_irq(self): return self.mtime() >= self.mtimecmp
    def update(self):
        if self.has_pending_irq(): self.system.csr[self.system.csr_mip] |= 1<<7  # timer expired, set MTIP
        else: self.system.csr[self.system.csr_mip] &= ~(1<<7)

class virt(tinyrv.sim):
    def __init__(self, image, ram_size, xlen=64, command_line=None):
        super().__init__(xlen=xlen, trap_misaligned=False)
        self.ram_size = ram_size

        self.flux_factor = 1000  # fake CPU speed factor to avoid thrashing the kernel scheduler
        self.deterministic = False
        self.enable_checkpoints = False
        self.syms = {}

        self.ram_base = 0x8000_0000
        self.clint_base, self.clint = 0x200_0000, clint(self)
        self.plic_base, self.plic = 0xc00_0000, plic(self)
        self.uart_base, self.uart = 0x1000_0000, uart8250(self)
        self.plic.add_device(0x0a, self.uart.has_pending_irq)

        dts = {'#address-cells': 2, '#size-cells': 2, 'compatible': "riscv-virt", 'model': "riscv-virt,qemu",
            'poweroff': {'value' : 0x5555, 'offset': 0, 'regmap': 4, 'compatible': "syscon-poweroff"},
            'reboot': {'value': 0x7777, 'offset': 0, 'regmap': 4, 'compatible': "syscon-reboot"},
            'cpus': {'#address-cells': 1, '#size-cells': 0, 'timebase-frequency': 0xf4240,
                'cpu@0': {'phandle': 1, 'device_type': "cpu", 'reg': 0, 'status': "okay", 'compatible': "riscv", 'riscv,isa': "rv64ima", 'mmu-type': "riscv,none",
                    'interrupt-controller': {'phandle': 2, '#interrupt-cells': 1, 'interrupt-controller' : [], 'compatible': "riscv,cpu-intc"},
                },
                'cpu-map': {'cluster0': {'core0': {'cpu': 1}}},
            },
            'soc': {'#address-cells': 2, '#size-cells': 2, 'compatible': "simple-bus", 'ranges': [],
                f'uart@{self.uart_base:x}': {'interrupts': 10, 'interrupt-parent': 3, 'clock-frequency': 0x1000000, 'reg': (0x00, self.uart_base, 0x00, self.uart.size), 'compatible': "ns16550a"},
                'syscon@100000': {'phandle': 4, 'reg': (0x00, 0x100000, 0x00, 0x1000), 'compatible': "syscon"},
                f'clint@{self.clint_base:x}': {'interrupts-extended': (2, 3, 2, 7), 'reg': (0x00, self.clint_base, 0x00, self.clint.size), 'compatible': ["sifive,clint0", "riscv,clint0"]},
                f'plic@{self.plic_base:x}': {'phandle': 3, 'riscv,ndev': 0x5f, 'reg': (0x00, self.plic_base, 0x00, self.plic.size), 'interrupts-extended': (2, 11, 2, 9), 'interrupt-controller': [], 'compatible': ["sifive,plic-1.0.0", "riscv,plic0"], '#address-cells': 0, '#interrupt-cells': 1},
            },
            f'memory@{self.ram_base:x}': {'device_type': "memory", 'reg': (0x00, self.ram_base, 0x00, self.ram_size)}
        }
        if command_line is not None: dts['chosen'] = {'bootargs': command_line}
        dtb_addr = self.ram_base+self.ram_size
        self.copy_in(dtb_addr, make_dtb(dts))
        self.copy_in(self.ram_base, image)

        # configure for launch
        self.start_input_thread()
        self.flux_capacitor = 0  # for time travel. how much have we advanced the clock while WFI
        self.host_clock_start = 0
        self.host_clock_start = self.get_host_clock()
        self.last_checkpoint = 0
        self.wfi = False
        self.pc = self.ram_base
        self.x[self.a0] = 0  # hart ID
        self.x[self.a1] = dtb_addr

    def get_host_clock(self):  # 1 MHz ticks since start
        return self.cycle if self.deterministic else time.monotonic_ns()//1000-self.host_clock_start

    def start_input_thread(self):  # start thread for capturing user key presses
        self.input = queue.Queue()
        def add_input(input):
            while True: input.put(readchar.readchar())
        threading.Thread(target=add_input, args=(self.input,), daemon=True).start()

    def __getstate__(self):
        self.last_checkpoint = self.get_host_clock()
        return {k: v for k, v in self.__dict__.items() if k not in {'input', 'op'}}

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.host_clock_start = 0
        self.host_clock_start = self.get_host_clock() - self.last_checkpoint
        self.start_input_thread()

    def notify_stored(self, addr):
        if addr >= self.ram_base: pass
        elif addr in range(self.clint_base, self.clint_base+self.clint.size): self.clint[addr-self.clint_base] = struct.unpack_from('Q', *self.page_and_offset(addr))[0]
        elif addr in range(self.uart_base, self.uart_base+self.uart.size): self.uart[addr-self.uart_base] = struct.unpack_from('B', *self.page_and_offset(addr))[0]
        elif addr in range(self.plic_base, self.plic_base+self.plic.size): self.plic[addr-self.plic_base] = struct.unpack_from('I', *self.page_and_offset(addr))[0]

    def notify_loading(self, addr):
        if addr >= self.ram_base: pass
        elif addr in range(self.clint_base, self.clint_base+self.clint.size): struct.pack_into('Q', *self.page_and_offset(addr), self.clint[addr-self.clint_base])
        elif addr in range(self.plic_base, self.plic_base+self.plic.size): struct.pack_into('I', *self.page_and_offset(addr), self.plic[addr-self.plic_base])
        elif addr in range(self.uart_base, self.uart_base+self.uart.size): struct.pack_into('B', *self.page_and_offset(addr), self.uart[addr-self.uart_base])

    def hook_csr(self, csr, reqval):
        if csr == 0x139: char = chr(reqval); print(char, end='', flush=True)  # mini-rv32ima console output: https://github.com/cnlohr/mini-rv32ima
        elif csr == 0x140: return super().hook_csr(csr, -1 if self.input.empty() else ord(self.input.get()))  # mini-rv32ima console input
        return super().hook_csr(csr, reqval)

    def interrupt_fired(self):
        if not self.input.empty(): self.uart.rxbuf.append(ord(self.input.get()))
        self.plic.update()
        self.clint.update()

        if self.csr[self.csr_mstatus] & 0x8:  # master interrupt enable
            for irq in (11, 7, 3): # external, timer, software - in that order of priority.
                if  self.csr[self.csr_mie] & self.csr[self.csr_mip] & (1<<irq):
                    if self.trace_log is not None: print(f'\n{{mtrap from_mode={self.current_mode} irq={irq} cycle={self.cycle} pc={self.pc} op={str(self.op)}}}\n')  # print here, because op will not execute.
                    self.mtrap(0, tinyrv.sext(self.xlen, irq | (1<<(self.xlen-1))))
                    self.wfi = False
                    return True
        return False

    def hook_exec(self):
        if self.enable_checkpoints and self.get_host_clock() >= (self.last_checkpoint + 30_000_000):
            with open(f'checkpoint-{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}-{self.cycle}.pkl', 'wb') as f: print(f'<<<--- {f.name} ...', end='', flush=True); pickle.dump(self, f); print(f' written. --->>>')
        if (self.cycle % 1000) == 0 and self.interrupt_fired(): return False  # don't execute current op
        while self.wfi:
            time.sleep(0.005); self.flux_capacitor += 5*self.flux_factor  # when waiting, run the clock at real-time speed.
            if self.interrupt_fired(): return False  # done waiting. don't execute current op
        if (self.trace_log is not None) and (self.op.addr in self.syms): self.trace_log.append(f'<{self.syms[self.op.addr]}>')
        return super().hook_exec()  # continue normally

    def _wfi(self, **_): self.pc += 4; self.csr[self.csr_mstatus] |= 0x8; self.wfi = True

def run_virt():
    parser = argparse.ArgumentParser(prog='tinyrv-system-virt', description='Emulates a minimal system similar to "virt" from qemu.')
    parser.add_argument('-k', '--kernel', type=argparse.FileType('rb'), help='Linux kernel image to boot')
    parser.add_argument('-m', '--memory', type=int, default=64, help='RAM size in MiB')
    parser.add_argument('-32', '--xlen32', action='store_true', help='Emulate a 32-bit system (default is 64-bit)')
    parser.add_argument('-f', '--flux', type=int, default=1000, help='Slows down the VM clock by this factor (default=1000) to mitigate thread starving. Actual simulation speed is about 1 MHz - running the clock real-time thrashes the 1 kHz scheduler loop and likely corrupts the stack. If your python is too slow, add more flux.')
    parser.add_argument('-t', '--trace', action='store_true', help='Prints everything happening in the simulator')
    parser.add_argument('-s', '--systemmap', type=argparse.FileType('r'), default=None, help='Enhance tracing with symbols from given System.map')
    parser.add_argument('-c', '--checkpoints', action='store_true', help='Store a checkpoint every 30s')
    parser.add_argument('-r', '--resume', type=argparse.FileType('rb'), default=None, help='Resume simulation from given checkpoint (ignores -k, -m)')
    parser.add_argument('-l', '--limit', type=int, default=0, help='Limit number of executed instructions (0=unlimited)')
    parser.add_argument('-d', '--deterministic', action='store_true', help='Repeatable simulations by using instruction cycle count as clock instead of real time. ')
    parser.add_argument('args', nargs='*', help='bootargs passed to the kernel')
    args = parser.parse_args()
    if args.resume: machine = pickle.load(args.resume); print(f'<<<--- resuming from {args.resume.name} at cycle: {machine.cycle} pc: {hex(machine.pc)} --->>>')
    elif args.kernel: machine = virt(args.kernel.read(), ram_size=args.memory*1024*1024, xlen=32 if args.xlen32 else 64); print(f'<<<--- booting {args.kernel.name} with {args.memory} MiB RAM --->>>')
    else: parser.print_usage(); print('error: need at least a kernel (-k) or a checkpoint to resume from (-r).'); exit(1)
    if args.systemmap: machine.syms = {int('0x'+addr, 16): sym for addr, _, sym in [l.split() for l in args.systemmap.readlines()]}
    machine.enable_checkpoints, machine.flux_factor, machine.deterministic = args.checkpoints, args.flux, args.deterministic
    machine.run(args.limit, trace=args.trace)

if __name__ == '__main__': run_virt()