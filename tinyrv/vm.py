import sys, struct, time, argparse

import lief
import dataclasses_struct as dcs

from tinyrv import sim, zext

def load_elf(vm, elf, trace=False):  # TODO: relocations
    if trace:
        print(f'ELF symbol table:')
        for s in elf.symbols:
            print(s)
    for s in elf.segments:
        if trace: print(s)
        if s.virtual_size > 0 and len(bytes(s.content)) > 0:
            if trace: print(f'loading {len(bytes(s.content))} bytes to {hex(s.physical_address)}')
            vm.copy_in(s.physical_address, bytes(s.content))
    vm.pc = elf.entrypoint
    if trace: print(f'ELF entry point: {hex(vm.pc)}')

def pack_args(args, xlen=32, sp=0x80000000):
    offsets, strings = [0], []
    for a in args:
        l = len(a)+1
        strings.append(struct.pack(f'{l}s', a.encode()))
        offsets.append(offsets[-1]+l)
    ptr_bytes = 4 if xlen == 32 else 8
    ptr_fmt = 'I' if xlen == 32 else 'Q'
    padding = ptr_bytes - (offsets[-1] % ptr_bytes)
    sp -= len(strings)*ptr_bytes + padding + offsets[-1]
    ptrs = []
    for o in offsets[:-1]: ptrs.append(struct.pack(ptr_fmt, sp+len(strings)*ptr_bytes+o+padding))
    return sp-ptr_bytes, struct.pack(ptr_fmt, len(strings)) + b''.join(ptrs+([b'\0']*padding)+strings)

@dcs.dataclass()
class kernel_stat2:
    st_dev:     dcs.U64 = 24
    st_ino:     dcs.U64 = 3
    st_mode:    dcs.U32 = 8592
    st_nlink:   dcs.U32 = 1
    st_uid:     dcs.U32 = 1000
    st_gid:     dcs.U32 = 5
    st_rdev:    dcs.U64 = 34816
    __pad1:     dcs.U64 = 0
    st_size:    dcs.I64 = 0
    st_blksize: dcs.I32 = 1024
    __pad2:     dcs.I32 = 0
    st_blocks:  dcs.I64 = 0
    st_atim:    dcs.I32 = int(time.monotonic())  # struct timespec
    st_mtim:    dcs.I32 = int(time.monotonic())  # struct timespec
    st_ctim:    dcs.I32 = int(time.monotonic())  # struct timespec
    __glibc_r1: dcs.I32 = 0
    __glibc_r2: dcs.I32 = 0

class linux(sim):
    def __init__(self, elf_file, args=[], trace=False):
        elf = lief.parse(elf_file)
        assert elf.header.machine_type == lief.ELF.ARCH.RISCV
        super().__init__(xlen=32 if elf.header.identity_class == lief.ELF.ELF_CLASS.CLASS32 else 64, trap_misaligned=False)
        self.elf_file, self.elf = elf_file, elf
        self.trace = trace
        load_elf(self, self.elf, trace=trace)
        heap_end_sym = self.elf.get_symbol('heap_end.0')
        self.heap_end = heap_end_sym.value if heap_end_sym is not None else 0xa0000000
        self.keep_running = True
        self.exitcode = 0
        self.x[self.sp], arg_data = pack_args(args, self.xlen)  # puts argc and **argv on stack and init sp
        self.copy_in(self.x[self.sp], arg_data)
        self.start_time = time.perf_counter()

    def _ecall(self, **_):
        # helpful: https://jborza.com/post/2021-05-11-riscv-linux-syscalls/
        syscall_no = self.x[self.a7]
        if syscall_no == 80:  # fstat
            fd = self.x[self.a0]
            out_mem_ptr = self.x[self.a1]
            self.copy_in(out_mem_ptr, kernel_stat2().pack())
            self.x[self.a0] = 0  # success
            self.pc += 4
            return
        elif syscall_no == 214:  # sbrk
            increment = self.x[self.a0]
            self.heap_end += increment
            self.x[self.a0] = self.heap_end  # return new heap_end
            self.pc += 4
            return
        elif syscall_no == 64:  # write
            fd = self.x[self.a0]
            ptr = self.x[self.a1]
            length = self.x[self.a2]
            #print(f'\nwriting {fd} {hex(ptr)} {length}\n')
            data = self.copy_out(ptr, length)
            s = data.decode()
            if fd == 1:
                print(s, end='', flush=True)
                self.x[self.a0] = length
                self.pc += 4
                return
            elif fd == 2:
                print(s, end='', flush=True, file=sys.stderr)
                self.x[self.a0] = length
                self.pc += 4
                return
            else:
                print(f'write to unknown file handle')
        elif syscall_no == 57:  # close
            fd = self.x[self.a0]
            #print(f'close file {fd}')
            self.x[self.a0] = 0  # success
            self.pc += 4
            return
        elif syscall_no == 93:  # exit
            self.exitcode = self.x[self.a0]
            if self.trace: print(f'exit {self.exitcode}')
            self.x[self.a0] = 0  # success
            self.pc += 0  # stop here. self.run will return since pc is unchanged.
            return
        else:
            print(f'linux: unimplemented syscall {syscall_no} at {hex(self.pc)}')
        self.mtrap(0, 8 if self.current_mode == 0 else 11)

    def hook_exec(self):
        if (self.cycle % 1000) == 0:
            current_time = zext(32, int((time.perf_counter()-self.start_time)*1000000))
            self.store('I', 0x1100bff8, current_time, notify=False)
        return self.keep_running

class semihosting(sim):
    def __init__(self, elf_file, args=[], trace=False):
        elf = lief.parse(elf_file)
        assert elf.header.machine_type == lief.ELF.ARCH.RISCV
        super().__init__(xlen=32 if elf.header.identity_class == lief.ELF.ELF_CLASS.CLASS32 else 64, trap_misaligned=False)
        self.elf_file, self.elf = elf_file, elf
        self.trace = trace
        load_elf(self, self.elf, trace=trace)
        self.exitcode = 0
        self.x[self.sp], arg_data = pack_args(args, self.xlen)  # puts argc and **argv on stack and init sp
        self.copy_in(self.x[self.sp], arg_data)

    def _ebreak(self, **_):
        if self.load('I', self.op.addr-4, 0, notify=False) != 0x01f01013: return super()._ebreak()  # check slli zero,zero,0x1f before
        if self.load('I', self.op.addr+4, 0, notify=False) != 0x40705013: return super()._ebreak()  # check srai zero,zero,0x7 after
        # we have a semihost call
        semihost_no = self.x[self.a0]
        semihost_param = self.x[self.a1]
        ptr_bytes = 4 if self.xlen == 32 else 8
        ptr_fmt = 'I' if self.xlen == 32 else 'Q'
        if semihost_no == 1:  # open
            file_ptr = self.load('I', semihost_param, 0, notify=False)
            s = []
            while (c := self.load('B', file_ptr, 0, notify=False)) != 0:
                s.append(chr(c))
                file_ptr += 1
            fname = ''.join(s)
            mode = self.load(ptr_fmt, semihost_param+ptr_bytes, 0, notify=False)
            #fnlen = self.load('I', semihost_param+ptr_bytes*2, 0, notify=False)
            handle = {(':tt', 0): 1, (':tt', 4): 2, (':tt', 8): 3}.get((fname, mode), -1)  # r:stdin, w:stdout, a:stderr
            #print(f'open {fname} mode {mode} -> {handle}')
            self.x[self.a0] = handle
            self.pc += 4
        elif semihost_no == 0x0c:  # flen
            handle = self.load(ptr_fmt, semihost_param, 0, notify=False)
            flen = 0
            #print(f'flen {handle} -> {flen}')
            self.x[self.a0] = flen
            self.pc += 4
        elif semihost_no == 0x09:  # istty
            handle = self.load(ptr_fmt, semihost_param, 0, notify=False)
            #print(f'istty {handle} -> 1')
            self.x[self.a0] = 1
            self.pc += 4
        elif semihost_no == 0x05:  # write
            handle = self.load(ptr_fmt, semihost_param, 0, notify=False)
            ptr = self.load(ptr_fmt, semihost_param+ptr_bytes, 0, notify=False)
            length = self.load(ptr_fmt, semihost_param+ptr_bytes*2, 0, notify=False)
            s = self.copy_out(ptr, length).decode()
            print(s, end='', flush=True)
            #print(f'write {hex(ptr)} {length}')
            self.x[self.a0] = 0
            self.pc += 4
        elif semihost_no == 0x02:  # close
            handle = self.load(ptr_fmt, semihost_param, 0, notify=False)
            #print(f'close {handle} -> 0')
            self.x[self.a0] = 0
            self.pc += 4
        elif semihost_no == 0x18:  # exit
            reason = semihost_param
            #print(f'exit {hex(reason)} -> 0')
            self.x[self.a0] = 0
            self.exitcode = semihost_param != 0x20026  # exit 1 if not a normal application exit.
        else:
            print(f'unknown semihost {hex(semihost_no)} {hex(semihost_param)} from {hex(self.op.addr)}')
            return super()._ebreak()

class htif(sim):  # Berkeley Host-Target Interface (HTIF)
    def __init__(self, elf_file, args=[], trace=False):
        elf = lief.parse(elf_file)
        assert elf.header.machine_type == lief.ELF.ARCH.RISCV
        super().__init__(xlen=32 if elf.header.identity_class == lief.ELF.ELF_CLASS.CLASS32 else 64, trap_misaligned=True)
        self.elf_file, self.elf = elf_file, elf
        self.trace = trace
        load_elf(self, self.elf, trace=trace)
        self.fromhost_addr = elf.get_symbol('fromhost').value
        self.tohost_addr = elf.get_symbol('tohost').value
        self.keep_running = True
        self.exitcode = 0

    def notify_stored(self, addr):
        if addr == self.tohost_addr:
            data = struct.unpack_from('I', *self.page_and_offset(addr))[0]
            if data & 1:
                self.exitcode = data>>1
                if self.trace: print(f'exit: {self.exitcode}')
                self.keep_running = False
            else:
                # data is a ptr to more info
                which, arg0, arg1, arg2 = self.load('Q', data), self.load('Q', data+8), self.load('Q', data+16), self.load('Q', data+24)
                if which == 64:
                    s = ''.join(chr(self.load('B', addr)) for addr in range(arg1, arg1+arg2))
                    print(s, end='', flush=True)
                    self.store('I', self.fromhost_addr, 1, notify=False)  # acknowledge
                else:
                    print(f'unknown syscall {hex(data)} {which} {arg0} {hex(arg1)} {arg2}')
                    self.keep_running = False
        return super().notify_stored(addr)
    def hook_exec(self):
        # if (self.cycle % 1000) == 0:
        #     current_time = zext(32, int(time.perf_counter()*1000))
        #     self.store('I', 0x10000000, current_time, notify=False)
        return self.keep_running

def run_riscof_vm():
    parser = argparse.ArgumentParser(
                    prog='tinyrv-vm-riscof',
                    description='Runs a riscof test and prints the signature.')
    parser.add_argument('-t', '--trace', action='store_true')
    parser.add_argument('elf', type=argparse.FileType('rb'))
    args = parser.parse_args()
    vm = htif(args.elf, trace=args.trace)
    vm.run(0, trace=args.trace)
    begin_signature = vm.elf.get_symbol('begin_signature').value
    end_signature = vm.elf.get_symbol('end_signature').value
    for addr in range(begin_signature, end_signature, 4):
        print(f'{vm.load("I",addr):08x}')
    return vm.exitcode

def run_semihosting_vm():
    parser = argparse.ArgumentParser(
                    prog='tinyrv-vm-semihosting',
                    description='Runs the binary with semihosting.')
    parser.add_argument('-t', '--trace', action='store_true')
    parser.add_argument('-l', '--limit', type=int, default=0)
    parser.add_argument('elf', type=argparse.FileType('rb'))
    parser.add_argument('args', nargs='*')
    args = parser.parse_args()
    vm = semihosting(args.elf, [args.elf.name] + args.args, trace=args.trace)
    vm.run(args.limit, trace=args.trace)
    return vm.exitcode

def run_linux_vm():
    parser = argparse.ArgumentParser(
                    prog='tinyrv-vm-linux',
                    description='Emulates a minimal linux userspace. Supports argv/argv and a few syscalls.')
    parser.add_argument('-t', '--trace', action='store_true')
    parser.add_argument('elf', type=argparse.FileType('rb'))
    parser.add_argument('args', nargs='*')
    args = parser.parse_args()
    vm = linux(args.elf, [args.elf.name] + args.args, trace=args.trace)
    vm.run(0, trace=args.trace)
    return vm.exitcode

if __name__ == '__main__':
    exit(run_linux_vm())