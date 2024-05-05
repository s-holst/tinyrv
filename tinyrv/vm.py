import sys, struct, time, dataclasses, argparse

import lief

from tinyrv import sim, zext

def load_elf(vm, elf, trace=False):
    if trace:
        print(f'ELF symbol table:')
        for s in elf.symbols:
            print(s)
    for s in elf.segments:
        if s.virtual_size > 0 and len(bytes(s.content)) > 0:
            if trace: print(f'loading {len(bytes(s.content))} bytes to {hex(s.virtual_address)}')
            vm.copy_in(s.virtual_address, bytes(s.content))
    vm.pc = elf.entrypoint
    if trace: print(f'ELF entry point: {hex(vm.pc)}')

@dataclasses.dataclass
class kernel_stat:
    st_dev:     int = 24    # unsigned long long
    st_ino:     int = 3     # unsigned long long
    st_mode:    int = 8592  # unsigned int
    st_nlink:   int = 1     # unsigned int
    st_uid:     int = 1000  # unsigned int
    st_gid:     int = 5     # unsigned int
    st_rdev:    int = 34816 # unsigned long long
    __pad1:     int = 0     # unsigned long long
    st_size:    int = 0     # long long
    st_blksize: int = 1024  # int
    __pad2:     int = 0     # int
    st_blocks:  int = 0     # long long
    st_atim:    int = int(time.monotonic())  # struct timespec
    st_mtim:    int = int(time.monotonic())  # struct timespec
    st_ctim:    int = int(time.monotonic())  # struct timespec
    __glibc_reserved1 = 0 # int
    __glibc_reserved2 = 0 # int

    def bytes(self):
        return struct.pack('QQIIIIQQqiiqIIIII',
            self.st_dev    ,
            self.st_ino    ,
            self.st_mode   ,
            self.st_nlink  ,
            self.st_uid    ,
            self.st_gid    ,
            self.st_rdev   ,
            self.__pad1    ,
            self.st_size   ,
            self.st_blksize,
            self.__pad2    ,
            self.st_blocks ,
            self.st_atim   ,
            self.st_mtim   ,
            self.st_ctim   ,
            self.__glibc_reserved1,
            self.__glibc_reserved2)

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
        self.x[self.sp], arg_data = self.pack_args(args) # puts argc and **argv on stack and init sp
        self.copy_in(self.x[self.sp], arg_data)

    def pack_args(self, args, sp=0x7fffffff):
        offsets, strings = [0], []
        for a in args:
            l = len(a)+1
            strings.append(struct.pack(f'{l}s', a.encode()))
            offsets.append(offsets[-1]+l)
        ptr_bytes = 4 if self.xlen == 32 else 8
        ptr_fmt = 'I' if self.xlen == 32 else 'Q'
        sp -= len(strings)*ptr_bytes + offsets[-1] - 1
        ptrs = []
        for o in offsets[:-1]: ptrs.append(struct.pack(ptr_fmt, sp+len(strings)*ptr_bytes+o))
        return sp-ptr_bytes, struct.pack(ptr_fmt, len(strings)) + b''.join(ptrs+strings)

    def _ecall(self, **_):
        syscall_no = self.x[self.a7]
        if syscall_no == 80:  # fstat
            fd = self.x[self.a0]
            out_mem_ptr = self.x[self.a1]
            self.copy_in(out_mem_ptr, kernel_stat().bytes())
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
            current_time = zext(32, int(time.perf_counter()*1000))
            self.store('I', 0x10000000, current_time, notify=False)
        return self.keep_running

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