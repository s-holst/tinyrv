import struct, collections, functools
from .opcodes import csrs
from .common import *
from .fpu import f32, f64

class Trap(Exception):
    def __init__(self, tval, cause): super().__init__(); self.tval = tval; self.cause = cause

class sim:  # simulates RV32GC, RV64GC (i.e. IMAFDCZicsr_Zifencei)
    class rvregs:
        def __init__(self, xlen, sim): self._x, self.xlen, self.sim = [0]*32, xlen, sim
        def __getitem__(self, i): return self._x[i]
        def __setitem__(self, i, d):
            if i!=0 and (self.sim.trace_log is not None): self.sim.trace_log.append(f'{iregs[i]}=' + (f'{zext(self.xlen, d):08x}' if self.xlen==32 else f'{zext(self.xlen, d):016x}'))
            if i!=0: self._x[i] = d
        def __repr__(self): return '\n'.join(['  '.join([f'x{r+rr:02d}({(iregs[r+rr])[-2:]})={xfmt(self.xlen, self._x[r+rr])}' for r in range(0, 32, 8)]) for rr in range(8)])
    class rvfregs:
        class accessor:
            def __init__(self, fregs, flen) -> None:
                self.fregs, self.flen, self.nan_box = fregs, flen, ~((1<<flen)-1)
                self.fmt, self.ifmt, self.QNAN = {16: ('e', 'H', 0x7e00), 32: ('f', 'I', f32.QNAN), 64: ('d', 'Q', f64.QNAN)}[self.flen]
            def __getitem__(self, i): return float('nan') if self.fregs.raw[i]&self.nan_box != self.nan_box else struct.unpack(self.fmt, struct.pack(self.ifmt, zext(self.flen, self.fregs.raw[i])))[0]
            def __setitem__(self, i, d):
                self.fregs.raw[i] = self.nan_box | (struct.unpack(self.ifmt, struct.pack(self.fmt, d))[0] if isinstance(d, float) else d)
                if self.fregs.sim.trace_log is not None: self.fregs.sim.trace_log.append(f'{fregs[i]}={xfmt(self.flen, self.fregs.raw[i])}')
        class raw_accessor(accessor):
            def __getitem__(self, i): return self.QNAN if self.fregs.raw[i]&self.nan_box != self.nan_box else zext(self.flen, self.fregs.raw[i])
        def __init__(self, flen, sim):
            self.raw, self.flen, self.sim = [0]*32, flen, sim
            self.s, self.raw_s, self.d, self.raw_d = self.accessor(self, 32), self.raw_accessor(self, 32), self.accessor(self, 64), self.raw_accessor(self, 64)
    class rvcsrs:
        def __init__(self, xlen, sim): self._csr, self.xlen, self.sim = [0]*4096, xlen, sim
        def __getitem__(self, i):
            if i == self.sim.TSELECT: return 1  # Return constant 1 for sw to discover that we don't support for any debug triggers.
            elif i == self.sim.MISA: return (0x40000000 if self.sim.xlen==32 else 0x80000000_00000000) | 0b1000000101101 # M______F_DC_A
            else: return self._csr[i]
        def __setitem__(self, i, d):
            if (self.sim.trace_log is not None) and (i != self.sim.MCYCLE): self.sim.trace_log.append(f'{csrs.get(i, f"csrs[{i}]")}=' + (f'{zext(self.xlen, d):08x}' if self.xlen==32 else f'{zext(self.xlen, d):016x}'))
            if   i == self.sim.FCSR:    self._csr[self.sim.FCSR] = d&0xff; self._csr[self.sim.FFLAGS] = d&0x1f; self._csr[self.sim.FRM] = (d>>5)&7
            elif i == self.sim.FFLAGS:  self._csr[self.sim.FCSR] = self._csr[self.sim.FCSR]&0xe0 | d&0x1f
            elif i == self.sim.FRM:     self._csr[self.sim.FCSR] = self._csr[self.sim.FCSR]&0x1f | ((d&7)<<5)
            else:
                if self.sim.xlen==64 and (i==self.sim.MSTATUS or i==self.sim.SSTATUS): d = d & ~0x100000000 | 0x200000000  # UXLEN hard-wired to 64-bit
                self._csr[i] = d
                for csr1, csr2, mask in [(self.sim.MSTATUS, self.sim.SSTATUS, 0x80000003000de762 if self.sim.xlen==64 else 0x800de762), (self.sim.MIE, self.sim.SIE, 0x2222), (self.sim.MIP, self.sim.SIP, 0x2222)]:
                    if i == csr1: self._csr[csr2] = self._csr[csr2]&~mask | d&mask
                    elif i == csr2: self._csr[csr1] = self._csr[csr1]&~mask | d&mask
    def __init__(self, xlen=64, trap_misaligned=True):
        self.xlen, self.trap_misaligned, self.trace_log = xlen, trap_misaligned, []
        self.pc, self.x, self.f, self.csr, self.lr_res_addr, self.cycle, self.plevel, self.mem_psize, self.mem_pages = 0, self.rvregs(self.xlen, self), self.rvfregs(64, self), self.rvcsrs(self.xlen, self), -1, 0, 3, 2<<20, collections.defaultdict(functools.partial(bytearray, 2<<20+2))  # 2-byte overlap for loading unaligned 32-bit opcodes
        [setattr(self, n.upper(), i) for i, n in list(enumerate(iregs))+list(csrs.items())]  # convenience
        self.csr[self.MSTATUS] = 0x6000  # FPU is active by default
    def hook_csr(self, csr, reqval):
        if (csr>>8)&3 > self.plevel: self.mtrap(self.op.data, 2); return self.csr[csr]  # insufficient privilege
        elif (csr&0xc00)==0xc00: return self.csr[csr]  # read-only CSR
        else: return reqval
    def notify_stored(self, addr): pass  # called *after* mem store
    def notify_loading(self, addr): pass  # called *before* mem load
    def mtrap(self, tval, cause):
        if self.trace_log is not None: self.trace_log.append(f'TRAP')
        from_plevel, self.plevel = self.plevel, max(1, self.plevel) if self.csr._csr[self.MIDELEG if cause<0 else self.MEDELEG] & (1<<(cause&63)) else 3
        if self.plevel == 3:
            self.csr[self.MCAUSE], self.csr[self.MTVAL], self.csr[self.MEPC], self.pc = cause, zext(self.xlen,tval), sext(self.xlen, self.op.addr), zext(self.xlen,self.csr[self.MTVEC]&(~3))  # TODO: vectored interrupts
            self.csr[self.MSTATUS] = self.csr[self.MSTATUS]&~(0x1888) | ((self.csr[self.MSTATUS]&0x08) << 4) | (from_plevel << 11)
        else:  # S-mode
            self.csr[self.SCAUSE], self.csr[self.STVAL], self.csr[self.SEPC], self.pc = cause, zext(self.xlen,tval), sext(self.xlen, self.op.addr), zext(self.xlen,self.csr[self.STVEC]&(~3))  # TODO: vectored interrupts
            self.csr[self.SSTATUS] = self.csr[self.SSTATUS]&~(0x122) | ((self.csr[self.SSTATUS]&0x02) << 4) | (from_plevel << 8)
    def page_and_offset_iter(self, addr, nbytes, doffset=0):
        while nbytes > doffset:
            page, poffset = self.page_and_offset(zext(self.xlen, addr+doffset))
            yield page, poffset, doffset, min(nbytes-doffset, self.mem_psize - poffset + 2)  # 2 bytes more to fill overlap
            doffset += min(nbytes-doffset, self.mem_psize - poffset)
    def copy_in(self, addr, bytes):
        for page, poffset, doffset, chunk in self.page_and_offset_iter(addr, len(bytes)): page[poffset:poffset+chunk] = bytes[doffset:doffset+chunk]
    def copy_out(self, addr, nbytes):
        data = bytearray(nbytes)
        for page, poffset, doffset, chunk in self.page_and_offset_iter(addr, nbytes): data[doffset:doffset+chunk] = page[poffset:poffset+chunk]
        return data
    def page_and_offset(self, addr): return self.mem_pages[addr&~(self.mem_psize-1)], addr&(self.mem_psize-1)
    def pa(self, addr, access='w'):
        pl = (self.csr._csr[self.MSTATUS]>>11)&3 if self.plevel==3 and self.csr._csr[self.MSTATUS]&0x00020000 and access!='x' else self.plevel
        satp, sum_bit, mxr_bit = self.csr._csr[self.SATP], (self.csr._csr[self.MSTATUS]>>18)&1, (self.csr._csr[self.MSTATUS]>>19)&1
        if pl==3 or satp==0: return addr  # no virtual memory
        pfault = Trap(addr, {'w':15, 'r':13, 'x':12}[access])
        def load_and_check_pte(pte_addr):
            pte = struct.unpack_from('I' if self.xlen==32 else 'Q', *self.page_and_offset(pte_addr))[0]
            if self.trace_log is not None: self.trace_log.append(f'pt[{xfmt(self.xlen, pte_addr)}]->{xfmt(self.xlen, pte)}')
            if (pte&1)==0 or (pte&2)==0 and (pte&4)!=0: raise pfault  # PTE valid?
            return pte, pte_addr
        if self.xlen==32 and (satp>>31)&1:  # Sv32
            pte, pte_addr, superpage_mask, pte_paddr_mask = *load_and_check_pte(((satp&0x3fffff)<<12) | ((addr>>20)&0xffc)), 0x3ff000, 0x3fffff000
            if (pte&2)==0 and (pte&8)==0: pte, pte_addr, superpage_mask = *load_and_check_pte(((pte<<2)&0x3fffff000) | ((addr>>10)&0xffc)), 0
        elif self.xlen==64 and ((satp>>60)&0xf)==8:  # Sv39
            pte, pte_addr, superpage_mask, pte_paddr_mask = *load_and_check_pte(((satp&0xfffffffffff)<<12) | ((addr>>27)&0xff8)), 0x3ffff000, 0xfffffffffff000
            if (pte&2)==0 and (pte&8)==0:
                pte, pte_addr, superpage_mask = *load_and_check_pte(((pte<<2)&0xfffffffffff000) | ((addr>>18)&0xff8)), 0x1ff000
                if (pte&2)==0 and (pte&8)==0: pte, pte_addr, superpage_mask = *load_and_check_pte(((pte<<2)&0xfffffffffff000) | ((addr>>9)&0xff8)), 0
        if (pte&2)==0 and (pte&8)==0: raise pfault
        if access=='w' and (pte&4)==0: raise pfault
        if access=='x' and (pte&8)==0: raise pfault
        if access=='r' and (pte&2)==0 and not (mxr_bit and (pte&8)!=0): raise pfault
        if pl==1 and (pte&0x10) and not sum_bit: raise pfault  # supervisor access to user page
        if (pte<<2)&superpage_mask: raise pfault  # misaligned superpage
        #if (pte&0x40)==0 or access=='w' and (pte&0x80)==0: raise pfault  # Svade: supervisor needs to update A or D bits
        struct.pack_into('I' if self.xlen==32 else 'Q', *self.page_and_offset(pte_addr), pte|0x40|(0x80*(access=='w')))  # Svadu: we update A and D bits
        return (addr & (0xfff|superpage_mask)) | (pte<<2)&pte_paddr_mask
    def store(self, format, addr, data, notify=True, cond=True):
        if not cond: return
        try: addr = self.pa(addr, access='w')
        except Trap as t: self.mtrap(t.tval, t.cause); return
        if self.trace_log is not None: self.trace_log.append(f'{xfmt(struct.calcsize(format)*8, data)}->mem[{xfmt(self.xlen, addr)}]')
        if self.trap_misaligned and addr&(struct.calcsize(format)-1) != 0: self.mtrap(addr, 6)
        else: struct.pack_into(format, *self.page_and_offset(zext(self.xlen,addr)), data)
        if notify: self.notify_stored(zext(self.xlen,addr))
    def load(self, format, addr, fallback=0, notify=True):
        if self.trap_misaligned and addr&(struct.calcsize(format)-1) != 0: self.mtrap(addr, 4); return fallback
        if zext(self.xlen, addr) & (1<<63): self.mtrap(addr, 5); return fallback
        addr = zext(self.xlen, addr)
        try: addr = self.pa(addr, access='r')
        except Trap as t: self.mtrap(t.tval, t.cause); return fallback
        if notify: self.notify_loading(addr)
        data = struct.unpack_from(format, *self.page_and_offset(addr))[0]
        if self.trace_log is not None: self.trace_log.append(f'mem[{xfmt(self.xlen, addr)}]->{xfmt(struct.calcsize(format)*8, data)}')
        return data
    def idiv2zero(self, a, b): return -(-a // b) if (a < 0) ^ (b < 0) else a // b
    def rem2zero(self, a, b): return a - b * self.idiv2zero(a, b)
    def _auipc     (self, rd, imm20,          **_): self.pc+=4; self.x[rd] = sext(self.xlen, self.op.addr+imm20)
    def _lui       (self, rd, imm20,          **_): self.pc+=4; self.x[rd] = imm20
    def _jal       (self, rd, jimm20,         **_): self.pc, self.x[rd] = zext(self.xlen, self.op.addr+jimm20),    sext(self.xlen, self.op.addr+4)
    def _jalr      (self, rd, rs1, imm12,     **_): self.pc, self.x[rd] = zext(self.xlen, self.x[rs1]+imm12)&(~1), sext(self.xlen, self.op.addr+4) # LSB=0
    def _beq       (self, rs1, rs2, bimm12,   **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] == self.x[rs2] else self.op.addr+4
    def _bne       (self, rs1, rs2, bimm12,   **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] != self.x[rs2] else self.op.addr+4
    def _blt       (self, rs1, rs2, bimm12,   **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] <  self.x[rs2] else self.op.addr+4
    def _bge       (self, rs1, rs2, bimm12,   **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] >= self.x[rs2] else self.op.addr+4
    def _bltu      (self, rs1, rs2, bimm12,   **_): self.pc = (self.op.addr+bimm12) if zext(self.xlen, self.x[rs1]) <  zext(self.xlen, self.x[rs2]) else self.op.addr+4
    def _bgeu      (self, rs1, rs2, bimm12,   **_): self.pc = (self.op.addr+bimm12) if zext(self.xlen, self.x[rs1]) >= zext(self.xlen, self.x[rs2]) else self.op.addr+4
    def _sb        (self, rs1, rs2, imm12,    **_): self.pc+=4; self.store('B', self.x[rs1]+imm12, zext( 8,self.x[rs2]))
    def _sh        (self, rs1, rs2, imm12,    **_): self.pc+=4; self.store('H', self.x[rs1]+imm12, zext(16,self.x[rs2]))
    def _sw        (self, rs1, rs2, imm12,    **_): self.pc+=4; self.store('I', self.x[rs1]+imm12, zext(32,self.x[rs2]))
    def _sd        (self, rs1, rs2, imm12,    **_): self.pc+=4; self.store('Q', self.x[rs1]+imm12, zext(64,self.x[rs2]))
    def _lb        (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = self.load('b', self.x[rs1]+imm12, self.x[rd])
    def _lbu       (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = self.load('B', self.x[rs1]+imm12, self.x[rd])
    def _lh        (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = self.load('h', self.x[rs1]+imm12, self.x[rd])
    def _lw        (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = self.load('i', self.x[rs1]+imm12, self.x[rd])
    def _ld        (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = self.load('q', self.x[rs1]+imm12, self.x[rd])
    def _lhu       (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = self.load('H', self.x[rs1]+imm12, self.x[rd])
    def _lwu       (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = self.load('I', self.x[rs1]+imm12, self.x[rd])
    def _addi      (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  +          imm12)
    def _xori      (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  ^          imm12)
    def _ori       (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  |          imm12)
    def _andi      (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  &          imm12)
    def _addiw     (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = sext(32,          self.x[rs1]  +          imm12)
    def _addw      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32, sext(32, self.x[rs1]) + sext(32, self.x[rs2]))
    def _subw      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32, sext(32, self.x[rs1]) - sext(32, self.x[rs2]))
    def _add       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  +          self.x[rs2])
    def _sub       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  -          self.x[rs2])
    def _xor       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  ^          self.x[rs2])
    def _or        (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  |          self.x[rs2])
    def _and       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  &          self.x[rs2])
    def _sltiu     (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] = zext(self.xlen,   self.x[rs1]) < zext(self.xlen, imm12)
    def _sltu      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = zext(self.xlen,   self.x[rs1]) < zext(self.xlen, self.x[rs2])
    def _slti      (self, rd, rs1, imm12,     **_): self.pc+=4; self.x[rd] =                   self.x[rs1]  <                 imm12
    def _slt       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] =                   self.x[rs1]  <                 self.x[rs2]
    def _slliw     (self, rd, rs1, shamtw,    **_): self.pc+=4; self.x[rd] = sext(32,                        self.x[rs1]  << shamtw)
    def _srliw     (self, rd, rs1, shamtw,    **_): self.pc+=4; self.x[rd] = sext(32,        zext(32,        self.x[rs1]) >> shamtw)
    def _sraiw     (self, rd, rs1, shamtw,    **_): self.pc+=4; self.x[rd] = sext(32,        sext(32,        self.x[rs1]) >> shamtw)
    def _slli      (self, rd, rs1, shamtd,    **_):  # shared with RV64I
        if shamtd >= self.xlen: self.mtrap(self.op.data, 2)  # shift with more than 31 bits on 32-bit is illegal
        else: self.pc+=4; self.x[rd] = sext(self.xlen, self.x[rs1] << shamtd)
    def _srai      (self, rd, rs1, shamtd,    **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  >> shamtd)  # shared with RV64I
    def _srli      (self, rd, rs1, shamtd,    **_): self.pc+=4; self.x[rd] = sext(self.xlen, zext(self.xlen, self.x[rs1]) >> shamtd)  # shared with RV64I
    def _sll       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  << (self.x[rs2]&(self.xlen-1)))
    def _srl       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen, zext(self.xlen, self.x[rs1]) >> (self.x[rs2]&(self.xlen-1)))
    def _sra       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  >> (self.x[rs2]&(self.xlen-1)))
    def _sllw      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32,        sext(32,        self.x[rs1]) << (self.x[rs2]&31))
    def _srlw      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32,        zext(32,        self.x[rs1]) >> (self.x[rs2]&31))
    def _sraw      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32,        sext(32,        self.x[rs1]) >> (self.x[rs2]&31))
    def _fence     (self,                     **_): self.pc+=4
    def _fence_i   (self,                     **_): self.pc+=4
    def _sfence_vma(self,                     **_): self.pc+=4
    def _csrrw     (self, rd, csr, rs1,       **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.x[rs1]               )
    def _csrrs     (self, rd, csr, rs1,       **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.csr[csr]| self.x[rs1])
    def _csrrc     (self, rd, csr, rs1,       **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.csr[csr]&~self.x[rs1])
    def _csrrwi    (self, rd, csr, zimm,      **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, zimm                      )
    def _csrrsi    (self, rd, csr, zimm,      **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.csr[csr]| zimm       )
    def _csrrci    (self, rd, csr, zimm,      **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.csr[csr]&~zimm       )
    def _mret      (self,                     **_): self.pc = zext(self.xlen, self.csr[self.MEPC]); new_plevel = (self.csr[self.MSTATUS]>>11)&3; self.csr[self.MSTATUS] = self.csr[self.MSTATUS] & ~(0x1888) | 0x80 | ((self.csr[self.MSTATUS]&0x80) >> 4); self.plevel = new_plevel
    def _sret      (self,                     **_): self.pc = zext(self.xlen, self.csr[self.SEPC]); new_plevel = (self.csr[self.SSTATUS]>>8)&1;  self.csr[self.SSTATUS] = self.csr[self.SSTATUS] & ~(0x122)  | 0x20 | ((self.csr[self.SSTATUS]&0x20) >> 4); self.plevel = new_plevel
    def _ecall     (self,                     **_): self.mtrap(0, 8 if self.plevel == 0 else 11)
    def _ebreak    (self,                     **_): self.mtrap(self.op.addr, 3)
    def _wfi       (self,                     **_): self.pc+=4
    def _mul       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen, (                self.x[rs1]  *                 self.x[rs2] )           )
    def _mulh      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen, (                self.x[rs1]  *                 self.x[rs2] )>>self.xlen)
    def _mulhu     (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen, (zext(self.xlen, self.x[rs1]) * zext(self.xlen, self.x[rs2]))>>self.xlen)
    def _mulhsu    (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen, (                self.x[rs1]  * zext(self.xlen, self.x[rs2]))>>self.xlen)
    def _div       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen, (self.idiv2zero( self.x[rs1]  ,                 self.x[rs2]))           ) if self.x[rs2] != 0 else -1
    def _divu      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen, (zext(self.xlen, self.x[rs1]) //zext(self.xlen, self.x[rs2]))           ) if self.x[rs2] != 0 else -1
    def _rem       (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen, (self.rem2zero ( self.x[rs1]  ,                 self.x[rs2]))           ) if self.x[rs2] != 0 else self.x[rs1]
    def _remu      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(self.xlen, (zext(self.xlen, self.x[rs1]) % zext(self.xlen, self.x[rs2]))           ) if self.x[rs2] != 0 else self.x[rs1]
    def _mulw      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32,        (sext(32,        self.x[rs1]) * sext(32,        self.x[rs2]))           )
    def _divw      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32, (self.idiv2zero(sext(32,self.x[rs1]) , sext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else -1
    def _divuw     (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32, (self.idiv2zero(zext(32,self.x[rs1]) , zext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else -1
    def _remw      (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32, (self.rem2zero (sext(32,self.x[rs1]) , sext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else sext(32,self.x[rs1])
    def _remuw     (self, rd, rs1, rs2,       **_): self.pc+=4; self.x[rd] = sext(32, (self.rem2zero (zext(32,self.x[rs1]) , zext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else sext(32,self.x[rs1])
    def _amoswap_w (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('i', self.x[rs1], self.x[rd]); self.store('i', ors1,                            sext(32,ors2)  ); self.x[rd]=tmp
    def _amoadd_w  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('i', self.x[rs1], self.x[rd]); self.store('i', ors1, sext(32,             tmp + sext(32,ors2)) ); self.x[rd]=tmp
    def _amoand_w  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('i', self.x[rs1], self.x[rd]); self.store('i', ors1, sext(32,             tmp & sext(32,ors2)) ); self.x[rd]=tmp
    def _amoor_w   (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('i', self.x[rs1], self.x[rd]); self.store('i', ors1, sext(32,             tmp | sext(32,ors2)) ); self.x[rd]=tmp
    def _amoxor_w  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('i', self.x[rs1], self.x[rd]); self.store('i', ors1, sext(32,             tmp ^ sext(32,ors2)) ); self.x[rd]=tmp
    def _amomax_w  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('i', self.x[rs1], self.x[rd]); self.store('i', ors1, sext(32, max(        tmp , sext(32,ors2)))); self.x[rd]=tmp
    def _amomin_w  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('i', self.x[rs1], self.x[rd]); self.store('i', ors1, sext(32, min(        tmp , sext(32,ors2)))); self.x[rd]=tmp
    def _amomaxu_w (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('i', self.x[rs1], self.x[rd]); self.store('i', ors1, sext(32, max(zext(32,tmp), zext(32,ors2)))); self.x[rd]=tmp
    def _amominu_w (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('i', self.x[rs1], self.x[rd]); self.store('i', ors1, sext(32, min(zext(32,tmp), zext(32,ors2)))); self.x[rd]=tmp
    def _amoswap_d (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('q', self.x[rs1], self.x[rd]); self.store('q', ors1,                                    ors2,  ); self.x[rd]=tmp
    def _amoadd_d  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('q', self.x[rs1], self.x[rd]); self.store('q', ors1, sext(64,             tmp +         ors2 ) ); self.x[rd]=tmp
    def _amoand_d  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('q', self.x[rs1], self.x[rd]); self.store('q', ors1, sext(64,             tmp &         ors2 ) ); self.x[rd]=tmp
    def _amoor_d   (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('q', self.x[rs1], self.x[rd]); self.store('q', ors1, sext(64,             tmp |         ors2 ) ); self.x[rd]=tmp
    def _amoxor_d  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('q', self.x[rs1], self.x[rd]); self.store('q', ors1, sext(64,             tmp ^         ors2 ) ); self.x[rd]=tmp
    def _amomax_d  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('q', self.x[rs1], self.x[rd]); self.store('q', ors1, sext(64, max(        tmp , sext(64,ors2)))); self.x[rd]=tmp
    def _amomin_d  (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('q', self.x[rs1], self.x[rd]); self.store('q', ors1, sext(64, min(        tmp , sext(64,ors2)))); self.x[rd]=tmp
    def _amomaxu_d (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('q', self.x[rs1], self.x[rd]); self.store('q', ors1, sext(64, max(zext(64,tmp), zext(64,ors2)))); self.x[rd]=tmp
    def _amominu_d (self, rd, rs1, rs2,       **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.load('q', self.x[rs1], self.x[rd]); self.store('q', ors1, sext(64, min(zext(64,tmp), zext(64,ors2)))); self.x[rd]=tmp
    def _lr_w      (self, rd, rs1,            **_): self.pc+=4; self.lr_res_addr = self.x[rs1]; self.x[rd] = self.load('i', self.x[rs1], self.x[rd])
    def _lr_d      (self, rd, rs1,            **_): self.pc+=4; self.lr_res_addr = self.x[rs1]; self.x[rd] = self.load('q', self.x[rs1], self.x[rd])
    def _sc_w      (self, rd, rs1, rs2,       **_): self.pc+=4; self.store('i', self.x[rs1], sext(32, self.x[rs2]), cond=self.lr_res_addr==self.x[rs1]); self.x[rd] = self.lr_res_addr!=self.x[rs1]; self.lr_res_addr = -1
    def _sc_d      (self, rd, rs1, rs2,       **_): self.pc+=4; self.store('q', self.x[rs1], sext(64, self.x[rs2]), cond=self.lr_res_addr==self.x[rs1]); self.x[rd] = self.lr_res_addr!=self.x[rs1]; self.lr_res_addr = -1
    def _c_ebreak  (self,                     **_): self.mtrap(self.op.addr, 3)
    def _c_nop     (self,                     **_): self.pc+=2;  # c.nop also required to pass test rv32i_m/privilege/src/misalign-jal-01.S
    def _c_lui     (self, rd_n2, nzimm18,     **_): self.pc+=2; self.x[rd_n2]      = nzimm18
    def _c_li      (self, rd_n0, imm6,        **_): self.pc+=2; self.x[rd_n0]      = imm6
    def _c_mv      (self, rd_n0, rs2_n0,      **_): self.pc+=2; self.x[rd_n0]      = self.x[rs2_n0]
    def _c_add     (self, rd_rs1_n0, rs2_n0,  **_): self.pc+=2; self.x[rd_rs1_n0]  = sext(self.xlen, self.x[rd_rs1_n0]  + self.x[rs2_n0] )
    def _c_addi    (self, rd_rs1_n0, nzimm6,  **_): self.pc+=2; self.x[rd_rs1_n0]  = sext(self.xlen, self.x[rd_rs1_n0]  + nzimm6         )
    def _c_addiw   (self, rd_rs1_n0, imm6,    **_): self.pc+=2; self.x[rd_rs1_n0]  = sext(32,        self.x[rd_rs1_n0]  + imm6           )
    def _c_slli    (self, rd_rs1_n0, nzuimm6, **_): self.pc+=2; self.x[rd_rs1_n0]  = sext(self.xlen, self.x[rd_rs1_n0] << nzuimm6        )
    def _c_and     (self, rd_rs1_p, rs2_p,    **_): self.pc+=2; self.x[rd_rs1_p+8] = sext(self.xlen, self.x[rd_rs1_p+8] & self.x[rs2_p+8])
    def _c_or      (self, rd_rs1_p, rs2_p,    **_): self.pc+=2; self.x[rd_rs1_p+8] = sext(self.xlen, self.x[rd_rs1_p+8] | self.x[rs2_p+8])
    def _c_xor     (self, rd_rs1_p, rs2_p,    **_): self.pc+=2; self.x[rd_rs1_p+8] = sext(self.xlen, self.x[rd_rs1_p+8] ^ self.x[rs2_p+8])
    def _c_sub     (self, rd_rs1_p, rs2_p,    **_): self.pc+=2; self.x[rd_rs1_p+8] = sext(self.xlen, self.x[rd_rs1_p+8] - self.x[rs2_p+8])
    def _c_addw    (self, rd_rs1_p, rs2_p,    **_): self.pc+=2; self.x[rd_rs1_p+8] = sext(32,        self.x[rd_rs1_p+8] + self.x[rs2_p+8])
    def _c_subw    (self, rd_rs1_p, rs2_p,    **_): self.pc+=2; self.x[rd_rs1_p+8] = sext(32,        self.x[rd_rs1_p+8] - self.x[rs2_p+8])
    def _c_andi    (self, rd_rs1_p, imm6,     **_): self.pc+=2; self.x[rd_rs1_p+8] = sext(self.xlen, self.x[rd_rs1_p+8] & imm6)
    def _c_srai    (self, rd_rs1_p, nzuimm6,  **_): self.pc+=2; self.x[rd_rs1_p+8] = sext(self.xlen, self.x[rd_rs1_p+8] >> nzuimm6)
    def _c_srli    (self, rd_rs1_p, nzuimm6,  **_): self.pc+=2; self.x[rd_rs1_p+8] = sext(self.xlen, zext(self.xlen, self.x[rd_rs1_p+8])  >> nzuimm6)
    def _c_lw      (self, rd_p, rs1_p, uimm7, **_): self.pc+=2; self.x[rd_p+8]     = self.load('i', self.x[rs1_p+8]+uimm7, self.x[rd_p+8])
    def _c_ld      (self, rd_p, rs1_p, uimm8, **_): self.pc+=2; self.x[rd_p+8]     = self.load('q', self.x[rs1_p+8]+uimm8, self.x[rd_p+8])
    def _c_flw     (self, rd_p, rs1_p, uimm7, **_): self.pc+=2; self.f.s[rd_p+8]   = self.load('I', self.x[rs1_p+8]+uimm7, self.x[rd_p+8])
    def _c_fld     (self, rd_p, rs1_p, uimm8, **_): self.pc+=2; self.f.d[rd_p+8]   = self.load('Q', self.x[rs1_p+8]+uimm8, self.x[rd_p+8])
    def _c_lwsp    (self, rd_n0, uimm8sp,     **_): self.pc+=2; self.x[rd_n0]      = self.load('i', self.x[2]+uimm8sp, self.x[rd_n0])
    def _c_ldsp    (self, rd_n0, uimm9sp,     **_): self.pc+=2; self.x[rd_n0]      = self.load('q', self.x[2]+uimm9sp, self.x[rd_n0])
    def _c_flwsp   (self, rd, uimm8sp,        **_): self.pc+=2; self.f.s[rd]       = self.load('I', self.x[2]+uimm8sp, self.x[rd])
    def _c_fldsp   (self, rd, uimm9sp,        **_): self.pc+=2; self.f.d[rd]       = self.load('Q', self.x[2]+uimm9sp, self.x[rd])
    def _c_addi16sp(self, nzimm10,            **_): self.pc+=2; self.x[2]         += nzimm10
    def _c_addi4spn(self, rd_p, nzuimm10,     **_):
        if nzuimm10!=0 or rd_p!=0: self.pc+=2; self.x[rd_p+8]     = self.x[2] + nzuimm10
        else: self.mtrap(self.op.data, 2)  # 16-bit all-0: defined illegal instruction
    def _c_swsp    (self, rs2, uimm8sp_s,     **_): self.pc+=2; self.store('I', self.x[2]+uimm8sp_s,   zext(32,self.x[rs2]))
    def _c_sdsp    (self, rs2, uimm9sp_s,     **_): self.pc+=2; self.store('Q', self.x[2]+uimm9sp_s,   zext(64,self.x[rs2]))
    def _c_fswsp   (self, rs2, uimm8sp_s,     **_): self.pc+=2; self.store('I', self.x[2]+uimm8sp_s,   zext(32,self.f.raw[rs2]), cond=(self.csr[self.MSTATUS]>>13)&3)
    def _c_fsdsp   (self, rs2, uimm9sp_s,     **_): self.pc+=2; self.store('Q', self.x[2]+uimm9sp_s,   zext(64,self.f.raw[rs2]), cond=(self.csr[self.MSTATUS]>>13)&3)
    def _c_sw      (self, rs1_p,rs2_p, uimm7, **_): self.pc+=2; self.store('I', self.x[rs1_p+8]+uimm7, zext(32,self.x[rs2_p+8]))
    def _c_sd      (self, rs1_p,rs2_p, uimm8, **_): self.pc+=2; self.store('Q', self.x[rs1_p+8]+uimm8, zext(64,self.x[rs2_p+8]))
    def _c_fsw     (self, rs1_p,rs2_p, uimm7, **_): self.pc+=2; self.store('I', self.x[rs1_p+8]+uimm7, zext(32,self.f.raw[rs2_p+8]), cond=(self.csr[self.MSTATUS]>>13)&3)
    def _c_fsd     (self, rs1_p,rs2_p, uimm8, **_): self.pc+=2; self.store('Q', self.x[rs1_p+8]+uimm8, zext(64,self.f.raw[rs2_p+8]), cond=(self.csr[self.MSTATUS]>>13)&3)
    def _c_jalr    (self, rs1_n0,             **_): self.pc, self.x[1] = zext(self.xlen, self.x[rs1_n0])&(~1), sext(self.xlen, self.op.addr+2) # LSB=0
    def _c_jal     (self, imm12,              **_): self.pc, self.x[1] = zext(self.xlen, self.op.addr+imm12),  sext(self.xlen, self.op.addr+2)
    def _c_jr      (self, rs1_n0,             **_): self.pc = zext(self.xlen, self.x[rs1_n0])&(~1) # LSB=0
    def _c_j       (self, imm12,              **_): self.pc = zext(self.xlen, self.op.addr+imm12)
    def _c_beqz    (self, rs1_p, bimm9,       **_): self.pc = (self.op.addr+bimm9) if self.x[rs1_p+8] == 0 else self.op.addr+2
    def _c_bnez    (self, rs1_p, bimm9,       **_): self.pc = (self.op.addr+bimm9) if self.x[rs1_p+8] != 0 else self.op.addr+2
    def _c_ntl_p1  (self,                     **_): self.pc+=2  # hints from Zihintntl, required to pass test rv32i_m/C/src/cadd-01.S
    def _c_ntl_pall(self,                     **_): self.pc+=2
    def _c_ntl_s1  (self,                     **_): self.pc+=2
    def _c_ntl_all (self,                     **_): self.pc+=2
    def _flw       (self, rd, rs1, imm12,     **_): self.pc+=4; self.f.s[rd] = self.load('I', self.x[rs1]+imm12, zext(32, self.f.raw[rd]))
    def _fsw       (self, rs1, rs2, imm12,    **_): self.pc+=4; self.store('I', self.x[rs1]+imm12, zext(32, self.f.raw[rs2]), cond=(self.csr[self.MSTATUS]>>13)&3)
    def _fcvt_w_s  (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f32(self.f.raw_s[rs1]).to_i32_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.x[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_wu_s (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f32(self.f.raw_s[rs1]).to_u32_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.x[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_l_s  (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f32(self.f.raw_s[rs1]).to_i64_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.x[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_lu_s (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f32(self.f.raw_s[rs1]).to_u64_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.x[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_s_w  (self, rs1, rd, rm,        **_): self.pc+=4; self.f.s[rd] = float(sext(32, self.x[rs1])); self.csr[self.FCSR] |= self.f.s[rd] != sext(32, self.x[rs1])
    def _fcvt_s_wu (self, rs1, rd, rm,        **_): self.pc+=4; self.f.s[rd] = float(zext(32, self.x[rs1])); self.csr[self.FCSR] |= self.f.s[rd] != zext(32, self.x[rs1])
    def _fcvt_s_l  (self, rs1, rd, rm,        **_): self.pc+=4; self.f.s[rd] = float(sext(64, self.x[rs1])); self.csr[self.FCSR] |= self.f.s[rd] != sext(64, self.x[rs1])
    def _fcvt_s_lu (self, rs1, rd, rm,        **_): self.pc+=4; self.f.s[rd] = float(zext(64, self.x[rs1])); self.csr[self.FCSR] |= self.f.s[rd] != zext(64, self.x[rs1])
    def _fsgnj_s   (self, rs1, rs2, rd,       **_): self.pc+=4; self.f.s[rd] = self.f.raw_s[rs1]&0x7fffffff | self.f.raw_s[rs2]&0x80000000
    def _fsgnjn_s  (self, rs1, rs2, rd,       **_): self.pc+=4; self.f.s[rd] = self.f.raw_s[rs1]&0x7fffffff | (~self.f.raw_s[rs2])&0x80000000
    def _fsgnjx_s  (self, rs1, rs2, rd,       **_): self.pc+=4; self.f.s[rd] = self.f.raw_s[rs1] ^ self.f.raw_s[rs2]&0x80000000
    def _fmv_x_s   (self, rs1, rd,            **_): self.pc+=4; self.x[rd] = sext(32, self.f.raw[rs1])
    def _fmv_s_x   (self, rs1, rd,            **_): self.pc+=4; self.f.s[rd] = zext(32, self.x[rs1])
    def _feq_s     (self, rs1, rs2, rd,       **_): self.pc+=4; self.x[rd] = self.f.s[rs1] == self.f.s[rs2]; self.csr[self.FCSR] |= (0x10*f32(self.f.raw_s[rs1]).is_snan) | (0x10*f32(self.f.raw_s[rs2]).is_snan)
    def _flt_s     (self, rs1, rs2, rd,       **_): self.pc+=4; self.x[rd] = self.f.s[rs1] <  self.f.s[rs2]; self.csr[self.FCSR] |= (0x10*f32(self.f.raw_s[rs1]).is_nan) | (0x10*f32(self.f.raw_s[rs2]).is_nan)
    def _fle_s     (self, rs1, rs2, rd,       **_): self.pc+=4; self.x[rd] = self.f.s[rs1] <= self.f.s[rs2]; self.csr[self.FCSR] |= (0x10*f32(self.f.raw_s[rs1]).is_nan) | (0x10*f32(self.f.raw_s[rs2]).is_nan)
    def _fclass_s  (self, rs1, rd,            **_): self.pc+=4; f = f32(self.f.raw_s[rs1]); self.x[rd] = (0x1*(f.is_neg and f.is_inf)) | (0x2*(f.is_neg and f.is_normal)) | (0x4*(f.is_neg and f.is_subnormal)) | (0x8*(f.is_neg and f.is_zero)) | (0x10*(not f.is_neg and f.is_zero)) | (0x20*(not f.is_neg and f.is_subnormal)) | (0x40*(not f.is_neg and f.is_normal)) | (0x80*(not f.is_neg and f.is_inf)) | (0x100*(f.is_snan)) | (0x200*(f.is_qnan))
    def _fadd_s    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f32.add(self.f.raw_s[rs1], self.f.raw_s[rs2]                                            , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fsub_s    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f32.add(self.f.raw_s[rs1], self.f.raw_s[rs2]^f32.SIGN_BIT                               , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmul_s    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f32.mul(self.f.raw_s[rs1], self.f.raw_s[rs2]                                            , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fdiv_s    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f32.div(self.f.raw_s[rs1], self.f.raw_s[rs2]                                            , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmadd_s   (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f32.mad(self.f.raw_s[rs1], self.f.raw_s[rs2]            , self.f.raw_s[rs3]             , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmsub_s   (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f32.mad(self.f.raw_s[rs1], self.f.raw_s[rs2]            , self.f.raw_s[rs3]^f32.SIGN_BIT, rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fnmsub_s  (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f32.mad(self.f.raw_s[rs1], self.f.raw_s[rs2]            , self.f.raw_s[rs3]             , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm, negate_product=True); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fnmadd_s  (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f32.mad(self.f.raw_s[rs1], self.f.raw_s[rs2]            , self.f.raw_s[rs3]^f32.SIGN_BIT, rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm, negate_product=True); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmin_s    (self, rs1, rs2, rd,       **_): self.pc+=4; f = f32.min(self.f.raw_s[rs1], self.f.raw_s[rs2]                                                                                                                 ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmax_s    (self, rs1, rs2, rd,       **_): self.pc+=4; f = f32.max(self.f.raw_s[rs1], self.f.raw_s[rs2]                                                                                                                 ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fsqrt_s   (self, rs1, rd, rm,        **_): self.pc+=4; f = f32.sqrt(self.f.raw_s[rs1]                                                              , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fld       (self, rd, rs1, imm12,     **_): self.pc+=4; self.f.d[rd] = self.load('Q', self.x[rs1]+imm12, zext(64, self.f.raw[rd]))
    def _fsd       (self, rs1, rs2, imm12,    **_): self.pc+=4; self.store('Q', self.x[rs1]+imm12, zext(64, self.f.raw[rs2]))
    def _fcvt_w_d  (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f64(self.f.raw_d[rs1]).to_i32_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.x[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_wu_d (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f64(self.f.raw_d[rs1]).to_u32_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.x[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_l_d  (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f64(self.f.raw_d[rs1]).to_i64_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.x[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_lu_d (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f64(self.f.raw_d[rs1]).to_u64_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.x[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_s_d  (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f64(self.f.raw_d[rs1]).to_f32_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.f.s[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_d_s  (self, rs1, rd, rm,        **_): self.pc+=4; v, flags = f32(self.f.raw_s[rs1]).to_f64_and_flags(rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm); self.f.d[rd] = v; self.csr[self.FCSR] |= flags
    def _fcvt_d_w  (self, rs1, rd, rm,        **_): self.pc+=4; self.f.d[rd] = float(sext(32, self.x[rs1])); self.csr[self.FCSR] |= self.f.d[rd] != sext(32, self.x[rs1])
    def _fcvt_d_wu (self, rs1, rd, rm,        **_): self.pc+=4; self.f.d[rd] = float(zext(32, self.x[rs1])); self.csr[self.FCSR] |= self.f.d[rd] != zext(32, self.x[rs1])
    def _fcvt_d_l  (self, rs1, rd, rm,        **_): self.pc+=4; self.f.d[rd] = float(sext(64, self.x[rs1])); self.csr[self.FCSR] |= self.f.d[rd] != sext(64, self.x[rs1])
    def _fcvt_d_lu (self, rs1, rd, rm,        **_): self.pc+=4; self.f.d[rd] = float(zext(64, self.x[rs1])); self.csr[self.FCSR] |= self.f.d[rd] != zext(64, self.x[rs1])
    def _fsgnj_d   (self, rs1, rs2, rd,       **_): self.pc+=4; self.f.d[rd] = self.f.raw_d[rs1]&f64.ABS_MASK | self.f.raw_d[rs2]&f64.SIGN_BIT
    def _fsgnjn_d  (self, rs1, rs2, rd,       **_): self.pc+=4; self.f.d[rd] = self.f.raw_d[rs1]&f64.ABS_MASK | (~self.f.raw_d[rs2])&f64.SIGN_BIT
    def _fsgnjx_d  (self, rs1, rs2, rd,       **_): self.pc+=4; self.f.d[rd] = self.f.raw_d[rs1] ^ self.f.raw_d[rs2]&f64.SIGN_BIT
    def _fmv_x_d   (self, rs1, rd,            **_): self.pc+=4; self.x[rd] = sext(64, self.f.raw[rs1])
    def _fmv_d_x   (self, rs1, rd,            **_): self.pc+=4; self.f.d[rd] = zext(64, self.x[rs1])
    def _feq_d     (self, rs1, rs2, rd,       **_): self.pc+=4; self.x[rd] = self.f.d[rs1] == self.f.d[rs2]; self.csr[self.FCSR] |= (0x10*f64(self.f.raw_d[rs1]).is_snan) | (0x10*f64(self.f.raw_d[rs2]).is_snan)
    def _flt_d     (self, rs1, rs2, rd,       **_): self.pc+=4; self.x[rd] = self.f.d[rs1] <  self.f.d[rs2]; self.csr[self.FCSR] |= (0x10*f64(self.f.raw_d[rs1]).is_nan) | (0x10*f64(self.f.raw_d[rs2]).is_nan)
    def _fle_d     (self, rs1, rs2, rd,       **_): self.pc+=4; self.x[rd] = self.f.d[rs1] <= self.f.d[rs2]; self.csr[self.FCSR] |= (0x10*f64(self.f.raw_d[rs1]).is_nan) | (0x10*f64(self.f.raw_d[rs2]).is_nan)
    def _fclass_d  (self, rs1, rd,            **_): self.pc+=4; f = f64(self.f.raw_d[rs1]); self.x[rd] = (0x1*(f.is_neg and f.is_inf)) | (0x2*(f.is_neg and f.is_normal)) | (0x4*(f.is_neg and f.is_subnormal)) | (0x8*(f.is_neg and f.is_zero)) | (0x10*(not f.is_neg and f.is_zero)) | (0x20*(not f.is_neg and f.is_subnormal)) | (0x40*(not f.is_neg and f.is_normal)) | (0x80*(not f.is_neg and f.is_inf)) | (0x100*(f.is_snan)) | (0x200*(f.is_qnan))
    def _fadd_d    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f64.add(self.f.raw_d[rs1], self.f.raw_d[rs2]                                            , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fsub_d    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f64.add(self.f.raw_d[rs1], self.f.raw_d[rs2]^f64.SIGN_BIT                               , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmul_d    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f64.mul(self.f.raw_d[rs1], self.f.raw_d[rs2]                                            , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fdiv_d    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f64.div(self.f.raw_d[rs1], self.f.raw_d[rs2]                                            , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmadd_d   (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f64.mad(self.f.raw_d[rs1], self.f.raw_d[rs2]            , self.f.raw_d[rs3]             , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmsub_d   (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f64.mad(self.f.raw_d[rs1], self.f.raw_d[rs2]            , self.f.raw_d[rs3]^f64.SIGN_BIT, rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fnmsub_d  (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f64.mad(self.f.raw_d[rs1], self.f.raw_d[rs2]            , self.f.raw_d[rs3]             , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm, negate_product=True); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fnmadd_d  (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f64.mad(self.f.raw_d[rs1], self.f.raw_d[rs2]            , self.f.raw_d[rs3]^f64.SIGN_BIT, rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm, negate_product=True); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmin_d    (self, rs1, rs2, rd,       **_): self.pc+=4; f = f64.min(self.f.raw_d[rs1], self.f.raw_d[rs2]                                                                                                                 ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmax_d    (self, rs1, rs2, rd,       **_): self.pc+=4; f = f64.max(self.f.raw_d[rs1], self.f.raw_d[rs2]                                                                                                                 ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fsqrt_d   (self, rs1, rd, rm,        **_): self.pc+=4; f = f64.sqrt(self.f.raw_d[rs1]                                                              , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def hook_exec(self): return True
    def unimplemented(self, **_): print(f'\n{zext(64,self.op.addr):08x}: unimplemented: {zext(32,self.op.data):08x} {self.op}'); self.exitcode=77
    def step(self, trace=True):
        self.trace_log = [] if trace else None
        try: addr = self.pa(self.pc, access='x')
        except Trap as t: self.mtrap(t.tval, t.cause); return
        self.op = decode(struct.unpack_from('I', *self.page_and_offset(addr))[0], 0, self.xlen); self.op.addr=addr  # setting op.addr afterwards enables opcode caching.
        if self.hook_exec():
            self.cycle += 1; self.csr[self.MCYCLE] = zext(self.xlen, self.cycle)
            if self.pc & (1<<63): self.mtrap(self.pc, 1)
            else: getattr(self, '_'+self.op.name, self.unimplemented)(**self.op.args)  # dynamic instruction dispatch
            if trace: print(f'{zext(64,self.op.addr):08x}: {str(self.op):40} # { {0:"U",1:"S",2:"H",3:"M"}[self.plevel]} [{self.cycle-1}]', ' '.join(self.trace_log))
            if trace and self.pc-self.op.addr not in (2, 4): print()
    def run(self, limit=0, bpts=set(), trace=True):
        while True:
            self.step(trace=trace)
            if self.op.addr in bpts|{self.pc} or (limit := limit-1)==0: break