import os, struct, array, struct, collections, functools
from .opcodes import *
from .fpu import f32, f64

iregs = 'zero,ra,sp,gp,tp,t0,t1,t2,fp,s1,a0,a1,a2,a3,a4,a5,a6,a7,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,t3,t4,t5,t6'.split(',')
fregs = 'ft0,ft1,ft2,ft3,ft4,ft5,ft6,ft7,fs0,fs1,fa0,fa1,fa2,fa3,fa4,fa5,fa6,fa7,fs2,fs3,fs4,fs5,fs6,fs7,fs8,fs9,fs10,fs11,ft8,ft9,ft10,ft11'.split(',')
customs={0b0001011: 'custom0', 0b0101011: 'custom1', 0b1011011: 'custom2', 0b1111011: 'custom3'}
def zext(length, word): return word&((1<<length)-1)
def sext(length, word): return word|~((1<<length)-1) if word&(1<<(length-1)) else zext(length, word)
def xfmt(length, word): return f'{{:0{length//4}x}}'.format(zext(length, word))

class rvop:
    def __init__(self, **kwargs): [setattr(self, k, v) for k, v in kwargs.items()]
    def arg_str(self):
        if self.name in 'lb,lh,lw,ld,lbu,lhu,lwu,sb,sh,sw,sd,jalr'.split(','): args = [iregs[self.rd] if 'rd' in self.args else iregs[self.rs2], f"{self.imm12}({iregs[self.rs1]})"]
        elif self.name[:3] == 'csr': args = [iregs[self.rd], csrs.get(self.csr, hex(self.csr)), iregs[self.rs1] if 'rs1' in self.args else f'{hex(self.zimm) if abs(self.zimm) > 255 else self.zimm}']
        elif self.name[:5] == 'fence': args = [''.join(c for c, b in zip([*'iorw'], [i=='1' for i in f'{self.args[name]:04b}']) if b) for name in ('pred', 'succ') if name in self.args] + [f'fm={self.fm:04b}' if 'fm' in self.args else None]
        elif (self.name[:3] == 'c_f') or (self.name[0] == 'f'): args = [f'{k}={v}' for k, v in self.args.items()]  # TODO: fp ops
        elif 'rd_rs1_p' in self.args: args = [iregs[self.rd_rs1_p+8], iregs[self.rs2_p+8] if 'rs2_p' in self.args else f'{self.nzuimm6}' if 'nzuimm6' in self.args else f'{self.imm6}' if 'imm6' in self.args else None]
        elif 'rd_rs1_n0' in self.args: args = [iregs[self.rd_rs1_n0], iregs[self.rs2_n0] if 'rs2_n0' in self.args else f'{self.nzuimm6}' if 'nzuimm6' in self.args else f'{self.nzimm6}' if 'nzimm6' in self.args else f'{self.imm6}' if 'imm6' in self.args else None]
        elif 'rd_n0' in self.args: args = [iregs[self.rd_n0], f'{self.imm6}' if 'imm6' in self.args else f'{hex(self.uimm8sp)}(sp)' if 'uimm8sp' in self.args else f'{hex(self.uimm9sp)}(sp)' if 'uimm9sp' in self.args else iregs[self.rs2_n0]]
        elif self.name in {'c_sw', 'c_sd', 'c_lw', 'c_ld'}: args = [iregs[self.rs2_p+8] if 'rs2_p' in self.args else iregs[self.rd_p+8], (f'{self.uimm7}' if 'uimm7' in self.args else f'{self.uimm8}') + f'({iregs[self.rs1_p+8]})']
        elif self.name == 'c_lui': args = [iregs[self.rd_n2], hex(self.nzimm18)]
        elif self.name == 'c_swsp': args = [iregs[self.rs2], f'{hex(self.uimm8sp_s)}(sp)']
        elif self.name == 'c_sdsp': args = [iregs[self.rs2], f'{hex(self.uimm9sp_s)}(sp)']
        elif self.name == 'c_addi4spn': args = [iregs[self.rd_p+8], hex(self.nzuimm10)]
        elif self.name == 'c_addi16sp': args = [hex(self.nzimm10)]
        elif self.name == 'c_jalr': args = ['ra', iregs[self.rs1_n0]]
        elif self.name == 'c_jr': args = [iregs[self.rs1_n0]]
        elif self.name == 'c_j': args = [hex(self.imm12)]
        elif self.name in {'c_beqz', 'c_bnez'}: args = [iregs[self.rs1_p+8], f'{self.bimm9}']
        elif self.name == 'jal' or ('bimm12' in self.args): args = [iregs[self.rd] if 'rd' in self.args else None, iregs[self.rs1] if 'rs1' in self.args else None, iregs[self.rs2] if 'rs2' in self.args else None, hex(zext(64, self.addr+(self.jimm20 if 'jimm20' in self.args else self.bimm12)))]
        elif ('rd' in self.args) and ('rs1' in self.args): args = [iregs[self.rd], iregs[self.rs1], iregs[self.rs2] if 'rs2' in self.args else None, *[f'{hex(self.args[name]) if abs(self.args[name]) > 255 else self.args[name]}' for name in ('imm12','shamtw','shamtd') if name in self.args]]
        elif ('rd' in self.args) and ('imm20' in self.args): args = [iregs[self.rd], hex(zext(32,self.imm20) if 'l' in self.name else self.imm20) if abs(self.imm20) > 255 else f'{self.imm20}']
        else: args = [f'{k}={v}' for k, v in self.args.items()]  # fallback
        return ', '.join([a for a in args if a is not None])
    def valid(self): return min([not('nz' in k or 'n0' in k) or v!=0 for k, v in self.args.items()] + [hasattr(self, 'extension')])
    def __repr__(self): return f'{self.name.replace("_","."):10} {self.arg_str()}'

def rvsplitter(*data, base=0, lower16=0):  # yields addresses and 32-bit/16-bit(compressed) RISC-V instruction words.
    for addr, instr in enumerate(struct.iter_unpack('<H', open(data[0],'rb').read() if isinstance(data[0],str) and os.path.isfile(data[0]) else array.array('I',[int(d,16) if isinstance(d,str) else d for d in (data[0] if hasattr(data[0], '__iter__') and not isinstance(data[0],str) else data)]))):
        if lower16: yield int(base)+(addr-1)*2, (instr[0]<<16)|lower16; lower16 = 0
        elif instr[0]&3 == 3: lower16 = instr[0]  # Two LSBs set: 32-bit instruction
        else: yield int(base)+addr*2, instr[0]

@functools.lru_cache(maxsize=4096)
def decode(instr, addr=0, xlen=64):  # decodes one instruction
    o = rvop(addr=addr, data=instr, name=customs.get(instr&0b1111111,'UNKNOWN'), args={})
    for mask, m_dict in mask_match_rv64 if xlen==64 else mask_match_rv32:
        if op := m_dict.get(instr&mask, None):
            o.args = dict((vf, getter(instr)) for vf, getter in op['arg_getter'].items())
            [setattr(o,k,v) for k,v in (op|o.args).items()]
            break
    return o

def decoder(*data, base=0):  # yields decoded instructions.
    for addr, instr in rvsplitter(*data, base=base):
        if instr != 0: yield decode(instr, addr)

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
        def __getitem__(self, i): return self._csr[i]
        def __setitem__(self, i, d):
            if (self.sim.trace_log is not None) and (i != self.sim.MCYCLE): self.sim.trace_log.append(f'{csrs[i]}=' + (f'{zext(self.xlen, d):08x}' if self.xlen==32 else f'{zext(self.xlen, d):016x}'))
            if   i == self.sim.FCSR:   self._csr[self.sim.FCSR] = d&0xff; self._csr[self.sim.FFLAGS] = d&0x1f; self._csr[self.sim.FRM] = (d>>5)&7
            elif i == self.sim.FFLAGS: self._csr[self.sim.FCSR] = self._csr[self.sim.FCSR]&0xe0 | d&0x1f
            elif i == self.sim.FRM:    self._csr[self.sim.FCSR] = self._csr[self.sim.FCSR]&0x1f | ((d&7)<<5)
            else: self._csr[i] = d
    def __init__(self, xlen=64, trap_misaligned=True):
        self.xlen, self.trap_misaligned, self.trace_log = xlen, trap_misaligned, []
        self.pc, self.x, self.f, self.csr, self.lr_res_addr, self.cycle, self.current_mode, self.mem_psize, self.mem_pages = 0, self.rvregs(self.xlen, self), self.rvfregs(64, self), self.rvcsrs(self.xlen, self), -1, 0, 3, 2<<20, collections.defaultdict(functools.partial(bytearray, 2<<20+2))  # 2-byte overlap for loading unaligned 32-bit opcodes
        [setattr(self, n.upper(), i) for i, n in list(enumerate(iregs))+list(csrs.items())]  # convenience
    def hook_csr(self, csr, reqval): return reqval if (csr&0xc00)!=0xc00 else self.csr[csr]
    def notify_stored(self, addr): pass  # called *after* mem store
    def notify_loading(self, addr): pass  # called *before* mem load
    def mtrap(self, tval, cause):
        self.csr[self.MTVAL], self.csr[self.MEPC], self.csr[self.MCAUSE], self.pc = zext(self.xlen,tval), self.op.addr, cause, zext(self.xlen,self.csr[self.MTVEC]&(~3))  # TODO: vectored interrupts
        if self.trace_log is not None: self.trace_log.append(f'mtrap from_mode={self.current_mode} cause={hex(cause)} tval={hex(tval)}')
        self.csr[self.MSTATUS], self.current_mode = ((self.csr[self.MSTATUS]&0x08) << 4) | (self.current_mode << 11), 3
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
    def store(self, format, addr, data, notify=True):
        if self.trace_log is not None: self.trace_log.append(f'{xfmt(struct.calcsize(format)*8, data)}->mem[{xfmt(self.xlen, addr)}]')
        if self.trap_misaligned and addr&(struct.calcsize(format)-1) != 0: self.mtrap(addr, 6)
        else: struct.pack_into(format, *self.page_and_offset(zext(self.xlen,addr)), data)
        if notify: self.notify_stored(zext(self.xlen,addr))
    def load(self, format, addr, fallback=0, notify=True):
        if self.trap_misaligned and addr&(struct.calcsize(format)-1) != 0: self.mtrap(addr, 4); return fallback
        addr = zext(self.xlen, addr)
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
    def _slli      (self, rd, rs1, shamtd,    **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  << shamtd)  # shared with RV64I
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
    def _csrrw     (self, rd, csr, rs1,       **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.x[rs1]               )
    def _csrrs     (self, rd, csr, rs1,       **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.csr[csr]| self.x[rs1])
    def _csrrc     (self, rd, csr, rs1,       **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.csr[csr]&~self.x[rs1])
    def _csrrwi    (self, rd, csr, zimm,      **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, zimm                      )
    def _csrrsi    (self, rd, csr, zimm,      **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.csr[csr]| zimm       )
    def _csrrci    (self, rd, csr, zimm,      **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.hook_csr(csr, self.csr[csr]&~zimm       )
    def _mret      (self,                     **_): self.pc = zext(self.xlen, self.csr[self.MEPC]); mmode = (self.csr[self.MSTATUS]>>11)&3; self.csr[self.MSTATUS] = (self.current_mode << 11) | 0x80 | ((self.csr[self.MSTATUS]&0x80) >> 4); self.current_mode = mmode
    def _ecall     (self,                     **_): self.mtrap(0, 8 if self.current_mode == 0 else 11)
    def _ebreak    (self,                     **_): self.mtrap(self.op.addr, 3)
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
    def _sc_w      (self, rd, rs1, rs2,       **_):
        if self.lr_res_addr == self.x[rs1]: self.pc+=4; self.lr_res_addr = -1; self.store('i', self.x[rs1], sext(32, self.x[rs2])); self.x[rd] = 0
        else:                               self.pc+=4; self.lr_res_addr = -1;                                                      self.x[rd] = 1
    def _lr_d      (self, rd, rs1,            **_): self.pc+=4; self.lr_res_addr = self.x[rs1]; self.x[rd] = self.load('q', self.x[rs1], self.x[rd])
    def _sc_d      (self, rd, rs1, rs2,       **_):
        if self.lr_res_addr == self.x[rs1]: self.pc+=4; self.lr_res_addr = -1; self.store('q', self.x[rs1], sext(64, self.x[rs2])); self.x[rd] = 0
        else:                               self.pc+=4; self.lr_res_addr = -1;                                                      self.x[rd] = 1
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
    def _c_addi4spn(self, rd_p, nzuimm10,     **_): self.pc+=2; self.x[rd_p+8]     = self.x[2] + nzuimm10
    def _c_lw      (self, rd_p, rs1_p, uimm7, **_): self.pc+=2; self.x[rd_p+8]     = self.load('i', self.x[rs1_p+8]+uimm7, self.x[rd_p+8])
    def _c_ld      (self, rd_p, rs1_p, uimm8, **_): self.pc+=2; self.x[rd_p+8]     = self.load('q', self.x[rs1_p+8]+uimm8, self.x[rd_p+8])
    def _c_lwsp    (self, rd_n0, uimm8sp,     **_): self.pc+=2; self.x[rd_n0]      = self.load('i', self.x[2]+uimm8sp, self.x[rd_n0])
    def _c_ldsp    (self, rd_n0, uimm9sp,     **_): self.pc+=2; self.x[rd_n0]      = self.load('q', self.x[2]+uimm9sp, self.x[rd_n0])
    def _c_addi16sp(self, nzimm10,            **_): self.pc+=2; self.x[2]         += nzimm10
    def _c_swsp    (self, rs2, uimm8sp_s,     **_): self.pc+=2; self.store('I', self.x[2]+uimm8sp_s,   zext(32,self.x[rs2]))
    def _c_sdsp    (self, rs2, uimm9sp_s,     **_): self.pc+=2; self.store('Q', self.x[2]+uimm9sp_s,   zext(64,self.x[rs2]))
    def _c_sw      (self, rs1_p,rs2_p, uimm7, **_): self.pc+=2; self.store('I', self.x[rs1_p+8]+uimm7, zext(32,self.x[rs2_p+8]))
    def _c_sd      (self, rs1_p,rs2_p, uimm8, **_): self.pc+=2; self.store('Q', self.x[rs1_p+8]+uimm8, zext(64,self.x[rs2_p+8]))
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
    def _fsw       (self, rs1, rs2, imm12,    **_): self.pc+=4; self.store('I', self.x[rs1]+imm12, zext(32, self.f.raw[rs2]))
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
    def _fsub_s    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f32.add(self.f.raw_s[rs1], self.f.raw_s[rs2]^0x80000000                                 , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmul_s    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f32.mul(self.f.raw_s[rs1], self.f.raw_s[rs2]                                            , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fdiv_s    (self, rs1, rs2, rd, rm,   **_): self.pc+=4; f = f32.div(self.f.raw_s[rs1], self.f.raw_s[rs2]                                            , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmadd_s   (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f32.mad(self.f.raw_s[rs1], self.f.raw_s[rs2]              , self.f.raw_s[rs3]           , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmsub_s   (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f32.mad(self.f.raw_s[rs1], self.f.raw_s[rs2]              , self.f.raw_s[rs3]^0x80000000, rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fnmsub_s  (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f32.mad(self.f.raw_s[rs1], self.f.raw_s[rs2]              , self.f.raw_s[rs3]           , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm, negate_product=True); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fnmadd_s  (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f32.mad(self.f.raw_s[rs1], self.f.raw_s[rs2]              , self.f.raw_s[rs3]^0x80000000, rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm, negate_product=True); self.f.s[rd] = f.float; self.csr[self.FCSR] |= f.flags
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
    def _fsgnj_d   (self, rs1, rs2, rd,       **_): self.pc+=4; self.f.d[rd] = self.f.raw_d[rs1]&0x7fffffff_ffffffff | self.f.raw_d[rs2]&f64.SIGN_BIT
    def _fsgnjn_d  (self, rs1, rs2, rd,       **_): self.pc+=4; self.f.d[rd] = self.f.raw_d[rs1]&0x7fffffff_ffffffff | (~self.f.raw_d[rs2])&f64.SIGN_BIT
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
    def _fmadd_d   (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f64.mad(self.f.raw_d[rs1], self.f.raw_d[rs2]              , self.f.raw_d[rs3]           , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmsub_d   (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f64.mad(self.f.raw_d[rs1], self.f.raw_d[rs2]              , self.f.raw_d[rs3]^f64.SIGN_BIT, rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fnmsub_d  (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f64.mad(self.f.raw_d[rs1], self.f.raw_d[rs2]              , self.f.raw_d[rs3]           , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm, negate_product=True); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fnmadd_d  (self, rs1,rs2,rs3,rd, rm, **_): self.pc+=4; f = f64.mad(self.f.raw_d[rs1], self.f.raw_d[rs2]              , self.f.raw_d[rs3]^f64.SIGN_BIT, rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm, negate_product=True); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmin_d    (self, rs1, rs2, rd,       **_): self.pc+=4; f = f64.min(self.f.raw_d[rs1], self.f.raw_d[rs2]                                                                                                                 ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fmax_d    (self, rs1, rs2, rd,       **_): self.pc+=4; f = f64.max(self.f.raw_d[rs1], self.f.raw_d[rs2]                                                                                                                 ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def _fsqrt_d   (self, rs1, rd, rm,        **_): self.pc+=4; f = f64.sqrt(self.f.raw_d[rs1]                                                              , rm=(self.csr[self.FCSR]>>5)&7 if rm==7 else rm                     ); self.f.d[rd] = f.float; self.csr[self.FCSR] |= f.flags
    def hook_exec(self): return True
    def unimplemented(self, **_): print(f'\n{zext(64,self.op.addr):08x}: unimplemented: {zext(32,self.op.data):08x} {self.op}')
    def step(self, trace=True):
        self.op = decode(struct.unpack_from('I', *self.page_and_offset(self.pc))[0], 0, self.xlen); self.op.addr=self.pc  # setting op.addr afterwards enables opcode caching.
        self.trace_log = [] if trace else None
        if self.hook_exec():
            self.cycle += 1; self.csr[self.MCYCLE] = zext(self.xlen, self.cycle)
            getattr(self, '_'+self.op.name, self.unimplemented)(**self.op.args)  # dynamic instruction dispatch
            if trace: print(f'{zext(64,self.op.addr):08x}: {str(self.op):40} # [{self.cycle-1}]', ' '.join(self.trace_log))
            if trace and self.pc-self.op.addr not in (2, 4): print()
    def run(self, limit=0, bpts=set(), trace=True):
        while True:
            self.step(trace=trace)
            if self.op.addr in bpts|{self.pc} or (limit := limit-1)==0: break