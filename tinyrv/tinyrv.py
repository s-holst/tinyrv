import os, struct, array, struct
from .opcodes import *

iregs = 'zero,ra,sp,gp,tp,t0,t1,t2,fp,s1,a0,a1,a2,a3,a4,a5,a6,a7,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,t3,t4,t5,t6'.split(',')
def zext(length, word): return word&((1<<length)-1)
def sext(length, word): return word|~((1<<length)-1) if word&(1<<(length-1)) else zext(length, word)
def xfmt(length, word): return f'{{:0{length//4}x}}'.format(zext(length, word))

class rvop:
    def __init__(self, **kwargs): [setattr(self, k, v) for k, v in kwargs.items()]
    def arg_str(self):
        if self.name in 'lb,lh,lw,ld,lbu,lhu,lwu,sb,sh,sw,sd,jalr'.split(','): args = [iregs[self.rd] if 'rd' in self.args else iregs[self.rs2], f"{self.imm12}({iregs[self.rs1]})"]
        elif self.name[:3] == 'csr': args = [iregs[self.rd], csrs.get(self.csr, hex(self.csr)), iregs[self.rs1] if 'rs1' in self.args else f'{hex(self.zimm) if abs(self.zimm) > 255 else self.zimm}']
        elif self.name[:5] == 'fence': args = [''.join(c for c, b in zip([*'iorw'], [i=='1' for i in f'{self.args[name]:04b}']) if b) for name in ('pred', 'succ') if name in self.args] + [f'fm={self.fm:04b}' if 'fm' in self.args else None]
        elif (self.name[:2] == 'c_') or (self.name[0] == 'f'): args = [f'{k}={v}' for k, v in self.args.items()]  # TODO: compressed and fp ops
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

def rvdecode(instr, addr=0):
    o = rvop(addr=addr, data=instr, name={0b0001011: 'custom0', 0b0101011: 'custom1', 0b1011011: 'custom2', 0b1111011: 'custom3'}.get(instr&0b1111111,'UNKNOWN'), args={})
    for mask, m_dict in mm_dicts:
        if op := m_dict.get(instr&mask, None):
            for vf, bits in op['arg_bits'].items():
                value = 0
                for bit in bits: value = (value<<1) | ((instr>>bit)&1 if bit>=0 else 0)
                o.args[vf] = sext(len(bits), value) if bits[0] == 31 else value
            [setattr(o,k,v) for k,v in (op|o.args).items()]
            break
    return o

def rvdecoder(*data, base=0):  # yields decoded instructions.
    for addr, instr in rvsplitter(*data, base=base):
        if instr != 0: yield rvdecode(instr, addr)

class rvregs:
    def __init__(self, xlen, trace_log): self._x, self.xlen, self.trace_log = [0]*32, xlen, trace_log
    def __getitem__(self, i): return self._x[i]
    def __setitem__(self, i, d):
        if i!=0 and (self.trace_log is not None) and d!=self._x[i]: self.trace_log.append(f'{iregs[i]}=' + (f'{zext(self.xlen, d):08x}' if d>>32 in (0, -1) else f'{zext(self.xlen, d):016x}'))
        if i!=0: self._x[i] = d

class rvsim:  # simulates RV32IMAZicsr_Zifencei, RV64IMAZicsr_Zifencei
    def __init__(self, xlen=64, misaligned_exceptions=True):
        self.xlen, self.misaligned_exceptions, self.trace_log = xlen, misaligned_exceptions, []
        self.pc, self.x, self.f, self.csr, self.lr_res_addr, self.cycle, self.current_mode, self.mem_psize, self.mem_pages, self.fmt_conv = 0, rvregs(self.xlen, self.trace_log), [0]*32, [0]*4096, -1, 0, 3, 2<<12, {}, {'q': 64, 'Q': 64, 'i': 32, 'I': 32, 'h': 16, 'H': 16, 'b': 8, 'B': 8, 32: 'i', 64: 'q'}
        [setattr(self, n, i) for i, n in list(enumerate(iregs))+list(csrs.items())]  # convenience
    def __repr__(self): return '\n'.join(['  '.join([f'x{r+rr:02d}({(iregs[r+rr])[-2:]})={xfmt(self.xlen, self.x[r+rr])}' for r in range(0, 32, 8)]) for rr in range(8)])
    def csr_hook(self, csr, reqval): return reqval if (csr&0xc00)!=0xc00 else self.csr[csr]
    def store_notify(self, addr): pass  # called *after* each store to memory
    def load_notify(self, addr): pass  # called *before* each load from memory
    def mtrap(self, tval, cause):
        self.csr[self.mtval], self.csr[self.mepc], self.csr[self.mcause], self.pc = zext(self.xlen,tval), self.op.addr, cause, zext(self.xlen,self.csr[self.mtvec]&(~3))
        if self.trace_log is not None: self.trace_log.append(f'mtrap cause={hex(cause)} tval={hex(tval)}')
        self.csr[self.mstatus] = ((self.csr[self.mstatus]&0x08) << 4) | (self.current_mode << 11)
    def read_bin(self, file, base=0): [self.store(i+base, b, 'B') for i, b in enumerate(open(file, 'rb').read())]  # FIXME: SLOOOOW
    def page_pa_(self, addr):
        pb, pa = addr&~(self.mem_psize-1), addr&(self.mem_psize-1)
        if pb not in self.mem_pages: self.mem_pages[pb] = bytearray(self.mem_psize)
        return self.mem_pages[pb], pa
    def store(self, addr, data, fmt=None, notify=True):
        page, pa, fmt = (*self.page_pa_(addr), fmt or self.fmt_conv[self.xlen])
        page[pa:pa+self.fmt_conv[fmt[-1:]]//8] = struct.pack(fmt, data)
        if self.trace_log is not None: self.trace_log.append(f'{xfmt(self.fmt_conv[fmt[-1:]], data)}->mem[{xfmt(self.xlen, addr)}]')
        if notify: self.store_notify(addr)
    def load(self, addr, fmt=None, notify=True):
        if notify: self.load_notify(addr)
        page, pa, fmt = (*self.page_pa_(addr), fmt or self.fmt_conv[self.xlen])
        data = struct.unpack(fmt, page[pa:pa+self.fmt_conv[fmt[-1:]]//8])[0]
        if self.trace_log is not None: self.trace_log.append(f'mem[{xfmt(self.xlen, addr)}]->{xfmt(self.fmt_conv[fmt[-1:]], data)}')
        return data
    def checked_store(self, addr, data, fmt, alignmask):
        if addr&alignmask != 0 and self.misaligned_exceptions: self.mtrap(addr, 6)
        else: self.store(zext(self.xlen,addr), data, fmt)
    def checked_load (self, addr, fallback, fmt, alignmask):
        if addr&alignmask != 0 and self.misaligned_exceptions: self.mtrap(addr, 4); return fallback
        else: return self.load(zext(self.xlen,addr), fmt)
    def idiv2zero(self, a, b): return -(-a // b) if (a < 0) ^ (b < 0) else a // b
    def rem2zero(self, a, b): return a - b * self.idiv2zero(a, b)
    def _auipc    (self, rd, imm20,        **_): self.pc+=4; self.x[rd] = sext(self.xlen, self.op.addr+imm20)
    def _lui      (self, rd, imm20,        **_): self.pc+=4; self.x[rd] = imm20
    def _jal      (self, rd, jimm20,       **_): self.pc, self.x[rd] = zext(self.xlen, self.op.addr+jimm20),    self.op.addr+4
    def _jalr     (self, rd, rs1, imm12,   **_): self.pc, self.x[rd] = zext(self.xlen, self.x[rs1]+imm12)&(~1), self.op.addr+4 # LSB=0
    def _beq      (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] == self.x[rs2] else self.op.addr+4
    def _bne      (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] != self.x[rs2] else self.op.addr+4
    def _blt      (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] <  self.x[rs2] else self.op.addr+4
    def _bge      (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] >= self.x[rs2] else self.op.addr+4
    def _bltu     (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if zext(self.xlen, self.x[rs1]) <  zext(self.xlen, self.x[rs2]) else self.op.addr+4
    def _bgeu     (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if zext(self.xlen, self.x[rs1]) >= zext(self.xlen, self.x[rs2]) else self.op.addr+4
    def _sb       (self, rs1, rs2, imm12,  **_): self.pc+=4; self.store(    zext(self.xlen, self.x[rs1]+imm12), self.x[rs2]&((1<<8)-1), 'B')
    def _sh       (self, rs1, rs2, imm12,  **_): self.pc+=4; self.checked_store(zext(self.xlen, self.x[rs1]+imm12), zext(16,self.x[rs2]), 'H', 1)
    def _sw       (self, rs1, rs2, imm12,  **_): self.pc+=4; self.checked_store(zext(self.xlen, self.x[rs1]+imm12), zext(32,self.x[rs2]), 'I', 3)
    def _sd       (self, rs1, rs2, imm12,  **_): self.pc+=4; self.checked_store(zext(self.xlen, self.x[rs1]+imm12), zext(64,self.x[rs2]), 'Q', 7)
    def _lb       (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = self.load(zext(self.xlen, self.x[rs1]+imm12), 'b')
    def _lbu      (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = self.load(zext(self.xlen, self.x[rs1]+imm12), 'B')
    def _lh       (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = self.checked_load(self.x[rs1]+imm12, self.x[rd], 'h', 1)
    def _lw       (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = self.checked_load(self.x[rs1]+imm12, self.x[rd], 'i', 3)
    def _ld       (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = self.checked_load(self.x[rs1]+imm12, self.x[rd], 'q', 7)
    def _lhu      (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = self.checked_load(self.x[rs1]+imm12, self.x[rd], 'H', 1)
    def _lwu      (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = self.checked_load(self.x[rs1]+imm12, self.x[rd], 'I', 3)
    def _addi     (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  +          imm12)
    def _xori     (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  ^          imm12)
    def _ori      (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  |          imm12)
    def _andi     (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  &          imm12)
    def _addiw    (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(32,          self.x[rs1]  +          imm12)
    def _addw     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, sext(32, self.x[rs1]) + sext(32, self.x[rs2]))
    def _subw     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, sext(32, self.x[rs1]) - sext(32, self.x[rs2]))
    def _add      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  +          self.x[rs2])
    def _sub      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  -          self.x[rs2])
    def _xor      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  ^          self.x[rs2])
    def _or       (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  |          self.x[rs2])
    def _and      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  &          self.x[rs2])
    def _sltiu    (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = zext(self.xlen,   self.x[rs1]) < zext(self.xlen, imm12)
    def _sltu     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = zext(self.xlen,   self.x[rs1]) < zext(self.xlen, self.x[rs2])
    def _slti     (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] =                   self.x[rs1]  <                 imm12
    def _slt      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] =                   self.x[rs1]  <                 self.x[rs2]
    def _slliw    (self, rd, rs1, shamtw,  **_): self.pc+=4; self.x[rd] = sext(32,                        self.x[rs1]  << shamtw)
    def _srliw    (self, rd, rs1, shamtw,  **_): self.pc+=4; self.x[rd] = sext(32,        zext(32,        self.x[rs1]) >> shamtw)
    def _sraiw    (self, rd, rs1, shamtw,  **_): self.pc+=4; self.x[rd] = sext(32,        sext(32,        self.x[rs1]) >> shamtw)
    def _slli     (self, rd, rs1, shamtd,  **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  << shamtd)  # shared with RV64I
    def _srai     (self, rd, rs1, shamtd,  **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  >> shamtd)  # shared with RV64I
    def _srli     (self, rd, rs1, shamtd,  **_): self.pc+=4; self.x[rd] = sext(self.xlen, zext(self.xlen, self.x[rs1]) >> shamtd)  # shared with RV64I
    def _sll      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  << (self.x[rs2]&(self.xlen-1)))
    def _srl      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, zext(self.xlen, self.x[rs1]) >> (self.x[rs2]&(self.xlen-1)))
    def _sra      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  >> (self.x[rs2]&(self.xlen-1)))
    def _sllw     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32,        sext(32,        self.x[rs1]) << (self.x[rs2]&31))
    def _srlw     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32,        zext(32,        self.x[rs1]) >> (self.x[rs2]&31))
    def _sraw     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32,        sext(32,        self.x[rs1]) >> (self.x[rs2]&31))
    def _fence    (self,                   **_): self.pc+=4
    def _fence_i  (self,                   **_): self.pc+=4
    def _csrrw    (self, rd, csr, rs1,     **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.csr_hook(csr, self.x[rs1]               )
    def _csrrs    (self, rd, csr, rs1,     **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.csr_hook(csr, self.csr[csr]| self.x[rs1])
    def _csrrc    (self, rd, csr, rs1,     **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.csr_hook(csr, self.csr[csr]&~self.x[rs1])
    def _csrrwi   (self, rd, csr, zimm,    **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.csr_hook(csr, zimm                      )
    def _csrrsi   (self, rd, csr, zimm,    **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.csr_hook(csr, self.csr[csr]| zimm       )
    def _csrrci   (self, rd, csr, zimm,    **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.csr_hook(csr, self.csr[csr]&~zimm       )
    def _mret     (self,                   **_): self.pc = zext(self.xlen, self.csr[self.mepc]); mmode = (self.csr[self.mstatus]>>11)&3; self.csr[self.mstatus] = (self.current_mode << 11) | 0x80 | ((self.csr[self.mstatus]&0x80) >> 4); self.current_mode = mmode
    def _ecall    (self,                   **_): self.mtrap(0, 8 if self.current_mode == 0 else 11); #print('****ecall')
    def _ebreak   (self,                   **_): self.mtrap(self.op.addr, 3); #print('****ebreak')
    def _mul      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (                self.x[rs1]  *                 self.x[rs2] )           )
    def _mulh     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (                self.x[rs1]  *                 self.x[rs2] )>>self.xlen)
    def _mulhu    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (zext(self.xlen, self.x[rs1]) * zext(self.xlen, self.x[rs2]))>>self.xlen)
    def _mulhsu   (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (                self.x[rs1]  * zext(self.xlen, self.x[rs2]))>>self.xlen)
    def _div      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (self.idiv2zero( self.x[rs1]  ,                 self.x[rs2]))           ) if self.x[rs2] != 0 else -1
    def _divu     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (zext(self.xlen, self.x[rs1]) //zext(self.xlen, self.x[rs2]))           ) if self.x[rs2] != 0 else -1
    def _rem      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (self.rem2zero ( self.x[rs1]  ,                 self.x[rs2]))           ) if self.x[rs2] != 0 else self.x[rs1]
    def _remu     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (zext(self.xlen, self.x[rs1]) % zext(self.xlen, self.x[rs2]))           ) if self.x[rs2] != 0 else self.x[rs1]
    def _mulw     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32,        (sext(32,        self.x[rs1]) * sext(32,        self.x[rs2]))           )
    def _divw     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, (self.idiv2zero(sext(32,self.x[rs1]) , sext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else -1
    def _divuw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, (self.idiv2zero(zext(32,self.x[rs1]) , zext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else -1
    def _remw     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, (self.rem2zero (sext(32,self.x[rs1]) , sext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else sext(32,self.x[rs1])
    def _remuw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, (self.rem2zero (zext(32,self.x[rs1]) , zext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else sext(32,self.x[rs1])
    def _amoswap_w(self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'i', 3); self.checked_store(ors1,                            sext(32,ors2),   'i', 3); self.x[rd]=tmp
    def _amoadd_w (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'i', 3); self.checked_store(ors1, sext(32,             tmp + sext(32,ors2)),  'i', 3); self.x[rd]=tmp
    def _amoand_w (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'i', 3); self.checked_store(ors1, sext(32,             tmp & sext(32,ors2)),  'i', 3); self.x[rd]=tmp
    def _amoor_w  (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'i', 3); self.checked_store(ors1, sext(32,             tmp | sext(32,ors2)),  'i', 3); self.x[rd]=tmp
    def _amoxor_w (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'i', 3); self.checked_store(ors1, sext(32,             tmp ^ sext(32,ors2)),  'i', 3); self.x[rd]=tmp
    def _amomax_w (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'i', 3); self.checked_store(ors1, sext(32, max(        tmp , sext(32,ors2))), 'i', 3); self.x[rd]=tmp
    def _amomin_w (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'i', 3); self.checked_store(ors1, sext(32, min(        tmp , sext(32,ors2))), 'i', 3); self.x[rd]=tmp
    def _amomaxu_w(self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'i', 3); self.checked_store(ors1, sext(32, max(zext(32,tmp), zext(32,ors2))), 'i', 3); self.x[rd]=tmp
    def _amominu_w(self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'i', 3); self.checked_store(ors1, sext(32, min(zext(32,tmp), zext(32,ors2))), 'i', 3); self.x[rd]=tmp
    def _amoswap_d(self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'q', 7); self.checked_store(ors1,                                    ors2,    'q', 7); self.x[rd]=tmp
    def _amoadd_d (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'q', 7); self.checked_store(ors1, sext(64,             tmp +         ors2 ),  'q', 7); self.x[rd]=tmp
    def _amoand_d (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'q', 7); self.checked_store(ors1, sext(64,             tmp &         ors2 ),  'q', 7); self.x[rd]=tmp
    def _amoor_d  (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'q', 7); self.checked_store(ors1, sext(64,             tmp |         ors2 ),  'q', 7); self.x[rd]=tmp
    def _amoxor_d (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'q', 7); self.checked_store(ors1, sext(64,             tmp ^         ors2 ),  'q', 7); self.x[rd]=tmp
    def _amomax_d (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'q', 7); self.checked_store(ors1, sext(64, max(        tmp , sext(64,ors2))), 'q', 7); self.x[rd]=tmp
    def _amomin_d (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'q', 7); self.checked_store(ors1, sext(64, min(        tmp , sext(64,ors2))), 'q', 7); self.x[rd]=tmp
    def _amomaxu_d(self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'q', 3); self.checked_store(ors1, sext(64, max(zext(64,tmp), zext(64,ors2))), 'q', 7); self.x[rd]=tmp
    def _amominu_d(self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; tmp = self.checked_load(self.x[rs1], self.x[rd], 'q', 3); self.checked_store(ors1, sext(64, min(zext(64,tmp), zext(64,ors2))), 'q', 7); self.x[rd]=tmp
    def _lr_w     (self, rd, rs1,          **_): self.pc+=4; self.lr_res_addr = self.x[rs1]; self.x[rd] = self.checked_load(self.x[rs1], self.x[rd], 'i', 3)
    def _sc_w     (self, rd, rs1, rs2,     **_): 
        if self.lr_res_addr == self.x[rs1]: self.pc+=4; self.lr_res_addr = -1; self.checked_store(self.x[rs1], sext(32, self.x[rs2]), 'i', 3); self.x[rd] = 0
        else: self.pc+=4; self.lr_res_addr = -1; self.x[rd] = 1
    def _c_addi  (self, rd_rs1_n0, nzimm6, **_): self.pc+=2; self.x[rd_rs1_n0] += nzimm6  # c.nop required to pass test rv32i_m/privilege/src/misalign-jal-01.S
    def hook_exec(self): return True
    def step(self, trace=True):
        self.op = rvdecode(self.load(self.pc, 'I', notify=False), addr=self.pc)
        self.cycle += 1; self.csr[self.mcycle] = zext(self.xlen, self.cycle)
        self.trace_log = [] if trace else None
        self.x.trace_log = self.trace_log
        if self.hook_exec():
            if hasattr(self, '_'+self.op.name): getattr(self, '_'+self.op.name)(**self.op.args)  # instruction dispatch 
            else: print(f'\n{zext(64,self.op.addr):08x}: unimplemented: {zext(32,self.op.data):08x} {self.op}')
            if trace: print(f'{zext(64,self.op.addr):08x}: {str(self.op):40} #', ' '.join(self.trace_log))
            if trace and self.pc-self.op.addr not in (2, 4): print()
    def run(self, limit=0, bpts=set(), trace=True):
        while True:
            self.step(trace=trace)
            if self.op.addr in bpts|{self.pc} or (limit := limit-1)==0: break