import os, re, csv, struct, array, struct, yaml, pathlib, importlib.resources, functools

try:
    base = pathlib.Path('.') if pathlib.Path('tinyrv_opcodes').exists() else importlib.resources.files('tinyrv')
    opcodes = yaml.safe_load(open(base / 'tinyrv_opcodes/instr_dict.yaml'))
    for aname, op in opcodes.items(): op['name'] = aname
    mask_match = [(int(op['mask'], 16), int(op['match'], 16), op) for op in opcodes.values()]
    def dr(h,l): return list(range(h,l-1,-1))
    arg_bits = dict((a, dr(int(h),int(l))) for a, h, l in csv.reader(open(base / 'tinyrv_opcodes/arg_lut.csv'), skipinitialspace=True))
    for s in open(base / 'tinyrv_opcodes/constants.py').readlines():  # immediate scrambling from latex_mapping. Some better way?
        if m := re.match(r"latex_mapping\[['\"](.*?)['\"]\] = ['\"][^\[]*\[([^\]]*)\]['\"]", s):
            fbits = sum([(dr(*(int(i) for i in part.split(':'))) if ':' in part else [int(part)]) for part in m[2].split('$\\\\vert$')], [])
            locs = [-1] * (max(fbits)+1)
            for i, b in enumerate(fbits): locs[-b-1] = arg_bits[m[1]][i]
            arg_bits[m[1]] = [31] * (32-len(locs)) + locs if locs[0] == 31 else locs  # sign extension to 32 bits
    csrs = dict((int(a, 16), n) for fn in ['tinyrv_opcodes/csrs.csv', 'tinyrv_opcodes/csrs32.csv'] for a, n in csv.reader(open(base / fn), skipinitialspace=True))
except Exception as e: raise Exception("Unable to load RISC-V specs. Do:\n"
                                       "git clone https://github.com/riscv/riscv-opcodes.git tinyrv_opcodes\n"
                                       "cd tinyrv_opcodes; make")

iregs = 'zero,ra,sp,gp,tp,t0,t1,t2,fp,s1,a0,a1,a2,a3,a4,a5,a6,a7,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,t3,t4,t5,t6'.split(',')
def zext(length, word): return word&((1<<length)-1)
def sext(length, word): return word|~((1<<length)-1) if word&(1<<(length-1)) else zext(length, word)
def xfmt(length, word): return f'{{:0{length//4}x}}'.format(zext(length, word))

class rvop:
    def __init__(self, **kwargs): [setattr(self, k, v) for k, v in kwargs.items()]
    def arg_str(self):
        args = [None]*4
        for k, v in self.args.items():  # hand-coded argument formats
            k = k.replace('c_','').replace('_n0','')
            if self.name[:5] == 'fence':
                if k in {'pred', 'succ'}: args[{'pred': 0, 'succ': 1}[k]] = ''.join(c for c, b in zip([*'iorw'], [i=='1' for i in f'{v:04b}']) if b)
                elif k == 'fm': args.append(f'{k}={v:04b}')
            elif self.name[:2] == 'c.' or self.name[0] == 'f': args.append(f'{k}={v}')  # TODO: compressed and fp ops
            elif k == 'rd': args[0] = iregs[v]
            elif k == 'csr': args[1] = csrs.get(v, hex(v))
            elif k == 'rs1': args[2] = f"{self.args['imm12']}({iregs[v]})" if self.name in 'lb,lh,lw,ld,lbu,lhu,lwu,sb,sh,sw,sd,jalr'.split(',') else iregs[v]
            elif k == 'rs2': args[3] = iregs[v]
            elif k in ['imm12', 'zimm']: args.append(f'{hex(v) if abs(v) > 255 else v}' if self.name not in 'lb,lh,lw,ld,lbu,lhu,lwu,sb,sh,sw,sd,jalr'.split(',') else None)
            elif k in ['jimm20', 'bimm12']: args.append(hex(zext(64, self.addr+v)))
            elif k in ['imm20']: args.append(hex(zext(32,v) if 'l' in self.name else v) if abs(v) > 255 else f'{v}')
            elif 'sham' in k: args.append(f'{v}')
            else: args.append(f'{k}={v}')  # fallback
        args = args[::-1] if self.name in 'sb,sh,sw,sd'.split(',') else args  # snowflake sb/sh/sw/sd arg order: <src>, <dst>
        return ', '.join([a for a in args if a is not None])
    def valid(self): return min([not('nz' in k or 'n0' in k) or v!=0 for k, v in self.args.items()] + [hasattr(self, 'extension')])
    def __repr__(self): return f'{self.name.replace("_","."):10} {self.arg_str()}'

def rvsplitter(*data, base=0, lower16=0):  # yields addresses and 32-bit/16-bit(compressed) RISC-V instruction words.
    for addr, instr in enumerate(struct.iter_unpack('<H', open(data[0],'rb').read() if isinstance(data[0],str) and os.path.isfile(data[0]) else array.array('I',[int(d,16) if isinstance(d,str) else d for d in (data[0] if hasattr(data[0], '__iter__') and not isinstance(data[0],str) else data)]))):
        if lower16: yield int(base)+(addr-1)*2, (instr[0]<<16)|lower16; lower16 = 0
        elif instr[0]&3 == 3: lower16 = instr[0]  # Two LSBs set: 32-bit instruction
        else: yield int(base)+addr*2, instr[0]

def rvdecoder(*data, base=0):  # yields decoded ops.
    for addr, instr in rvsplitter(*data, base=base):
        if instr == 0: continue  # RV-spec: 0x0 is invalid - skip
        o = rvop(addr=addr, data=instr, name={0b0001011: 'custom0', 0b0101011: 'custom1', 0b1011011: 'custom2', 0b1111011: 'custom3'}.get(instr&0b1111111,'UNKNOWN'), args={})
        for mask, match, op in mask_match:
            if instr&mask == match:
                for vf in op['variable_fields']:
                    value = functools.reduce(int.__or__, [((instr>>bit)&1 if bit>=0 else 0) << pos for pos, bit in enumerate(arg_bits[vf][::-1])])
                    vf = vf.replace('hi','').replace('lo','').replace('c_','')
                    o.args[vf] = o.args.get(vf, 0) | sext(32, value)
                    if '_p' in vf: o.args[vf.replace('_p','')] = o.args[vf]+8  # reg aliases for some compressed instructions
                    if '_n0' in vf: o.args[vf.replace('_n0','')] = o.args[vf]
                [setattr(o,k,v) for k,v in (op|o.args).items()]
                break
        yield o

def rvprint(*data, base=0):  # prints listing of decoded instructions.
    for op in rvdecoder(*data, base=base): print(f'{zext(64,op.addr):08x}: {str(op):40} # {", ".join(op.extension) if op.valid() else "INVALID data=" + hex(op.data)}')

class rvregs:
    def __init__(self, xlen, trace_log): self._x, self.xlen, self.trace_log = [0]*32, xlen, trace_log
    def __getitem__(self, i): return self._x[i]
    def __setitem__(self, i, d):
        if i!=0 and d!=self._x[i]: self.trace_log.append(f'{iregs[i]}=' + (f'{zext(self.xlen, d):08x}' if d>>32 in (0, -1) else f'{zext(self.xlen, d):016x}'))
        if i!=0: self._x[i] = d

class rvsim:  # simulates RV32IMZicsr_Zifencei, RV64IMZicsr_Zifencei
    def __init__(self, xlen=64, misaligned_exceptions=True):
        self.xlen, self.misaligned_exceptions, self.trace_log = xlen, misaligned_exceptions, []
        self.pc, self.x, self.f, self.csr, self.mem_psize, self.mem_pages, self.fmt_conv = 0, rvregs(self.xlen, self.trace_log), [0]*32, [0]*4096, 2<<12, {}, {'q': 64, 'Q': 64, 'i': 32, 'I': 32, 'h': 16, 'H': 16, 'b': 8, 'B': 8, 32: 'i', 64: 'q'}
        [setattr(self, n, i) for i, n in enumerate(iregs)]
        [setattr(self, n, a) for a, n in csrs.items()]
    def __repr__(self): return '\n'.join(['  '.join([f'x{r+rr:02d}({(iregs[r+rr])[-2:]})={xfmt(self.xlen, self.x[r+rr])}' for r in range(0, 32, 8)]) for rr in range(8)])
    def mtrap(self, tval, cause): self.csr[self.mtval], self.csr[self.mepc], self.csr[self.mcause], self.pc = zext(self.xlen,tval), self.op.addr, cause, zext(self.xlen,self.csr[self.mtvec]&(~3)); self.trace_log.append(f'mtrap cause={cause} tval={hex(tval)}')
    def read_bin(self, file, base=0): [self.store(i+base, b, 'B') for i, b in enumerate(open(file, 'rb').read())]
    def page_pa_(self, addr):
        pb, pa = addr&~(self.mem_psize-1), addr&(self.mem_psize-1)
        if pb not in self.mem_pages: self.mem_pages[pb] = bytearray(self.mem_psize)
        return self.mem_pages[pb], pa
    def store(self, addr, data, fmt=None):
        page, pa, fmt = (*self.page_pa_(addr), fmt or self.fmt_conv[self.xlen])
        page[pa:pa+self.fmt_conv[fmt]//8] = struct.pack(fmt, data)
        self.trace_log.append(f'{xfmt(self.fmt_conv[fmt], data)}->mem[{xfmt(self.xlen, addr)}]')
    def load(self, addr, fmt=None):
        page, pa, fmt = (*self.page_pa_(addr), fmt or self.fmt_conv[self.xlen])
        data = struct.unpack(fmt, page[pa:pa+self.fmt_conv[fmt]//8])[0]
        self.trace_log.append(f'mem[{xfmt(self.xlen, addr)}]->{xfmt(self.fmt_conv[fmt], data)}')
        return data
    def checked_store(self, addr, rs2, fmt, mask, alignmask):
        if addr&alignmask != 0 and self.misaligned_exceptions: self.mtrap(addr, 6)
        else: self.store(zext(self.xlen,addr), self.x[rs2]&mask, fmt)
    def checked_load (self, rd, addr, fmt, alignmask):
        if addr&alignmask != 0 and self.misaligned_exceptions: self.mtrap(addr, 4)
        else: self.x[rd] = self.load(zext(self.xlen,addr), fmt)
    def idiv2zero(self, a, b): return -(-a // b) if (a < 0) ^ (b < 0) else a // b
    def rem2zero(self, a, b): return a - b * self.idiv2zero(a, b)
    def _auipc   (self, rd, imm20,        **_): self.pc+=4; self.x[rd] = sext(self.xlen, self.op.addr+imm20)
    def _lui     (self, rd, imm20,        **_): self.pc+=4; self.x[rd] = imm20
    def _jal     (self, rd, jimm20,       **_): self.pc, self.x[rd] = zext(self.xlen, self.op.addr+jimm20),    self.op.addr+4
    def _jalr    (self, rd, rs1, imm12,   **_): self.pc, self.x[rd] = zext(self.xlen, self.x[rs1]+imm12)&(~1), self.op.addr+4 # LSB=0
    def _beq     (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] == self.x[rs2] else self.op.addr+4
    def _bne     (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] != self.x[rs2] else self.op.addr+4
    def _blt     (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] <  self.x[rs2] else self.op.addr+4
    def _bge     (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if self.x[rs1] >= self.x[rs2] else self.op.addr+4
    def _bltu    (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if zext(self.xlen, self.x[rs1]) <  zext(self.xlen, self.x[rs2]) else self.op.addr+4
    def _bgeu    (self, rs1, rs2, bimm12, **_): self.pc = (self.op.addr+bimm12) if zext(self.xlen, self.x[rs1]) >= zext(self.xlen, self.x[rs2]) else self.op.addr+4
    def _sb      (self, rs1, rs2, imm12,  **_): self.pc+=4; self.store(    zext(self.xlen, self.x[rs1]+imm12), self.x[rs2]&((1<<8)-1), 'B')
    def _sh      (self, rs1, rs2, imm12,  **_): self.pc+=4; self.checked_store(zext(self.xlen, self.x[rs1]+imm12), rs2, 'H', (1<<16)-1, 1)
    def _sw      (self, rs1, rs2, imm12,  **_): self.pc+=4; self.checked_store(zext(self.xlen, self.x[rs1]+imm12), rs2, 'I', (1<<32)-1, 3)
    def _sd      (self, rs1, rs2, imm12,  **_): self.pc+=4; self.checked_store(zext(self.xlen, self.x[rs1]+imm12), rs2, 'Q', (1<<64)-1, 7)
    def _lb      (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = self.load(zext(self.xlen, self.x[rs1]+imm12), 'b')
    def _lbu     (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = self.load(zext(self.xlen, self.x[rs1]+imm12), 'B')
    def _lh      (self, rd, rs1, imm12,   **_): self.pc+=4; self.checked_load(rd, self.x[rs1]+imm12, 'h', 1)
    def _lw      (self, rd, rs1, imm12,   **_): self.pc+=4; self.checked_load(rd, self.x[rs1]+imm12, 'i', 3)
    def _ld      (self, rd, rs1, imm12,   **_): self.pc+=4; self.checked_load(rd, self.x[rs1]+imm12, 'q', 7)
    def _lhu     (self, rd, rs1, imm12,   **_): self.pc+=4; self.checked_load(rd, self.x[rs1]+imm12, 'H', 1)
    def _lwu     (self, rd, rs1, imm12,   **_): self.pc+=4; self.checked_load(rd, self.x[rs1]+imm12, 'I', 3)
    def _addi    (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  +          imm12)
    def _xori    (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  ^          imm12)
    def _ori     (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  |          imm12)
    def _andi    (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  &          imm12)
    def _addiw   (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = sext(32,          self.x[rs1]  +          imm12)
    def _addw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, sext(32, self.x[rs1]) + sext(32, self.x[rs2]))
    def _subw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, sext(32, self.x[rs1]) - sext(32, self.x[rs2]))
    def _add     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  +          self.x[rs2])
    def _sub     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  -          self.x[rs2])
    def _xor     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  ^          self.x[rs2])
    def _or      (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  |          self.x[rs2])
    def _and     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,   self.x[rs1]  &          self.x[rs2])
    def _sltiu   (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] = zext(self.xlen,   self.x[rs1]) < zext(self.xlen, imm12)
    def _sltu    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = zext(self.xlen,   self.x[rs1]) < zext(self.xlen, self.x[rs2])
    def _slti    (self, rd, rs1, imm12,   **_): self.pc+=4; self.x[rd] =                   self.x[rs1]  <                 imm12
    def _slt     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] =                   self.x[rs1]  <                 self.x[rs2]
    def _slliw   (self, rd, rs1, shamtw,  **_): self.pc+=4; self.x[rd] = sext(32,                        self.x[rs1]  << shamtw)
    def _srliw   (self, rd, rs1, shamtw,  **_): self.pc+=4; self.x[rd] = sext(32,        zext(32,        self.x[rs1]) >> shamtw)
    def _sraiw   (self, rd, rs1, shamtw,  **_): self.pc+=4; self.x[rd] = sext(32,        sext(32,        self.x[rs1]) >> shamtw)
    def _slli    (self, rd, rs1, shamtd,  **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  << shamtd)  # shared with RV64I
    def _srai    (self, rd, rs1, shamtd,  **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  >> shamtd)  # shared with RV64I
    def _srli    (self, rd, rs1, shamtd,  **_): self.pc+=4; self.x[rd] = sext(self.xlen, zext(self.xlen, self.x[rs1]) >> shamtd)  # shared with RV64I
    def _sll     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  << (self.x[rs2]&(self.xlen-1)))
    def _srl     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, zext(self.xlen, self.x[rs1]) >> (self.x[rs2]&(self.xlen-1)))
    def _sra     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen,                 self.x[rs1]  >> (self.x[rs2]&(self.xlen-1)))
    def _sllw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32,        sext(32,        self.x[rs1]) << (self.x[rs2]&31))
    def _srlw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32,        zext(32,        self.x[rs1]) >> (self.x[rs2]&31))
    def _sraw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32,        sext(32,        self.x[rs1]) >> (self.x[rs2]&31))
    def _fence   (self,                   **_): self.pc+=4
    def _fence_i (self,                   **_): self.pc+=4
    def _csrrw   (self, rd, csr, rs1,     **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], self.x[rs1]                  if (csr&0xc00)!=0xc00 else self.csr[csr]
    def _csrrs   (self, rd, csr, rs1,     **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], (self.csr[csr]| self.x[rs1]) if (csr&0xc00)!=0xc00 else self.csr[csr]
    def _csrrc   (self, rd, csr, rs1,     **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], (self.csr[csr]&~self.x[rs1]) if (csr&0xc00)!=0xc00 else self.csr[csr]
    def _csrrwi  (self, rd, csr, zimm,    **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], zimm                         if (csr&0xc00)!=0xc00 else self.csr[csr]
    def _csrrsi  (self, rd, csr, zimm,    **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], (self.csr[csr]| zimm)        if (csr&0xc00)!=0xc00 else self.csr[csr]
    def _csrrci  (self, rd, csr, zimm,    **_): self.pc+=4; self.x[rd], self.csr[csr] = self.csr[csr], (self.csr[csr]&~zimm)        if (csr&0xc00)!=0xc00 else self.csr[csr]
    def _mret    (self,                   **_): self.pc = zext(self.xlen, self.csr[self.mepc])
    def _ecall   (self,                   **_): self.pc = zext(self.xlen, self.csr[self.mtvec]&(~3)); self.csr[self.mepc] = self.op.addr; self.csr[self.mcause] = 11
    def _ebreak  (self,                   **_): self.pc = zext(self.xlen, self.csr[self.mtvec]&(~3)); self.csr[self.mepc] = self.op.addr; self.csr[self.mcause] = 3; self.csr[self.mtval] = self.op.addr
    def _mul     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (                self.x[rs1]  *                 self.x[rs2] )           )
    def _mulh    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (                self.x[rs1]  *                 self.x[rs2] )>>self.xlen)
    def _mulhu   (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (zext(self.xlen, self.x[rs1]) * zext(self.xlen, self.x[rs2]))>>self.xlen)
    def _mulhsu  (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (                self.x[rs1]  * zext(self.xlen, self.x[rs2]))>>self.xlen)
    def _div     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (self.idiv2zero( self.x[rs1]  ,                 self.x[rs2]))           ) if self.x[rs2] != 0 else -1
    def _divu    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (zext(self.xlen, self.x[rs1]) //zext(self.xlen, self.x[rs2]))           ) if self.x[rs2] != 0 else -1
    def _rem     (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (self.rem2zero ( self.x[rs1]  ,                 self.x[rs2]))           ) if self.x[rs2] != 0 else self.x[rs1]
    def _remu    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(self.xlen, (zext(self.xlen, self.x[rs1]) % zext(self.xlen, self.x[rs2]))           ) if self.x[rs2] != 0 else self.x[rs1]
    def _mulw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32,        (sext(32,        self.x[rs1]) * sext(32,        self.x[rs2]))           )
    def _divw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, (self.idiv2zero(sext(32,self.x[rs1]) , sext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else -1
    def _divuw   (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, (self.idiv2zero(zext(32,self.x[rs1]) , zext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else -1
    def _remw    (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, (self.rem2zero (sext(32,self.x[rs1]) , sext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else sext(32,self.x[rs1])
    def _remuw   (self, rd, rs1, rs2,     **_): self.pc+=4; self.x[rd] = sext(32, (self.rem2zero (zext(32,self.x[rs1]) , zext(32,        self.x[rs2])))          ) if sext(32,self.x[rs2]) != 0 else sext(32,self.x[rs1])
    def _amoadd_w(self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; self.checked_load(rd, self.x[rs1], 'i', 3); self.checked_store(zext(self.xlen, ors1), sext(self.xlen, self.x[rd] + ors2), 'i', (1<<32)-1, 3)
    def _amoand_w(self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; self.checked_load(rd, self.x[rs1], 'i', 3); self.checked_store(zext(self.xlen, ors1), sext(self.xlen, self.x[rd] & ors2), 'i', (1<<32)-1, 3)
    def _amoor_w (self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; self.checked_load(rd, self.x[rs1], 'i', 3); self.checked_store(zext(self.xlen, ors1), sext(self.xlen, self.x[rd] | ors2), 'i', (1<<32)-1, 3)
    def _amoxor_w(self, rd, rs1, rs2,     **_): self.pc+=4; ors1, ors2 = self.x[rs1], self.x[rs2]; self.checked_load(rd, self.x[rs1], 'i', 3); self.checked_store(zext(self.xlen, ors1), sext(self.xlen, self.x[rd] ^ ors2), 'i', (1<<32)-1, 3)
    def _c_addi  (self, rd_rs1, nzimm6,   **_): self.pc+=2; self.x[rd_rs1] += nzimm6  # c.nop required to pass test rv32i_m/privilege/src/misalign-jal-01.S
    def step(self, trace=True):
        self.op = next(rvdecoder(self.load(self.pc, 'I'), base=self.pc)); self.trace_log.clear()
        if hasattr(self, '_'+self.op.name): getattr(self, '_'+self.op.name)(**self.op.args)  # instruction dispatch 
        else: print(f'\n{zext(64,self.op.addr):08x}: unknown opcode: {zext(32,self.op.data):08x}')
        if trace: print(f'{zext(64,self.op.addr):08x}: {str(self.op):40} #', ' '.join(self.trace_log))
        if trace and self.pc-self.op.addr not in (2, 4): print()
    def run(self, limit=0, bpts=set(), trace=True):
        while True:
            self.step(trace=trace)
            if self.op.addr in bpts|{self.pc} or (limit := limit-1)==0: break