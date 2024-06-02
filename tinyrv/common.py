import functools
from .opcodes import csrs, mask_match_rv32, mask_match_rv64

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

@functools.lru_cache(maxsize=4096)
def decode(instr, addr=0, xlen=64):  # decodes one instruction
    o = rvop(addr=addr, data=instr, name=customs.get(instr&0b1111111,'UNKNOWN'), args={})
    for mask, m_dict in mask_match_rv64 if xlen==64 else mask_match_rv32:
        if op := m_dict.get(instr&mask, None):
            o.args = dict((vf, getter(instr)) for vf, getter in op['arg_getter'].items())
            [setattr(o,k,v) for k,v in (op|o.args).items()]
            break
    return o