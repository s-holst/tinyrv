#!/usr/bin/env python3
import re, csv, yaml, pathlib

base = pathlib.Path('riscv-opcodes')

try:    
    def dr(h,l): return list(range(h,l-1,-1))    
    arg_bits = dict((a, dr(int(h),int(l))) for a, h, l in csv.reader(open(base / 'arg_lut.csv'), skipinitialspace=True))
    for s in open(base / 'constants.py').readlines():  # immediate scrambling from latex_mapping. Some better way?
        if m := re.match(r"latex_mapping\[['\"](.*?)['\"]\] = ['\"][^\[]*\[([^\]]*)\]['\"]", s):
            fbits = sum([(dr(*(int(i) for i in part.split(':'))) if ':' in part else [int(part)]) for part in m[2].split('$\\\\vert$')], [])
            locs = [-1] * (max(fbits)+1)
            for i, b in enumerate(fbits): locs[-b-1] = arg_bits[m[1]][i]
            arg_bits[m[1]] = [31] * (32-len(locs)) + locs if locs[0] == 31 else locs  # sign extension to 32 bits
            
    opcodes = yaml.safe_load(open(base / 'instr_dict.yaml'))
    
    for aname, op in opcodes.items():
        op['name'] = aname
        del op['encoding']
        op['mask'] = int(op['mask'], 16)
        op['match'] = int(op['match'], 16)
        
        op['arg_bits'] = {}
        for vf in op['variable_fields']:
            if vf not in arg_bits: continue
            bits = [-1] * (32-len(arg_bits[vf])) + arg_bits[vf]
            vf2 = vf.replace('hi','').replace('lo','').replace('c_','')
            if vf2 in op['arg_bits']:
                op['arg_bits'][vf2] = [max(a,b) for a, b in zip(op['arg_bits'][vf2], bits)]
            else:
                op['arg_bits'][vf2] = bits
        for vf in op['arg_bits']:
            while (len(op['arg_bits'][vf]) > 1) and ((op['arg_bits'][vf][0] == -1) or (op['arg_bits'][vf][0] == 31) and op['arg_bits'][vf][1] == 31):
                op['arg_bits'][vf] = op['arg_bits'][vf][1:]
        
    csrs = dict((int(a, 16), n) for fn in ['csrs.csv', 'csrs32.csv'] for a, n in csv.reader(open(base / fn), skipinitialspace=True))
except Exception as e: raise Exception("Unable to load RISC-V specs. Do:\n"
                                       "git clone https://github.com/riscv/riscv-opcodes.git\n"
                                       "make -C riscv-opcodes")

commonops = ('addi,sw,lw,jal,bne,beq,add,jalr,lbu,slli,lui,andi,or,bltu,srli,and,sub,blt,bgeu,xor,sb,auipc,sltiu,bge,lb,mul,sltu,lhu,sll,srl,sh,amoadd_w,xori,ori,csrrci,csrrs,srai,fence,lr_w,sc_w,mulhu,amoor_w,lh,amoand_w,csrrsi,divu,div,remu,sra,slt,csrrw,amoswap_w,csrrc,mulh,fence_i,rem,mret,csrrwi').split(',')

masks = []
for op in commonops:  # priority
    if len(op) < 1: continue
    mask = opcodes[op]['mask']
    if mask not in masks:
        masks.append(mask)
for mask in list(set([o['mask'] for o in opcodes.values()])):  # other masks
    if mask not in masks:
        masks.append(mask)
        
mm_dicts = []
for m in masks:
    ops = {}
    for op in opcodes.values():
        name = op['name']
        if name.endswith('_rv32'): continue
        op_m = op['mask']
        if m == op_m:
            match = op['match']
            if match in ops:
                pass #print(f'already in ops: {ops[match]} (trying to add {name})')
            else:
                ops[match] = f'${name}$'
    mm_dicts.append((m, ops))

with open('tinyrv/opcodes.py', 'w') as f:
    f.write(f'# auto-generated by tinyrv_opcodes_gen.py\n')
    f.write(f'opcodes={str(opcodes)}\n')
    f.write(f'arg_bits={str(arg_bits)}\n')
    f.write(f'csrs={str(csrs)}\n')
    dstr = str(mm_dicts).replace("'$", "opcodes['").replace("$'", "']")
    f.write(f'mm_dicts={dstr}\n')