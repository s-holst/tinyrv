# tinyRV

A RISC-V instruction decoder and emulator in less than 200 lines of pure python3.

- Uses official RISC-V specs to decode *every* specified RISC-V instruction.
- Emulates at least the base ISAs RV32I/RV64I and is easily extendable.

## Getting Started

```sh
pip install tinyrv
```

Print all RISC-V instructions in a binary:
```py
from tinyrv import rvprint
rvprint('firmware.bin', xlen=32)  # xlen just for output formatting
```
Outputs for `firmware.bin` from [picorv32](https://github.com/YosysHQ/picorv32/tree/main):
```
00000000: custom-0   raw=0x0800400b                # INVALID
00000004: custom-0   raw=0x0600600b                # INVALID
00000008: jal        zero, .+984                   # rv_i
0000000c: addi       zero, zero, 0                 # rv_i
00000010: custom-0   raw=0x0200a10b                # INVALID
00000014: custom-0   raw=0x0201218b                # INVALID
00000018: lui        ra, 0x0                       # rv_i
0000001c: addi       ra, ra, 352                   # rv_i
00000020: custom-0   raw=0x0000410b                # INVALID
00000024: sw         sp, 0(ra)                     # rv_i
00000028: custom-0   raw=0x0001410b                # INVALID
0000002c: sw         sp, 4(ra)                     # rv_i
00000030: custom-0   raw=0x0001c10b                # INVALID
00000034: sw         sp, 8(ra)                     # rv_i
00000038: sw         gp, 12(ra)                    # rv_i
0000003c: sw         tp, 16(ra)                    # rv_i
...
```
picorv32 uses some custom instructions for IRQ handling.

Decode instructions from data:
```py
from tinyrv import rvdecoder
for op in rvdecoder(0xf2410113, 0xde0ec086, 0x2013b7):
    print(op)
```
Outputs four instructions (the second word contains actually two 16-bit compressed instructions):
```
addi       sp, sp, -220
c.swsp     ra, uimm8sp_s=64
c.swsp     gp, uimm8sp_s=60
lui        t2, 0x201000
```
Each decoded instruction comes with a lot of metadata and parsed arguments:
```py
op = next(rvdecoder(0xf2410113))
print(hex(op.data), op.name, op.extension, op.encoding, op.variable_fields, op.valid())
print(op.args, op.rd, op.rs1, op.imm12)
print(op.arg_str())
```
```
0xf2410113 addi ['rv_i'] -----------------000-----0010011 ['rd', 'rs1', 'imm12'] True
{'rd': 2, 'rs1': 2, 'imm12': -220} 2 2 -220
sp, sp, -220
```
Simulate a binary:
```py
from tinyrv import rvmem, rvsim
mem = rvmem(xlen=32)  # xlen just for output formatting
mem.load('firmware.bin', base=0)
rv = rvsim(mem, xlen=32)  # xlen affects overflows, sign extensions
print(rv)  # print registers
print()
rv.step(10)  # simulate up to 10 instructions
```
Outputs:
```
x00(ro)=00000000  x08(fp)=00000000  x16(a6)=00000000  x24(s8)=00000000
x01(ra)=00000000  x09(s1)=00000000  x17(a7)=00000000  x25(s9)=00000000
x02(sp)=00000000  x10(a0)=00000000  x18(s2)=00000000  x26(10)=00000000
x03(gp)=00000000  x11(a1)=00000000  x19(s3)=00000000  x27(11)=00000000
x04(tp)=00000000  x12(a2)=00000000  x20(s4)=00000000  x28(t3)=00000000
x05(t0)=00000000  x13(a3)=00000000  x21(s5)=00000000  x29(t4)=00000000
x06(t1)=00000000  x14(a4)=00000000  x22(s6)=00000000  x30(t5)=00000000
x07(t2)=00000000  x15(a5)=00000000  x23(s7)=00000000  x31(t6)=00000000

00000000: custom-0   raw=0x0800400b                # UNKNOWN  # halted: unimplemented op
```
Simulation steps at the first instruction that is not implemented. Just set the pc and carry on:
```py
rv.pc = 8
rv.step(50)
```
```
00000008: jal        zero, .+984                   #  

000003e0: addi       ra, zero, 0                   # ra = 00000000 
000003e4: addi       sp, zero, 0                   # sp = 00000000 
(... boring initialization stuff skipped ...)
00000454: addi       t5, zero, 0                   # t5 = 00000000 
00000458: addi       t6, zero, 0                   # t6 = 00000000 
0000045c: lui        sp, 0x20000                   # sp = 00020000 
00000460: jal        ra, .+1916                    # ra = 00000464 

00000bdc: lui        a0, 0xc000                    # a0 = 0000c000 
00000be0: addi       a0, a0, 1948                  # a0 = 0000c79c 
00000be4: jal        zero, .-220                   #  

00000b08: lui        a4, 0x10000000                # a4 = 10000000 
00000b0c: lbu        a5, 0(a0)                     # a5 = 00000068 mem[0000c79c] -> 68
00000b10: bne        a5, zero, .+8                 #  

00000b18: addi       a0, a0, 1                     # a0 = 0000c79d 
00000b1c: sw         a5, 0(a4)                     #  mem[10000000] <- 00000068
00000b20: jal        zero, .-20                    #  

00000b0c: lbu        a5, 0(a0)                     # a5 = 00000065 mem[0000c79d] -> 65
00000b10: bne        a5, zero, .+8                 #
```
Each jump, taken branch produces a newline, right-hand side has register changes and memory transactions. `rvmem` is paged. Memory is allocated on demand and persists. Now let's get past this loop by setting a breakpoint:
```py
rv.step(1000, bpts={0xb14})
rv.step(10)
```
```
...
00000b0c: lbu        a5, 0(a0)                     # a5 = 0000000a mem[0000c7a7] -> 0a
00000b10: bne        a5, zero, .+8                 #  

00000b18: addi       a0, a0, 1                     # a0 = 0000c7a8 
00000b1c: sw         a5, 0(a4)                     #  mem[10000000] <- 0000000a
00000b20: jal        zero, .-20                    #  

00000b0c: lbu        a5, 0(a0)                     # a5 = 00000000 mem[0000c7a8] -> 00
00000b10: bne        a5, zero, .+8                 #  
00000b14: jalr       zero, 0(ra)                   #  
00000464: addi       ra, zero, 1000                # ra = 000003e8 
00000468: custom-0   raw=0x0a00e00b                # UNKNOWN  # halted: unimplemented op
```

## Dev Setup

All code is in `tinyrv.py`.
No dependencies, except [pyyaml](https://pypi.org/project/PyYAML/).
However, tinyRV needs to load opcode specs from [riscv-opcodes](https://github.com/riscv/riscv-opcodes).
Do this:
```sh
git clone https://github.com/riscv/riscv-opcodes.git
cd riscv-opcodes; make
```
The necessary opcode specs are also bundled in the PyPI package. If there is a `riscv-opcodes` in the current directory, tinyRV will try to use those instead of the packaged ones.

## Related

- [TinyFive](https://github.com/OpenMachine-ai/tinyfive)
- [mini-rv32ima](https://github.com/cnlohr/mini-rv32ima)