# tinyRV

A RISC-V instruction decoder and instruction set simulator in less than 200 lines of python.

**Mission**: Make the most useful RISC-V disassembler/simulator for understanding the ISA and reverse-engineering binaries with the least amount of easily extendable code. Simulation performance is secondary.

- Uses official RISC-V specs to decode *every* specified RISC-V instruction.
- Simulates the base ISAs and is easily extendable.
- RV32IMAZicsr_Zifencei and RV64IMAZicsr_Zifencei compliance validated using RISCOF (see Testing below).
- Boots Linux! Big thanks to CNLohr for [mini-rv32ima](https://github.com/cnlohr/mini-rv32ima).

## Getting Started

```sh
pip install tinyrv
```

Print all RISC-V instructions in a binary:
```
tinyrv-dump firmware.bin
```
Outputs for `firmware.bin` from [picorv32](https://github.com/YosysHQ/picorv32/tree/main):
```
00000000: custom0                                  # INVALID data=0x800400b
00000004: custom0                                  # INVALID data=0x600600b
00000008: jal        zero, 0x3e0                   # rv_i
0000000c: addi       zero, zero, 0                 # rv_i
00000010: custom0                                  # INVALID data=0x200a10b
00000014: custom0                                  # INVALID data=0x201218b
00000018: lui        ra, 0                         # rv_i
0000001c: addi       ra, ra, 0x160                 # rv_i
00000020: custom0                                  # INVALID data=0x410b
00000024: sw         sp, 0(ra)                     # rv_i
00000028: custom0                                  # INVALID data=0x1410b
0000002c: sw         sp, 4(ra)                     # rv_i
00000030: custom0                                  # INVALID data=0x1c10b
00000034: sw         sp, 8(ra)                     # rv_i
00000038: sw         gp, 12(ra)                    # rv_i
0000003c: sw         tp, 16(ra)                    # rv_i
...
```
picorv32 uses some custom instructions for IRQ handling.

Decode instructions from data:
```
tinyrv-dump 0xf2410113 0xde0ec086 0x2013b7
```
or in python:
```py
import tinyrv
for op in tinyrv.decoder(0xf2410113, 0xde0ec086, 0x2013b7):
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
op = tinyrv.decode(0xf2410113)
print(hex(op.data), op.name, op.extension, op.variable_fields, bin(op.mask), bin(op.match), op.valid())
print(op.args, op.rd, op.rs1, op.imm12)
print(op.arg_str())
```
```
0xf2410113 addi ['rv_i'] ['rd', 'rs1', 'imm12'] 0b111000001111111 0b10011 True
{'rd': 2, 'rs1': 2, 'imm12': -220} 2 2 -220
sp, sp, -220
```
Simulate a binary:
```py
rv = tinyrv.sim(xlen=32)  # xlen affects overflows, sign extensions
rv.read_bin('firmware.bin', base=0)
print(rv.x)  # print registers
print()
rv.step()  # simulate a single instruction at rv.pc
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


00000000: unimplemented: 0800400b custom0    
00000000: custom0                                  #
```
Simulation halts at the first instruction that is not implemented. Just set the pc and carry on:
```py
rv.pc = 8
rv.run(50)
```
```
00000008: jal        zero, 0x3e0                   # 

000003e0: addi       ra, zero, 0                   # 
000003e4: addi       sp, zero, 0                   # 
(... boring initialization stuff skipped ...)
00000454: addi       t5, zero, 0                   # 
00000458: addi       t6, zero, 0                   # 
0000045c: lui        sp, 0x20000                   # sp=00020000
00000460: jal        ra, 0xbdc                     # ra=00000464

00000bdc: lui        a0, 0xc000                    # a0=0000c000
00000be0: addi       a0, a0, 0x79c                 # a0=0000c79c
00000be4: jal        zero, 0xb08                   # 

00000b08: lui        a4, 0x10000000                # a4=10000000
00000b0c: lbu        a5, 0(a0)                     # mem[0000c79c]->68 a5=00000068
00000b10: bne        a5, zero, 0xb18               # 

00000b18: addi       a0, a0, 1                     # a0=0000c79d
00000b1c: sw         a5, 0(a4)                     # 00000068->mem[10000000]
00000b20: jal        zero, 0xb0c                   # 

00000b0c: lbu        a5, 0(a0)                     # mem[0000c79d]->65 a5=00000065
00000b10: bne        a5, zero, 0xb18               # 

00000b18: addi       a0, a0, 1                     # a0=0000c79e
00000b1c: sw         a5, 0(a4)                     # 00000065->mem[10000000]
00000b20: jal        zero, 0xb0c                   # 

00000b0c: lbu        a5, 0(a0)                     # mem[0000c79e]->6c a5=0000006c
00000b10: bne        a5, zero, 0xb18               # 
```
Each jump, taken branch produces a newline, right-hand side has register changes and memory transactions. Memory is paged, allocated on demand and persists. Now let's get past this loop by setting a breakpoint:
```py
rv.run(1000, bpts={0xb14})
rv.run(10)
```
```
...
00000b1c: sw         a5, 0(a4)                     # 00000064->mem[10000000]
00000b20: jal        zero, 0xb0c                   # 

00000b0c: lbu        a5, 0(a0)                     # mem[0000c7a7]->0a a5=0000000a
00000b10: bne        a5, zero, 0xb18               # 

00000b18: addi       a0, a0, 1                     # a0=0000c7a8
00000b1c: sw         a5, 0(a4)                     # 0000000a->mem[10000000]
00000b20: jal        zero, 0xb0c                   # 

00000b0c: lbu        a5, 0(a0)                     # mem[0000c7a8]->00 a5=00000000
00000b10: bne        a5, zero, 0xb18               # 
00000b14: jalr       zero, 0(ra)                   # 

00000464: addi       ra, zero, 0x3e8               # ra=000003e8

00000468: unimplemented: 0a00e00b custom0    
00000468: custom0                                  # 
```
Simulate from command line:
```
# usage: tinyrv-sim file.bin [(32|64) [run limit in decimal [start PC in hex]]]

tinyrv-sim firmware.bin 32 100 8
```


## Dev Setup

All core simulator code is in `tinyrv/tinyrv.py` and has no external dependencies.
tinyRV loads opcode specs from `tinyrv/opcodes.py`, which is auto-generated from [riscv-opcodes](https://github.com/riscv/riscv-opcodes) by `tinyrv_opcodes_gen.py`.

Do this to re-generate:
```bash
git clone https://github.com/riscv/riscv-opcodes.git
make -C riscv-opcodes
python3 tinyrv_opcodes_gen.py
```

Some VMs use external libraries:
- [lief](https://pypi.org/project/lief/) for loading ELFs
- [readchar](https://pypi.org/project/readchar/) for reading keystrokes
- [dataclasses-struct](https://pypi.org/project/dataclasses-struct/) for easier binary data manipulation

## Testing

Install [riscv-gnu-toolchain](https://github.com/riscv/riscv-gnu-toolchain) or [homebrew-riscv](https://github.com/riscv-software-src/homebrew-riscv) (for MacOS).

### RISCOF

Install [the RISC-V compatibility framework RISCOF](https://github.com/riscv-software-src/riscof):
```sh
pip3 install setuptools wheel
git clone https://github.com/riscv/riscof.git
cd riscof
pip3 install -e .
```

Install the [Sail ISA specification language](https://github.com/rems-project/sail):
```sh
brew install opam zlib z3 pkg-config
opam init
opam switch create ocaml-base-compiler
opam install sail
eval $(opam config env)
```

Install the [RISCV Sail Model](https://github.com/riscv/sail-riscv):
```sh
git clone https://github.com/riscv/sail-riscv.git
cd sail-riscv
ARCH=RV32 make c_emulator/riscv_sim_RV32
ARCH=RV64 make c_emulator/riscv_sim_RV64
# copy / link c_emulator/riscv_sim_RV{32,64} into $PATH location
```

Optionally, install [Spike RISC-V ISA Simulator](https://github.com/riscv-software-src/riscv-isa-sim):
```sh
git clone https://github.com/riscv-software-src/riscv-isa-sim.git
cd riscv-isa-sim
mkdir build
cd build
../configure --prefix=/path/to/install  # /path/to/install/bin must be in $PATH
make
make install
spike  # test
```
Then, run the tests:
```sh
make -C tests run_riscof
```


### riscv-software-src/riscv-tests

```sh
make -C tests run_riscv_tests
```
This will automatically clone and build the test suite if necessary.

### Run Coremark

```sh
make -C tests run_coremark
```
This will automatically clone and build coremark if necessary.

### Boot Linux

```bash
make -C tests run_linux
```
Will download an Image and boot it.
Boottime is about a minute on a reasonable fast machine and recent Python.

The Image was made using [buildroot](https://buildroot.org).
The configuration is based on qemu_riscv64_nommu_virt_defconfig with FPU, compressed instructions and other extensions turned off.

To (re-)create this Image, run:
```bash
make -C tests Image
```
This will download buildroot and build the kernel (takes some time).
The build configuration is in tests/br2_external_tinyrv.

## Related

- [TinyFive](https://github.com/OpenMachine-ai/tinyfive)
- [mini-rv32ima](https://github.com/cnlohr/mini-rv32ima)