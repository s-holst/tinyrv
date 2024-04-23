# tinyRV

A RISC-V instruction decoder and emulator in less than 200 lines of pure python3.

- Uses official RISC-V specs to decode *every specified* RISC-V instruction.
- Emulates at least the base ISAs RV32I/RV64I and is easily extendable.


## Setup

All code is in `tinyrv.py`.
However, it needs to load opcode specs from [riscv-opcodes](https://github.com/riscv/riscv-opcodes).
Do this:
```sh
git clone https://github.com/riscv/riscv-opcodes.git
cd riscv-opcodes; make
```

## Usage

Print all RISC-V instructions in a binary (here: `firmware.bin` from [picorv32](https://github.com/YosysHQ/picorv32/tree/main)):
```py
from tinyrv import rvprint
rvprint('firmware.bin', xlen=32)
```
Outputs:
```
00000000 custom-0   raw=0x0800400b                        # INVALID
00000004 custom-0   raw=0x0600600b                        # INVALID
00000008 jal        zero, .+984                           # rv_i
0000000c addi       zero, zero, 0                         # rv_i
00000010 custom-0   raw=0x0200a10b                        # INVALID
00000014 custom-0   raw=0x0201218b                        # INVALID
00000018 lui        ra, 0x0                               # rv_i
0000001c addi       ra, ra, 352                           # rv_i
00000020 custom-0   raw=0x0000410b                        # INVALID
00000024 sw         sp, 0(ra)                             # rv_i
00000028 custom-0   raw=0x0001410b                        # INVALID
0000002c sw         sp, 4(ra)                             # rv_i
00000030 custom-0   raw=0x0001c10b                        # INVALID
00000034 sw         sp, 8(ra)                             # rv_i
00000038 sw         gp, 12(ra)                            # rv_i
0000003c sw         tp, 16(ra)                            # rv_i
00000040 sw         t0, 20(ra)                            # rv_i
00000044 sw         t1, 24(ra)                            # rv_i
...
```
picorv32 uses some custom instructions for IRQ handling.