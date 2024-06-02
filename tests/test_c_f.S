# Tests compressed float instructions not covered by riscv test suites

# assemble with:
#  riscv64-unknown-elf-gcc -nostartfiles -march=rv32gc -mabi=ilp32 test_c_f.S
#  riscv64-unknown-elf-gcc -nostartfiles -march=rv64gc -mabi=lp64 test_c_f.S

.data  # data section

.align 8
dnumber: .double 3.14
fnumber: .float 3.14
fout: .word 0
dout: .dword 0
stack:
    .dword 0
    .dword 0
    .dword 0
    .dword 0

.text  # code section

.globl _start
_start:  # entry point

    .option push
	.option norelax
	la gp, __global_pointer$
	.option pop

    la a0, dnumber
    c.fld fa0, (a0)  # compressed load double (available in rv64 and rv32)
    fld ft0, (a0)  # normal load double (ft0 is not supported in c.fld, so this one will stay uncompressed)

    li a0, 1
    feq.d a1, fa0, ft0
    beqz a1, exit

    li a1, 314  # synthesize a double from immediates
    li a2, 100
    fcvt.d.w fa1, a1
    fcvt.d.w fa2, a2
    fdiv.d fa1, fa1, fa2  # 314 / 100 = 3.14

    li a0, 2
    feq.d a1, fa0, fa1
    beqz a1, exit

    la a0, fnumber
    flw fa1, (a0)  # compressed load float (will assemble to c.flw in rv32)
    flw ft1, (a0)  # normal load float (ft1 is not supported in c.flw, so this one will stay uncompressed)

    li a0, 3
    feq.s a1, fa1, ft1
    beqz a1, exit

    li a2, 314  # synthesize a float from immediates
    li a3, 100
    fcvt.s.w fa2, a2
    fcvt.s.w fa3, a3
    fdiv.s fa2, fa2, fa3  # 314 / 100 = 3.14

    li a0, 4
    feq.s a1, fa1, fa2
    beqz a1, exit

    la a0, dout
    c.fsd fa0, (a0)  # compressed store double (available in rv64 and rv32)
    fld ft3, (a0)  # normal load double

    li a0, 5
    feq.d a1, fa0, ft3
    beqz a1, exit

    la a0, fout
    fsw fa1, (a0)  # compressed store float (will assemble to c.fsw in rv32)
    flw ft4, (a0)  # normal load float

    li a0, 6
    feq.s a1, fa1, ft4
    beqz a1, exit

    la sp, stack

    c.fsdsp fa0, 0(sp)
    fld ft5, 0(sp)

    li a0, 7
    feq.d a1, fa0, ft5
    beqz a1, exit

    c.fldsp ft6, 0(sp)

    li a0, 8
    feq.d a1, fa0, ft6
    beqz a1, exit

#if __riscv_xlen == 32

    c.fswsp fa1, 8(sp)
    flw ft7, 8(sp)

    li a0, 9
    feq.s a1, fa1, ft7
    beqz a1, exit

    c.flwsp ft8, 8(sp)

    li a0, 10
    feq.s a1, fa1, ft8
    beqz a1, exit

#endif

    li a0, 0  # success
exit:
    addi a7, zero, 93  # syscall 93 = exit(A0)
    ecall
