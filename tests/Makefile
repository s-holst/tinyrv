test: test_mini32 test_mini64 run_riscv_tests run_riscof

############# riscv-software-src/riscv-tests

run_riscv_tests: riscv-tests-compiled
	for i in riscv-tests/isa/rv??ui-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-vm-linux $$i || exit $$?; fi; done
	for i in riscv-tests/isa/rv??ua-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-vm-linux $$i || exit $$?; fi; done
	for i in riscv-tests/isa/rv??um-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-vm-linux $$i || exit $$?; fi; done

riscv-tests-compiled: riscv-tests/isa/rv32ui-p-add

riscv-tests/isa/rv32ui-p-add: riscv-tests/Makefile
	make -C riscv-tests

riscv-tests/Makefile: riscv-tests
	cd riscv-tests && autoupdate && autoconf && ./configure

riscv-tests:
	git clone https://github.com/riscv-software-src/riscv-tests.git
	cd riscv-tests && git submodule update --init --recursive

############# riscof

run_riscof: riscv-arch-test
	riscof run --config=riscof_config32.ini --suite=riscv-arch-test/riscv-test-suite  --env=riscv-arch-test/riscv-test-suite/env
	riscof run --config=riscof_config64.ini --suite=riscv-arch-test/riscv-test-suite  --env=riscv-arch-test/riscv-test-suite/env

riscv-arch-test:
	git clone https://github.com/riscv-non-isa/riscv-arch-test.git

############# mini

test_mini32: mini32
	test "$(shell tinyrv-vm-linux mini32 foo 0x01 42)" = "hello mini32 foo 0x01 42"

test_mini64: mini64
	test "$(shell tinyrv-vm-linux mini64 foo 0x01 42)" = "hello mini64 foo 0x01 42"

mini64: mini.c
	riscv64-unknown-elf-gcc -O2 -mcmodel=medany -march=rv64ima -mabi=lp64 -static $^ -o $@

mini32: mini.c
	riscv64-unknown-elf-gcc -O2 -mcmodel=medany -march=rv32ima -mabi=ilp32 -static $^ -o $@

%.bin: %
	riscv64-unknown-elf-objcopy -O binary $< $@

%.disass: %
	riscv64-unknown-elf-objdump -d $< >$@

clean:
	-rm mini32* mini64*

proxy:
	riscv64-unknown-elf-gcc -mcmodel=medany -march=rv32g -mabi=ilp32 -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf -fno-tree-loop-distribute-patterns -Ienv -I. -c env/crt32.S env/proxy.c mini.c
	riscv64-unknown-elf-gcc -mcmodel=medany -march=rv32g -mabi=ilp32 -static -nostdlib -nostartfiles -lm -lgcc -T env/test.ld crt32.o proxy.o mini.o -o mini.elf
	riscv64-unknown-elf-objcopy -O binary mini.elf mini.bin

