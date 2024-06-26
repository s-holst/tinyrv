all: test_mini32 test_mini64 test_mini32semi test_mini64semi test_c_f run_riscv_tests run_riscof run_coremark

############# riscv-software-src/riscv-tests

run_riscv_tests: riscv-tests-compiled
	for i in riscv-tests/isa/rv??ui-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-user-elf $$i || exit $$?; fi; done
	for i in riscv-tests/isa/rv??ua-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-user-elf $$i || exit $$?; fi; done
	for i in riscv-tests/isa/rv??um-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-user-elf $$i || exit $$?; fi; done
	for i in riscv-tests/isa/rv??uc-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-user-elf $$i || exit $$?; fi; done
	for i in riscv-tests/isa/rv??uf-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-user-elf $$i || exit $$?; fi; done
	for i in riscv-tests/isa/rv??ud-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-user-elf $$i || exit $$?; fi; done
	for i in riscv-tests/isa/rv??mi-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-user-elf $$i || exit $$?; fi; done
	for i in riscv-tests/isa/rv??si-p-*; do if [[ ! $$i =~ "." ]]; then echo running $$i; tinyrv-user-elf $$i || exit $$?; fi; done

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

############# compressed float instructions test

test_c_f_64: test_c_f.S
	riscv64-unknown-elf-gcc -nostartfiles -march=rv64gc -mabi=lp64 test_c_f.S -o test_c_f_64

test_c_f_32: test_c_f.S
	riscv64-unknown-elf-gcc -nostartfiles -march=rv32gc -mabi=ilp32 test_c_f.S -o test_c_f_32

test_c_f: test_c_f_64 test_c_f_32
	tinyrv-user-elf test_c_f_32 || exit $$?
	tinyrv-user-elf test_c_f_64 || exit $$?

############# mini

#CC_FLAGS=-O2 -mcmodel=medany -static -specs=/usr/lib/picolibc/riscv64-unknown-elf/picolibc.specs --oslib=semihost
CC_FLAGS=-O2 -mcmodel=medany -static
CC_FLAGS_SEMI=${CC_FLAGS} -specs=/opt/riscv/riscv64-unknown-elf/lib/semihost.specs


test_mini32: mini32
	test "$(shell tinyrv-user-elf mini32 foo 0x01 42)" = "hello mini32 foo 0x01 42"

test_mini64: mini64
	test "$(shell tinyrv-user-elf mini64 foo 0x01 42)" = "hello mini64 foo 0x01 42"

test_mini32semi: mini32semi
	test "$(shell tinyrv-user-elf mini32semi foo 0x01 42)" = "hello mini32semi foo 0x01 42"

test_mini64semi: mini64semi
	test "$(shell tinyrv-user-elf mini64semi foo 0x01 42)" = "hello mini64semi foo 0x01 42"

mini64: mini.c
	riscv64-unknown-elf-gcc ${CC_FLAGS} -march=rv64ima -mabi=lp64 $^ -o $@

mini32: mini.c
	riscv64-unknown-elf-gcc ${CC_FLAGS} -march=rv32ima -mabi=ilp32 $^ -o $@

mini64semi: mini.c
	riscv64-unknown-elf-gcc ${CC_FLAGS_SEMI} -march=rv64ima -mabi=lp64 $^ -o $@

mini32semi: mini.c
	riscv64-unknown-elf-gcc ${CC_FLAGS_SEMI} -march=rv32ima -mabi=ilp32 $^ -o $@

%.bin: %
	riscv64-unknown-elf-objcopy -O binary $< $@

%.disass: %
	riscv64-unknown-elf-objdump -d $< >$@

clean:
	-rm mini32* mini64*


######## coremark

run_coremark: coremark/run2.log

coremark/run2.log: coremark coremark_tinyrv_port/core_portme.c coremark_tinyrv_port/core_portme.h
	make -C coremark PORT_DIR=../coremark_tinyrv_port clean run

coremark:
	git clone https://github.com/eembc/coremark.git

####### boot pre-compiled linux

run_linux: tinyrv-test-blobs
	tinyrv-system-virt -k tinyrv-test-blobs/linux-6.6.18-rv64-nommu/Image

tinyrv-test-blobs:
	git clone https://github.com/s-holst/tinyrv-test-blobs.git

####### buildroot system building

Image: buildroot/output/images/Image
	cp buildroot/output/images/Image Image

buildroot/output/images/Image: buildroot/.config
	make -C buildroot

buildroot/.config: buildroot br2_external_tinyrv/configs/tinyrv_defconfig
	make -C buildroot BR2_EXTERNAL=../br2_external_tinyrv tinyrv_defconfig

buildroot:
	git clone https://gitlab.com/buildroot.org/buildroot.git
