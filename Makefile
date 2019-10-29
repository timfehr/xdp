NETDEVICE = ens160
BINARY = reqrouter
KERN_OBJ = $(BINARY)_kern.o

# Notice: the kbuilddir can be redefined on make cmdline
kbuilddir ?= /lib/modules/$(shell uname -r)/build/
KERNEL = $(kbuilddir)

# Includes to the current Kernel
LINUXINCLUDE := -I$(KERNEL)arch/x86/include
LINUXINCLUDE += -I$(KERNEL)arch/x86/include/generated/uapi
LINUXINCLUDE += -I$(KERNEL)arch/x86/include/generated
LINUXINCLUDE += -I$(KERNEL)include
LINUXINCLUDE += -I$(KERNEL)arch/x86/include/uapi
LINUXINCLUDE += -I$(KERNEL)include/uapi
LINUXINCLUDE += -I$(KERNEL)include/generated/uapi
LINUXINCLUDE += -include $(KERNEL)include/linux/kconfig.h
LINUXINCLUDE += -I$(KERNEL)tools/lib

NOSTDINC_FLAGS := -nostdinc -isystem $(shell gcc -print-file-name=include)

HOSTCFLAGS := -O2 -Wall #-H
HOSTCFLAGS += -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__
HOSTCFLAGS += -D__TARGET_ARCH_$(ARCH)
HOSTCFLAGS += -Werror
HOSTCFLAGS += -Wno-unused-value -Wno-pointer-sign
HOSTCFLAGS += -Wno-compare-distinct-pointer-types
HOSTCFLAGS += -Wno-gnu-variable-sized-type-not-at-end
HOSTCFLAGS += -Wno-tautological-compare
HOSTCFLAGS += -Wno-unknown-warning-option
HOSTCFLAGS += -Wno-address-of-packed-member

CFLAGS := -O2 -Wall -Werror
CFLAGS += -I$(KERNEL)usr/include
CFLAGS += -I$(KERNEL)tools/include
CFLAGS += -I$(KERNEL)tools/lib
CFLAGS += -I$(KERNEL)tools/perf/include
CFLAGS += -L$(KERNEL)tools/lib/bpf

all: $(KERN_OBJ) $(BINARY)

# BPF Kernel Object
$(KERN_OBJ): $(KERN_OBJ:%.o=%.c)
	clang-9 $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(HOSTCFLAGS) \
		-S -emit-llvm -c $<
	llc-9 -march=bpf -filetype=obj -o $@ $(KERN_OBJ:%.o=%.ll)

# Userspace program with dynamic (shared) lib
$(BINARY): %: $(BINARY)_user.c functions.h Makefile
	gcc -g $(CFLAGS) $(OBJECTS) -o reqrouter $< reqrouter.c -lbpf -lelf -pthread

# Catchall for the objects
%.o: %.c
	gcc $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	rm -rf *.o *.ll $(BINARY)

.PHONY: run
run: $(BINARY) $(KERN_OBJ)
	sudo ./$(BINARY) -i $(NETDEVICE) -S
