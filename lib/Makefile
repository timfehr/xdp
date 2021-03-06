LIB = libxdp
SOURCE = libxdp
PREFIX = /usr/local/

# Notice: the kbuilddir can be redefined on make cmdline
kbuilddir ?= /lib/modules/$(shell uname -r)/build/
KERNEL = $(kbuilddir)

CFLAGS := -O2 -Wall -Werror
CFLAGS += -I$(KERNEL)usr/include
CFLAGS += -I$(KERNEL)tools/include
CFLAGS += -I$(KERNEL)tools/lib
CFLAGS += -I$(KERNEL)tools/perf/include
CFLAGS += -L$(KERNEL)tools/lib/bpf

.PHONY: all
all: $(LIB)
	ar rcs $(LIB).a $(LIB).o
	gcc -shared $(LIB).o -o $(LIB).so

# Object file
$(LIB): %: $(SOURCE).c $(SOURCE).h
	gcc -c -fPIC $(CFLAGS) -o $(LIB).o $< -lbpf -lelf

.PHONY: clean
clean:
	rm -rf *.o *.a *.so $(LIB)

.PHONY: static
static:	$(LIB)
	ar rcs $(LIB).a $(LIB).o

.PHONY: shared
shared: $(LIB)
	gcc -shared $(LIB).o -o $(LIB).so

.PHONY: install
install:
	cp $(LIB).a $(PREFIX)lib/$(LIB).a
	cp $(LIB).so $(PREFIX)lib/$(LIB).so
	cp *.h $(PREFIX)include/

.PHONY: uninstall
uninstall:
	rm $(PREFIX)lib/$(LIB).a
	rm $(PREFIX)lib/$(LIB).so
	rm $(PREFIX)include/$(LIB).h
	rm $(PREFIX)include/perf-sys.h
	rm $(PREFIX)include/bpf_helpers.h
	rm $(PREFIX)include/bpf_util.h