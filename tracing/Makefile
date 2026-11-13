# Build the syscall_trace QEMU TCG plugin.
#
# QEMU plugins compile against the single public header qemu-plugin.h, shipped
# in a QEMU source/install tree under include/qemu/. Point QEMU_INCLUDE at the
# directory that CONTAINS qemu-plugin.h, then `make`.
#
#   make QEMU_INCLUDE=/path/to/qemu/include/qemu
#
# The result, libsyscall_trace.so, is loaded with:
#   qemu-system-<arch> ... -plugin ./libsyscall_trace.so,out=syscalls.log -d plugin
#
# Requires a QEMU built with ./configure --enable-plugins.

NAME        := syscall_trace
QEMU_INCLUDE ?= /usr/include/qemu

CC      ?= cc
CFLAGS  += -I$(QEMU_INCLUDE) -fPIC -Wall -O2 -g
LDFLAGS += -shared

all: lib$(NAME).so

lib$(NAME).so: $(NAME).o
	$(CC) $(LDFLAGS) -o $@ $^

$(NAME).o: $(NAME).c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(NAME).o lib$(NAME).so

.PHONY: all clean
