CFLAGS = -W -Wall -O3
TARGETS = bench

check: all
	./bench

$(TARGETS): curve25519_i64.o

all: $(TARGETS)

clean:
	$(RM) $(TARGETS) *.o .gdb_history

.PHONY: all check clean

%.s: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -S -g0 -o $@ $<
