src = reader.c main.c check.c log.c event.c

CPPFLAGS = -D_GNU_SOURCE
CFLAGS = -g -Wall -Wextra -Wno-unused-parameter -Werror
LDLIBS = -lev -laio

obj = $(src:.c=.o)

check: $(obj)
	$(LINK.o) $^ $(LDLIBS) -o $@

.PHONY: clean
clean:
	rm -f check *.o
