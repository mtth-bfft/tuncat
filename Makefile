.SUFFIXES:

CFLAGS=-Wall -Wextra -pedantic -Werror -std=c11

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
EXE=tuncat
default: $(EXE)

$(EXE): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(OBJECTS) $(EXE)
