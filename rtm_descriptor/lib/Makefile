CC = gcc
AR = ar

LIBFMD = libfmd.a
CFLAGS = -I../inc -Wall -Werror

OBJECTS = parse.o generate.o

all: $(LIBFMD)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(LIBFMD): $(OBJECTS)
	ar -crv $@ $^

clean:
	rm -f *.a *.o
