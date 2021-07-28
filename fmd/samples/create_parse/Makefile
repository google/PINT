CC = gcc

PROJECT_ROOT = ../..

LIBFMD = $(PROJECT_ROOT)/lib/libfmd.a
SAMPLE = create_parse
CFLAGS = -I$(PROJECT_ROOT)/inc -Wall -Werror -MD

OBJECTS = main.o

all: $(SAMPLE)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(LIBFMD):
	make -C $(PROJECT_ROOT)/lib

$(SAMPLE): $(OBJECTS) $(LIBFMD)
	$(CC) -o $@ $^

clean:
	rm -f *.o *.d $(SAMPLE)

-include $(OBJECTS:.o=.d)
