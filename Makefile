PROGRAM = psig
LIBRARY = -ltepla -lgmp -lcrypto
SRC = main.c psig.c
OBJS = main.o psig.o

CC := gcc

.PHONY: all
all: psig

$(PROGRAM): $(OBJS)
	$(CC)  $(CFLAGS) $^ $(LIBRARY) -o $@

main.o: main.c
	$(CC) $(CFLAGS) -c $^

psig.o: psig.c
	$(CC) $(CFLAGS) -c $^

main.c: psig.h
psig.c: psig.h

.PHONY: clean
clean:
	$(RM) $(PROGRAM) *.o
