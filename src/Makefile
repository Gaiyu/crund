CFLAGS += -O2

all: crund_launcher crund_exec

clean:
	rm -f *.o
	rm -f crund_launcher
	rm -f crund_exec

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

crund_exec: crund_exec.o
	$(CC) -o $@ $^

crund_launcher: crund_launcher.o
	$(CC) $(LDFLAGS) -lcap -o $@ $^
