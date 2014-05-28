CC=gcc
LIBS=-lpcap
OPTS=-ggdb3 -rdynamic

traffic:
	$(CC) -o traffic *.c $(LIBS) $(OPTS)
	
all: traffic

clean:
	rm traffic

