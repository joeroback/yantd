CFLAGS += -Wall -Wunused -I. -DNDEBUG -fomit-frame-pointer

.PHONY: all

all: yantd yantd-cli

yantd-cli: yantd-cli.o
yantd-cli.o: yantd-cli.c yantd.h

yantd: yantd.o
yantd.o: yantd.c yantd.h

.PHONY: clean

clean:
	rm -f yantd-cli yantd-cli.o yantd yantd.o
