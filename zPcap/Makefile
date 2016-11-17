CC := gcc
CFLAGS := -Wall -O2
LFLAGS := -lpcap

TARGET := test.elf
OBJ    := test.o zPcap.o

$(TARGET):$(OBJ)
	$(CC) $(LFLAGS) $^ -o $@

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o *.elf -rf