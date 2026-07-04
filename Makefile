CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap
TARGET = sniff
SRCS = sniff.c

all: $(TARGET)

$(TARGET): $(SRCS) myheader.h
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
