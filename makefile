CFLAGS= -std=c++11 -Wextra
CC=g++

all:main

main:main.cpp
	$(CC) $(CFLAGS) main.cpp -o hexa_data

clean:
	rm main
