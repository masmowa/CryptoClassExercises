CC = gcc
CFLAGS = -O6 -Wall  -pedantic
CLIBS = -lm 

all: vigenere

vigenere: vigenere.o
	$(CC) -o vigenere $(CFLAGS) vigenere.o $(CLIBS)

clean: 
	$(RM) -rf  core *~ vigenere.o vigenere

