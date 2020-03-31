CC = gcc
CFLAGS = -O6 -Wall  -pedantic
CLIBS = -lm 

all: wizard cwizard

wizard: wizard.o trie.o
	$(CC) -o wizard $(CFLAGS) wizard.o trie.o $(CLIBS)

cwizard: cwizard.o trie.o
	$(CC) -o cwizard $(CFLAGS) cwizard.o trie.o $(CLIBS)

clean: 
	$(RM) -rf  core *~ wizard wizard.o cwizard cwizard.o trie.o
