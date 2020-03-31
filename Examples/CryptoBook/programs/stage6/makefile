CC = gcc
CFLAGS = -O6 -Wall  -pedantic
CLIBS = -lm 

all: square playfair check_tables heavy

play_fair: playfair.o
	$(CC) -o playfair $(CFLAGS) playfair.o $(CLIBS)

square: square.o
	$(CC) -o square $(CFLAGS) square.o $(CLIBS)

check_tables: check_tables.o
	$(CC) -o check_tables $(CFLAGS) check_tables.o $(CLIBS)

heavy: heavy.o
	$(CC) -o heavy $(CFLAGS) heavy.o $(CLIBS)

clean: 
	$(RM) -rf  core *~ square square.o playfair playfair.o check_tables check_tables.o heavy heavy.o
