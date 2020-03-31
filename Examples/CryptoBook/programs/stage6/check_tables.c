#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <limits.h>

#undef isalpha
#undef toupper

int square[25];
int inv_square[25];

int plain_to_cipher[25][25][2];
int cipher_to_plain[25][25][2];

/* Builds the plain_to_cipher and cipher_to_plain tables. */
/* The parameters rowshift or colshift determins what shift */
/* that should be made if the cells are on the same row or */
/* column respectively. The parameter horizontal is a boolean */
/* that is true if the first cypher character should be in the */
/* same row as the first plain text character and the same column */
/* as the last plain text character. */
void build_substitution_tables(int rowshift, int colshift, int horizontal) {
  int i, j;
  int row1, col1, row2, col2;

  for (i = 0; i < 25; i++) {
    for (j = 0; j < 25; j++) {
      
      row1 = i / 5;
      col1 = i % 5;
      row2 = j / 5;
      col2 = j % 5;

      if (i == j) {
	plain_to_cipher[i][j][0] = -1;
	plain_to_cipher[i][j][1] = -1;
	cipher_to_plain[i][j][0] = -1;
	cipher_to_plain[i][j][1] = -1;
      } else if (row1 == row2) {
	plain_to_cipher[i][j][0] = 5 * row1 + ((col1 + colshift + 5) % 5);
	plain_to_cipher[i][j][1] = 5 * row2 + ((col2 + colshift + 5) % 5);
	cipher_to_plain[i][j][0] = 5 * row1 + ((col1 - colshift + 5) % 5);
	cipher_to_plain[i][j][1] = 5 * row2 + ((col2 - colshift + 5) % 5);
      } else if (col1 == col2) {
	plain_to_cipher[i][j][0] = 5 * ((row1 + rowshift + 5) % 5) + col1;
	plain_to_cipher[i][j][1] = 5 * ((row2 + rowshift + 5) % 5) + col2;
	cipher_to_plain[i][j][0] = 5 * ((row1 - rowshift + 5) % 5) + col1;
	cipher_to_plain[i][j][1] = 5 * ((row2 - rowshift + 5) % 5) + col2;
      } else {
	if (horizontal) {
	  plain_to_cipher[i][j][0] = 5 * row1 + col2;
	  plain_to_cipher[i][j][1] = 5 * row2 + col1;
	  cipher_to_plain[i][j][0] = 5 * row1 + col2;
	  cipher_to_plain[i][j][1] = 5 * row2 + col1;
	} else {
	  plain_to_cipher[i][j][0] = 5 * row2 + col1;
	  plain_to_cipher[i][j][1] = 5 * row1 + col2;
	  cipher_to_plain[i][j][0] = 5 * row2 + col1;
	  cipher_to_plain[i][j][1] = 5 * row1 + col2;
	}
      }
    }
  }
}


int caps_not_j_to_int(char c) {
  if (c < 'A' || c > 'Z' || c == 'J') {
    fprintf(stderr, "Illegal character %c in caps_not_j_to_int.\n", c);
    exit(EXIT_FAILURE);
  }  else {
    if (c < 'J') {
      return c - 'A';
    } else {
      return c - 'A' - 1;
    }
  }
}

char int_to_caps_not_j(int i) {
  if (i < 0 || i > 24) {
    fprintf(stderr, "Illegal int %d in int_to_caps_not_j).\n", i);
    exit(EXIT_FAILURE);
  }  else {
    if (i <= 8) {
      return i + 'A';
    } else {
      return i + 'A' + 1;
    }
  }
}

void print_usage() {
  fprintf(stderr, "Usage: check_tables -k <square> [-sp -4..4 -4..4 1|0]\n");
}

void parse_command_line(int argc, char **argv, int *rowshift, int *colshift, int *horizontal) {
  int i, j;

  *rowshift = 1;
  *colshift = 1;
  *horizontal = 1;

  square[0] = -1;

  for (i = 1; i < argc; i++) {
      
    if (!strcmp("-k", argv[i])) {
      if (++i == argc || strlen(argv[i]) != 25) {
	fprintf(stderr, "Error in key length: %d.\n", strlen(argv[i]));
	exit(EXIT_FAILURE);
      }
      for (j = 0; j < 25; j++) {
	inv_square[j] = -1;
      }
      for (j = 0; j < 25; j++) {
	if (toupper(argv[i][j]) < 'A' || toupper(argv[i][j]) > 'Z' || 
	    toupper(argv[i][j]) == 'J') {
 	  fprintf(stderr, "Illegal key character: %c.\n", toupper(argv[i][j]));
	  exit(EXIT_FAILURE);
	} else {
	  square[j] = caps_not_j_to_int(argv[i][j]);
	  inv_square[square[j]] = j;
	}
      }
      for (j = 0; j < 25; j++) {
	if (inv_square[j] == -1) {
 	  fprintf(stderr, "Character %c missing in key.\n", int_to_caps_not_j(j));
	  exit(EXIT_FAILURE);	  
	}
      }
    } else if (!strcmp("-sp", argv[i])) {
      if (i + 3 >= argc) {
	print_usage();
	exit(EXIT_FAILURE);
      }
      if (sscanf(argv[++i], "%d ", rowshift) != 1) {
	print_usage();
	exit(EXIT_FAILURE);
      }
      if (sscanf(argv[++i], "%d ", colshift) != 1) {
	print_usage();
	exit(EXIT_FAILURE);
      }
      if (sscanf(argv[++i], "%d ", horizontal) != 1) {
	print_usage();
	exit(EXIT_FAILURE);
      }
    } else if (!strcmp("-h", argv[i])) {
      print_usage();
      exit(EXIT_SUCCESS);
    } else {
      print_usage();
      exit(EXIT_FAILURE);
    }
  }

  if (!(*rowshift < 5 || *rowshift > -5) ||
      !(*colshift < 5 || *colshift > -5) || 
      !(*horizontal == 1 || *horizontal == 0)) {
	print_usage();
	exit(EXIT_FAILURE);    
  }

  if (square[0] == -1) {
    fprintf(stderr, "Mandatory option -k <square> was not present.\n");
    print_usage();
    exit(EXIT_FAILURE);
  } 
}

void print_square(FILE* outfile) {
  int i;

  fprintf(outfile, "+-+-+-+-+-+\n");
  for (i = 0; i < 25; i++) {
    fprintf(outfile, "|%c", int_to_caps_not_j(square[i]));
    if ((i+1) % 5 == 0) {
      fprintf(outfile, "|\n+-+-+-+-+-+\n");
    }
  }
}


int main(int argc, char *argv[]) {
  char *first, *last, buf[64];

  int rowshift, colshift, horizontal;

  char pfc, plc, cfc, clc;
  int pfi, pli, cfi, cli;
  
  const int *pair;

  parse_command_line(argc, argv, &rowshift, &colshift, &horizontal);

  /* Build the substitution tables. */
  build_substitution_tables(rowshift, colshift, horizontal);

  for (;;) {
    
    print_square(stdout);
      
  prompt:
    fprintf(stdout, "\n");
    fprintf(stdout, ">");
    fflush(stdin);
    
    fgets(buf, 63, stdin);
    buf[strlen(buf) - 1] = '\0';
    
    if (buf[0] == 'c') { 
      /* Bind a letter to another. */
      if ((first = strtok(&(buf[1]), " \t\n")) == NULL) {
	fprintf(stdout, "Illegal input: %s\n", buf);
	goto prompt;	  
      }
      
      last = strtok(NULL, " ");
      if (last == NULL) {
	fprintf(stdout, "Illegal input: %s\n", buf);
	goto prompt;
      }

      cfc = toupper(first[0]);
      clc = toupper(last[0]);
      cfi = inv_square[caps_not_j_to_int(cfc)];
      cli = inv_square[caps_not_j_to_int(clc)];
      pair = cipher_to_plain[cfi][cli];
      pfi = pair[0]; 
      pli = pair[1];
      pfc = int_to_caps_not_j(square[pfi]);
      plc = int_to_caps_not_j(square[pli]);

      fprintf(stdout, "cipher text [%c, %c] (%d, %d) => plain text [%c, %c] (%d, %d)\n",
	      cfc, clc, cfi, cli, pfc, plc, pfi, pli);

    } else if (buf[0] == 'p') { 
      /* Bind a letter to another. */
      if ((first = strtok(&(buf[1]), " \t\n")) == NULL) {
	fprintf(stdout, "Illegal input: %s\n", buf);
	goto prompt;	  
      }

      last = strtok(NULL, " ");
      if (last == NULL) {
	fprintf(stdout, "Illegal input: %s\n", buf);
	goto prompt;
      }
      
      pfc = toupper(first[0]);
      plc = toupper(last[0]);
      pfi = inv_square[caps_not_j_to_int(pfc)];
      pli = inv_square[caps_not_j_to_int(plc)];
      pair = plain_to_cipher[pfi][pli];
      cfi = pair[0]; 
      cli = pair[1];
      cfc = int_to_caps_not_j(square[cfi]);
      clc = int_to_caps_not_j(square[cli]);
      
      fprintf(stdout, "plain text [%c, %c] (%d, %d) => cipher text [%c, %c] (%d, %d)\n",
	      pfc, plc, pfi, pli, cfc, clc, cfi, cli);
	      
	      
    } else if (!strcmp(buf, "quit")) {
	/* Quit */
      break;
    }
  }

  return EXIT_SUCCESS;
}
