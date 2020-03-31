/******************************************************************/
/*                                                                */
/*   File:        playfar.c                                       */
/*   Author:      Lars Ivansson                                   */
/*   Created:     October 6, 1999                                 */
/*   Modified:    October 6, 1999                                 */
/*   Description: This program encrypt a text using the           */
/*                playfair cipher.                                */
/*                                                                */
/******************************************************************/

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
  fprintf(stderr, "Usage: playfair [-h] [-pf <filename>] [-cf <filename>] -e/-d -k <square>\n");
  fprintf(stderr, "                [-sp -4..4 -4..4 0|1]\n");
  fprintf(stderr, "Type playfair -h for help.\n");
}

void print_help() {
  fprintf(stderr, "Usage: playfair [-h] [-pf <filename>] [-cf <filename>] -e/-d -k <square>\n");
  fprintf(stderr, "                [-sp -4..4 -4..4 0|1]\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -pf <filename>  The name of the file containing the plain text.\n");
  fprintf(stderr, "                  The default is stdout during decryption and stdin\n");
  fprintf(stderr, "                  during encryption.\n");
  fprintf(stderr, "  -cf <filename>  The name of the file containing the cipher text.\n");
  fprintf(stderr, "                  The default is stdin during decryption and stdout\n");
  fprintf(stderr, "                  during encryption.\n");
  fprintf(stderr, "  -e              Encrypt.\n");
  fprintf(stderr, "  -d              Decrypt.\n");
  fprintf(stderr, "  -sp <r> <s> <h> Specifies the rowshift, colshift and if horizontal corner\n");
  fprintf(stderr, "                  shift is applied.  Default is 1, 1, 1.\n");
  fprintf(stderr, "  -k <square>     Specifies a string representing the square.\n");
  fprintf(stderr, "  -h              Display this message.\n");
}

void parse_command_line(int argc, char **argv, char **p_filename, char **c_filename, 
			int *encrypt, int *rowshift, int *colshift, int *horizontal) {
  int i, j;

  *p_filename = NULL;
  *c_filename = NULL;
  *encrypt = 1;

  *rowshift = 1;
  *colshift = 1;
  *horizontal = 1;

  square[0] = -1;

  for (i = 1; i < argc; i++) {
    if (!strcmp("-pf", argv[i])) {
      if (++i == argc) {
	print_usage(); 
	exit(EXIT_FAILURE);
      }
      (*p_filename) = strdup(argv[i]);
    } else if (!strcmp("-cf", argv[i])) {
      if (++i == argc) {
	print_usage(); 
	exit(EXIT_FAILURE);
      }
      (*c_filename) = strdup(argv[i]);
    } else if (!strcmp("-k", argv[i])) {
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
      print_help();
      exit(EXIT_SUCCESS);
    } else if (!strcmp("-e", argv[i])) {
      *encrypt = 1;
    } else if (!strcmp("-d", argv[i])) {
      *encrypt = 0;
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


/* Reads text from a file and stores it as numbers from 0 to 25. */
/* The letter J is excluded. If 'J' is present it is replaced by the letter 'I'. */
int read_text(FILE *infile, int **text) {
  int length = 512;
  int c, lc;
  int n = 0;
   
  if (((*text) = malloc(length * sizeof(int))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for the plain text.\n");
    exit(EXIT_FAILURE);
  }
     
   
  lc = toupper(getc(infile));
  while (lc != EOF && !isalpha(lc)) {
    lc = toupper(getc(infile));
  }
  if (lc == 'J')
    lc = 'I';

  while ((c = toupper(getc(infile))) != EOF) {
     
    if (!isalpha(c)) 
      continue;

    if (c == 'J')
      c = 'I';

    if (c != lc) {

      /* Store the bigram. */
      (*text)[n++] = caps_not_j_to_int(lc);
      (*text)[n++] = caps_not_j_to_int(c);
       
      if (n == length) {
	length += 512;
	if (((*text) = realloc((*text), length * sizeof(int))) == NULL) {
	  fprintf(stderr, "Error: Unable to reallocate memory for the plain text.\n");
	  exit(EXIT_FAILURE);
	}
      }
       
      /* Find a new first character to the next bigram. */
      lc = toupper(getc(infile));
      while (lc != EOF && !isalpha(lc)) {
	lc = toupper(getc(infile));
      }
      if (lc == 'J')
	lc = 'I';

    } else { /* c == lc */
      /* Store the first character and an X. */
      (*text)[n++] = caps_not_j_to_int(lc);
      (*text)[n++] = caps_not_j_to_int('X');

      if (n == length) {
	length += 512;
	if (((*text) = realloc((*text), length * sizeof(int))) == NULL) {
	  fprintf(stderr, "Error: Unable to reallocate memory for the plain text.\n");
	  exit(EXIT_FAILURE);
	}
      }

      lc = c; /* Not necessary since c == lc */
    }
  }
  if (n % 2 == 1) {
    /* We lack a complete bigram at the end. */
    (*text)[n++] = caps_not_j_to_int('X');
  }

  if (((*text) = realloc((*text), n * sizeof(int))) == NULL) {
    fprintf(stderr, "Error: Unable to reallocate memory for the plain text.\n");
    exit(EXIT_FAILURE);
  }

  return n;
}


void encrypt(int *cipher_text, int *plain_text, int length) {
  int i;
  int c_first, c_last, pi_first, pi_last;
  const int *pair;
  
  for (i = 0; i < length; i += 2) {
    /* Find the i:th and i+1:st square index in the cipher text. */
    pi_first = inv_square[plain_text[i]];
    pi_last = inv_square[plain_text[i + 1]];
    pair = plain_to_cipher[pi_first][pi_last];
    c_first = square[pair[0]];
    c_last = square[pair[1]];
    cipher_text[i] = c_first;
    cipher_text[i + 1] = c_last;
  }
}

void decrypt(int *cipher_text, int *plain_text, int length) {
  int i;
  int ci_first, ci_last, p_first, p_last;
  const int *pair;
  
  for (i = 0; i < length; i += 2) {
    /* Find the i:th and i+1:st square index in the cipher text. */
    ci_first = inv_square[cipher_text[i]];
    ci_last = inv_square[cipher_text[i + 1]];
    pair = cipher_to_plain[ci_first][ci_last];
    p_first = square[pair[0]];
    p_last = square[pair[1]];
    plain_text[i] = p_first;
    plain_text[i + 1] = p_last;
  }
}


int main(int argc, char *argv[]) {
  int i, length;

  int rowshift, colshift, horizontal;

  char *p_filename, *c_filename;
  FILE *p_file, *c_file;  

  int enc;
  int *plain_text, *cipher_text;

  parse_command_line(argc, argv, &p_filename, &c_filename, &enc, 
		     &rowshift, &colshift, &horizontal);

  /* Build the substitution tables. */
  build_substitution_tables(rowshift, colshift, horizontal);

  if (enc) { /* encrypt using the key. */
    
    fprintf(stderr, "Encrypting...\n");
    
    if (p_filename != NULL) {
      if ((p_file = fopen(p_filename, "r")) == NULL) {
	fprintf(stderr, "Unable to open plain text file %s for reading.\n", p_filename);
	exit(EXIT_FAILURE);
      }
    } else {
      p_file = stdin;
    }
    
    if (c_filename != NULL) {
      if ((c_file = fopen(c_filename, "w")) == NULL) {
	fprintf(stderr, "Unable to open cipher text file %s for writing.\n", c_filename);
	exit(EXIT_FAILURE);
      }
    } else {
      c_file = stdout;
    }
      
    /* Allocate the plain_text array and store the plain */
    /* text read from p_file in it. */
    length = read_text(p_file, &plain_text);
    
    /* Allocate a cipher text array of the same size */
    /* as the plain text. */
    if ((cipher_text = malloc(length * sizeof(int))) == NULL) {
      fprintf(stderr, "Error: Unable to allocate memory for the cipher text.\n");
      exit(EXIT_FAILURE);
    }

    /* Encrypt the plain text and put it in the cipher text. */
    encrypt(cipher_text, plain_text, length);
    

    for (i = 0; i < length; i++) {
      fprintf(c_file, "%c", int_to_caps_not_j(cipher_text[i]));
      if((i + 1) % 60 == 0)
	fprintf(c_file, "\n");
    }

    fprintf(c_file, "\n");

  } else { /* decrypt */


    fprintf(stderr, "Decrypting...\n");

    if (c_filename != NULL) {
      if ((c_file = fopen(c_filename, "r")) == NULL) {
	fprintf(stderr, "Unable to open cipher text file %s for reading.\n", c_filename);
	exit(EXIT_FAILURE);
      }
    } else {
      c_file = stdin;
    }
    
    if (p_filename != NULL) {
      if ((p_file = fopen(p_filename, "w")) == NULL) {
	fprintf(stderr, "Unable to open plain text file %s for writing.\n", p_filename);
	exit(EXIT_FAILURE);
      }
    } else {
      p_file = stdout;
    }
    
  
    /* Allocate the plain_text array and store the plain */
    /* text read from p_file in it. */
    length = read_text(c_file, &cipher_text);
    
    /* Allocate a cipher text array of the same size */
    /* as the plain text. */
    if ((plain_text = malloc(length * sizeof(int))) == NULL) {
      fprintf(stderr, "Error: Unable to allocate memory for the cipher text.\n");
      exit(EXIT_FAILURE);
    }

    /* Encrypt the plain text and put it in the cipher text. */
    decrypt(cipher_text, plain_text, length);
    

    for (i = 0; i < length; i++) {
      fprintf(p_file, "%c", int_to_caps_not_j(plain_text[i]));
      if((i + 1) % 60 == 0)
	fprintf(p_file, "\n");
    }

    fprintf(p_file, "\n");
  }
  return EXIT_SUCCESS;
}
