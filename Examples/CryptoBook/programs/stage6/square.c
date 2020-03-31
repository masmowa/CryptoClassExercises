/******************************************************************/
/*                                                                */
/*   File:        square.c                                        */
/*   Author:      Lars Ivansson                                   */
/*   Created:     October 5, 1999                                 */
/*   Modified:    October 7, 1999                                 */
/*   Description: This program computes square candidates given   */
/*                a playfair cipher.                              */
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

#define SMALL -1e100
#define TINY  -1e200

typedef struct item_ {
  int square[25];
  double score;
  int size;
} item;

int top_list_size = 100;
item **top_list;

int subset_size = 5;
int *subset;

int square[25];
int inv_square[25];

double log_probabilities[25][25];

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
  fprintf(stderr, "Usage: square [-h] [-cf <filename>] [-sf <filename>] -bf <filename>\n"); 
  fprintf(stderr, "              [-sp -4..4 -4..4 0|1] -n <int> -s <int>\n");
  fprintf(stderr, "Type square -h for help.\n");
}

void print_help() {
  fprintf(stderr, "Usage: square [-h] [-cf <filename>] [-sf <filename>] -bf <filename>\n"); 
  fprintf(stderr, "              [-sp -4..4 -4..4 0|1] -n <int> -s <int>\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -cf <filename>  The name of the file from which to read the cipher text.\n");
  fprintf(stderr, "                  The default is stdin.\n");
  fprintf(stderr, "  -sf <filename>  The name of the file on which to write the squares.\n");
  fprintf(stderr, "                  The default is stdout.\n");
  fprintf(stderr, "  -bf <filename>  The name of the file from which to read the bigram stats.\n");
  fprintf(stderr, "  -sp <r> <s> <h> Specifies the rowshift, colshift and if horizontal corner\n");
  fprintf(stderr, "                  shift is applied.  Default is 1, 1, 1.\n");
  fprintf(stderr, "  -n <int>        The number of candidates to store.\n");
  fprintf(stderr, "  -s <int>        The code word length to try.\n");
  fprintf(stderr, "  -h              Displays this information.\n");
}

void parse_command_line(int argc, char **argv, char **c_filename, 
			char **s_filename, char **b_filename,
			int *rowshift, int *colshift, int *horizontal) {
  int i, j;

  *c_filename = NULL;
  *s_filename = NULL;
  *b_filename = NULL;
  *rowshift = 1;
  *colshift = 1;
  *horizontal = 1;

  for (i = 1; i < argc; i++) {
    if (!strcmp("-cf", argv[i])) {
      if (++i == argc) {
	print_usage(); 
	exit(EXIT_FAILURE);
      }
      (*c_filename) = strdup(argv[i]);
    } else if (!strcmp("-sf", argv[i])) {
      if (++i == argc) {
	print_usage(); 
	exit(EXIT_FAILURE);
      }
      (*s_filename) = strdup(argv[i]);
    } else if (!strcmp("-bf", argv[i])) {
      if (++i == argc) {
	print_usage(); 
	exit(EXIT_FAILURE);
      }
      (*b_filename) = strdup(argv[i]);
    } else if (!strcmp("-n", argv[i])) {
      if (++i == argc || sscanf(argv[i], "%d", &top_list_size) != 1) {
	print_usage();
	exit(EXIT_FAILURE);
      }
    } else if (!strcmp("-s", argv[i])) {
      if (++i == argc || sscanf(argv[i], "%d", &subset_size) != 1) {
	print_usage();
	exit(EXIT_FAILURE);
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

  if ((*b_filename) == NULL) {
    fprintf(stderr, "Mandatory option -bf <filename> was not present.\n");
    print_usage();
    exit(EXIT_FAILURE);
  }

  /* Allocate and initialize the top_list. */
  if ((top_list = malloc(top_list_size * sizeof(item*))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for the top list.\n");
    exit(EXIT_FAILURE);
  }
  for (i = 0; i < top_list_size; i++) {
    if ((top_list[i] = malloc(sizeof(item))) == NULL) {
      fprintf(stderr, "Error: Unable to allocate memory for the %d:th top list item.\n",
	      i + 1);
      exit(EXIT_FAILURE);
    }
    for (j = 0; j < 25; j++) {
      top_list[i]->square[j] = -1;
    }
    top_list[i]->score = TINY;
  }

  /* Allocate and initialize the subset. */
  if ((subset = malloc(subset_size * sizeof(int))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for the subset.\n");
    exit(EXIT_FAILURE);
  }
  for (i = 0; i < subset_size; i++) {
    subset[i] = subset_size - i - 1;
  }

}

double update_toplist(int *square, double score, int size) {
  int i, j;
  
  /* Find the position in which to insert the item. */
  for (i = 0; i < top_list_size; i++) {
    if (score > top_list[i]->score)
      break;    
  }
  /* Shift down the ones below. */
  free(top_list[top_list_size - 1]);
  for (j = top_list_size - 1; j > i; j--) {
    top_list[j] = top_list[j - 1];
  }
  
  if ((top_list[j] = malloc(sizeof(item))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for the new top list item.\n");
    exit(EXIT_FAILURE);
  }
  
  /* Insert the new item. */
  for (j = 0; j < 25; j++) {
    top_list[i]->square[j] = square[j];
  }
  top_list[i]->score = score;
  top_list[i]->size = size;
  
  return top_list[top_list_size - 1]->score;
}

void build_log_probs(FILE *infile) {
  int i, j, i1, i2;
  double log_prob, prob;
  char c1, c2, row[512];
  
  for (i = 0; i < 25; i++) {
    for (j = 0; j < 25; j++) {
      log_probabilities[i][j] = 0;
    }
  }

  while (fgets(row, 511, infile)) {
    if (row[0] == '#') 
      continue;
    if (sscanf(row, "%c %c: %*d %*f %lf", &c1, &c2, &log_prob) == 3) {

      if (c1 == 'J') {
	i1 = caps_not_j_to_int('I');
      } else {
	i1 = caps_not_j_to_int(c1);
      }

      if (c2 == 'J') {
	i2 = caps_not_j_to_int('I');
      } else {
	i2 = caps_not_j_to_int(c2);
      }

      if (log_probabilities[i1][i2] == 0) {
	log_probabilities[i1][i2] = log_prob;
      } else {
#ifdef DEBUG
	fprintf(stderr, "Warning: Changing characters (%c, %c) to (%c, %c) in build_log_probs.\n",
		c1, c2, int_to_caps_not_j(i1), int_to_caps_not_j(i2));
#endif	
	prob = exp(log_probabilities[i1][i2]) + exp(log_prob);
	log_probabilities[i1][i2] = log(prob);
      }
    } else {
      fprintf(stderr, "Error in file format!\nIllegal row: %s\n", row);
      exit(EXIT_FAILURE);
    }
  }

  for (i = 0; i < 25; i++) {
    for (j = 0; j < 25; j++) {
      if (log_probabilities[i][j] == 0) {
	if (i == j) {
	  log_probabilities[i][j] = TINY;
	} else {
	  log_probabilities[i][j] = -1.570047e+01;
	}

      }
    }
  }
}


/* Reads text from a file and stores it as numbers from 0 to 25. */
/* The letter 'J' should not be present. */
int read_text(FILE *infile, int **text) {
  char row[2048];
  int length = 512;
  int i, n = 0;

  if (((*text) = malloc(length * sizeof(int))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for the cipher text.\n");
    exit(EXIT_FAILURE);
  }
  while (fgets(row, 2047, infile)) {

    for (i = 0; i < strlen(row); i++) {

      if (isalpha(row[i])) {
	(*text)[n++] = caps_not_j_to_int(toupper(row[i]));

	if (n == length) {
	  length += 512;
	  if (((*text) = realloc((*text), length * sizeof(int))) == NULL) {
	    fprintf(stderr, "Error: Unable to reallocate memory for the cipher text.\n");
	    exit(EXIT_FAILURE);
	  }
	}
      }
    }
  }

  if (((*text) = realloc((*text), n * sizeof(int))) == NULL) {
    fprintf(stderr, "Error: Unable to reallocate memory for the plain text.\n");
    exit(EXIT_FAILURE);
  }

  return n;
}

int next_subset() {
  int j;
  
  for (j = 0; j < subset_size; j++) {
    if (subset[j] < 24 - j) {
      subset[j]++;
      break;
    } 
  }  

  if (j == subset_size)
    return 0;

  for (j = j - 1; j >= 0; j--) {
    subset[j] = subset[j + 1] + 1;
  }

  return 1;
}

double mean_score() {
  int i, j, m;
  int ci_first, ci_last, p_first, p_last;
  const int *pair;
  double score, add;

  m = 0;
  score = 0;

  /* We should not include bigrams from the sub set. */
  for (i = subset_size; i < 25; i++) {
    for (j = i + 1; j < 25; j++) {
      p_first = square[i];
      p_last = square[j];
      pair = plain_to_cipher[i][j];
      ci_first = pair[0];
      ci_last = pair[1];
      
      /* We should not include bigrams from the sub set. */
      if (ci_first >= subset_size && ci_last >=subset_size) {
	add = log_probabilities[p_first][p_last];
	if (add > -9) {
	  score += add;
	  m++;
	}
	 add = log_probabilities[p_last][p_first];
	if (add > -9) {
	  score += add;
	  m++;
	}
      }      
    }
  }
  
  return score / m;
}

double decrypt(int *cipher_text, int length, double mean, int *bigs) {
  int i;
  int ci_first, ci_last, p_first, p_last, last;
  const int *pair;
  double score;
  
  last = -1;
  score = 0.0;
  *bigs = 0;

  for (i = 0; i < length; i += 2) {
    /* Find the i:th and i+1:st square index in the cipher text. */
    ci_first = inv_square[cipher_text[i]];
    ci_last = inv_square[cipher_text[i + 1]];

    if (ci_first >= subset_size && ci_last >= subset_size) {
      /* None of the cipher text characters are in the unsafe subset. */

      /* Find the corresponding plain text positions. */
      pair = cipher_to_plain[ci_first][ci_last];

      if (pair[0] >= subset_size && pair[1] >= subset_size) {
	/* None of the plain text characters are among the unsafe. */

	p_first = square[pair[0]];
	p_last = square[pair[1]];

	score += log_probabilities[p_first][p_last];
	(*bigs)++;

	if (last >= 0) {
	  /* If we substituted the previous bigram we have to */
	  /* score the overlapping bigram. */
	  score += log_probabilities[last][p_first];
	  (*bigs)++;
	}
	
	/* Set last to be the last character. */
	last = p_last;
      } else {

	/* No substitution was made. */
	last = -1;
      }
    }
  }
  return (score / (*bigs) - mean);
}

int main(int argc, char *argv[]) {
  int i, j, length, si, size;
  
  char *c_filename, *s_filename, *b_filename;
  FILE *c_file, *s_file, *b_file;

  int rowshift, colshift, horizontal;

  double last_score_on_top_list, score, mean;
  int *cipher_text;
  char c_square[26];

  parse_command_line(argc, argv, &c_filename, &s_filename, &b_filename,
		     &rowshift, &colshift, &horizontal);

  if (c_filename != NULL) {
    if ((c_file = fopen(c_filename, "r")) == NULL) {
      fprintf(stderr, "Unable to open cipher text file %s for reading.\n", c_filename);
      exit(EXIT_FAILURE);
    }
  } else {
    c_file = stdin;
  }

  if (s_filename != NULL) {
    if ((s_file = fopen(s_filename, "w")) == NULL) {
      fprintf(stderr, "Unable to open square file %s for writing.\n", s_filename);
      exit(EXIT_FAILURE);
    }
  } else {
    s_file = stdout;
  }

  if ((b_file = fopen(b_filename, "r")) == NULL) {
    fprintf(stderr, "Unable to open bigram file %s for reading.\n", b_filename);
    exit(EXIT_FAILURE);
  }
  

  /* Build the substitution tables. */
  build_substitution_tables(rowshift, colshift, horizontal);

  /* Build the tables for log probabilities. */
  build_log_probs(b_file);
  

  /* Allocate the cipher text array and store the cipher */
  /* text read from c_file in it. */
  length = read_text(c_file, &cipher_text);

  /* This variable should be smaller than everything else from the start. */
  last_score_on_top_list = TINY;

  do {

    /* Create the next square and inverse of square from the subset. */
    si = 0;
    for (i = 0; i < 25; i++) {
      if (subset[subset_size - 1 - si] == i) {
	square[si] = i;
	inv_square[i] = si;
	si++;
      } else {
	square[subset_size + i - si] = i;
	inv_square[i] = subset_size + i - si;		
      }
    }

    /* Calculate the mean score for all possible bigrams. */
    mean = mean_score();

    /* Calculate the score from decrypting using this square. */
    score = decrypt(cipher_text, length, mean, &size);
    
    /* Add the square to the toplist if it is good. */
    if (score > last_score_on_top_list) {
      last_score_on_top_list = update_toplist(square, score, size);
    }

  } while (next_subset());

  fprintf(s_file, "%d\n", subset_size);
  for (i = 0; i < top_list_size; i++) {
    for (j = 0; j < 25; j++) {
      c_square[j] = int_to_caps_not_j(top_list[i]->square[j]);
    }
    c_square[25] = '\0';
    fprintf(s_file, "%4d. %s\t %e\t%d\n", i + 1, c_square, top_list[i]->score, top_list[i]->size);
  }

  exit(EXIT_SUCCESS);
}
