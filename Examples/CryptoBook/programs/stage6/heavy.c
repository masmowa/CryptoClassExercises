/******************************************************************/
/*                                                                */
/*   File:        heavy.c                                         */
/*   Author:      Lars Ivansson                                   */
/*   Created:     October 8, 1999                                 */
/*   Modified:    October 8, 1999                                 */
/*   Description: This program solves the playfair cipher.        */
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

#define TINY  -1000000.0

typedef struct LightNode_ {
  char square[17];
  float score;
} LightNode;

typedef struct LightHeap_{
  unsigned int size;
  unsigned int max_size;
  LightNode **node_ptr;
} LightHeap;

typedef struct HeavyNode_ {
  char square[25];
  float score;
} HeavyNode;

typedef struct HeavyHeap_{
  unsigned int size;
  unsigned int max_size;
  HeavyNode **node_ptr;
} HeavyHeap;

/* Globals for the two heap types. */
int max_light_heap_size;
LightHeap *light_heap_1;
LightNode *light_ware_house_1;
LightHeap *light_heap_2;
LightNode *light_ware_house_2;

int max_heavy_heap_size;
HeavyHeap *heavy_heap_1;
HeavyNode *heavy_ware_house_1;
HeavyHeap *heavy_heap_2;
HeavyNode *heavy_ware_house_2;

/* This is a mapping from the ordinary characters */
/* to the numbers between 0 and 25 ('J' is excluded). */
char alphabet_mapping[128];
char number_to_alphabet[25];

int bar;

float log_probabilities[25][25];

int plain_to_cipher[25][25][2];
int cipher_to_plain[25][25][2];

/********************************************************/
/*              Light heap functions.                   */
/********************************************************/

void light_swap(LightNode **el1, LightNode **el2) {
  LightNode *temp = *el1;
  *el1 = *el2;
  *el2 = temp;
}

void down_light_heap(LightHeap *heap, int i) {
 START:
  if (i >= heap->size / 2) {
    return;
  }

  if (heap->node_ptr[i]->score > heap->node_ptr[2 * i + 1]->score) {
    if (2 * i + 2 < heap->size) {
      if (heap->node_ptr[2 * i + 1]->score <
	  heap->node_ptr[2 * i + 2]->score) {
	light_swap(&(heap->node_ptr[i]), &(heap->node_ptr[2 * i + 1]));
	i = 2 * i + 1;
	goto START;
      }
      else {
	light_swap(&(heap->node_ptr[i]), &(heap->node_ptr[2 * i + 2]));
	i = 2 * i + 2;
	goto START;
      }
    }
    else {
      light_swap(&(heap->node_ptr[i]), &(heap->node_ptr[2 * i + 1]));
      i = 2 * i + 1;
      goto START;
    }
  }
  else if ((2 * i + 2 < heap->size) &&
	   (heap->node_ptr[i]->score > heap->node_ptr[2 * i + 2]->score)) {
    light_swap(&(heap->node_ptr[i]), &(heap->node_ptr[2 * i + 2]));
    i = 2 * i + 2;
    goto START;
  }
}

void up_light_heap(LightHeap *heap, int i) {
  int parent;
  
 START:
  if (i == 0) {
    return;
  }
  
  parent = (i - 1) / 2;
  if (heap->node_ptr[i]->score < heap->node_ptr[parent]->score) {
    light_swap(&(heap->node_ptr[i]), &(heap->node_ptr[parent]));
    i = parent;
    goto START;
  }
}

void update_light_heap(LightHeap *heap, float score, char *square, int length) {
  int i, size;

  size = heap->size;
  if (size < heap->max_size) {

    heap->node_ptr[size]->score = score;
    for (i = 0; i < length; i++) {
      heap->node_ptr[size]->square[i] = square[i];
    }
    up_light_heap(heap, heap->size);
    heap->size++;

  } else if (score > heap->node_ptr[0]->score) {

    heap->node_ptr[0]->score = score;
    for (i = 0; i < length; i++) {
      heap->node_ptr[0]->square[i] = square[i];
    }
    down_light_heap(heap, 0);
  }
}
 
LightNode *light_heap_extract_min(LightHeap *heap) {
  LightNode *node;

  node = heap->node_ptr[0];
  heap->size--;
  heap->node_ptr[0] = heap->node_ptr[heap->size];
  down_light_heap(heap, 0);

  return node;
}

void init_light_heap(LightHeap **heap, LightNode **ware_house) {
  int i;
  
  if (((*heap) = malloc(sizeof(LightHeap))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for light_heap head.\n");
    exit(EXIT_FAILURE);
  }

  if (((*heap)->node_ptr = malloc(max_light_heap_size * sizeof(LightNode*))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for light heap.\n");
    exit(EXIT_FAILURE);
  }

  if (((*ware_house) = malloc(max_light_heap_size * sizeof(LightNode))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for light_ware_house.\n");
    exit(EXIT_FAILURE);
  }

  for (i = 0; i < max_light_heap_size; i++) {
    (*ware_house)[i].score = TINY;
    (*heap)->node_ptr[i] = &((*ware_house)[i]);
  }
  (*heap)->max_size = max_light_heap_size;
  (*heap)->size = 0;
}

void free_light_heap(LightHeap **heap, LightNode **ware_house) {
  free((*heap)->node_ptr);
  free((*heap));
  free((*ware_house));
}

/********************************************************/
/*              Heavy heap functions.                   */
/********************************************************/

void heavy_swap(HeavyNode **el1, HeavyNode **el2) {
  HeavyNode *temp = *el1;
  *el1 = *el2;
  *el2 = temp;
}

void down_heavy_heap(HeavyHeap *heap, int i) {
 START:
  if (i >= heap->size / 2) {
    return;
  }

  if (heap->node_ptr[i]->score > heap->node_ptr[2 * i + 1]->score) {
    if (2 * i + 2 < heap->size) {
      if (heap->node_ptr[2 * i + 1]->score <
	  heap->node_ptr[2 * i + 2]->score) {
	heavy_swap(&(heap->node_ptr[i]), &(heap->node_ptr[2 * i + 1]));
	i = 2 * i + 1;
	goto START;
      }
      else {
	heavy_swap(&(heap->node_ptr[i]), &(heap->node_ptr[2 * i + 2]));
	i = 2 * i + 2;
	goto START;
      }
    }
    else {
      heavy_swap(&(heap->node_ptr[i]), &(heap->node_ptr[2 * i + 1]));
      i = 2 * i + 1;
      goto START;
    }
  }
  else if ((2 * i + 2 < heap->size) &&
	   (heap->node_ptr[i]->score > heap->node_ptr[2 * i + 2]->score)) {
    heavy_swap(&(heap->node_ptr[i]), &(heap->node_ptr[2 * i + 2]));
    i = 2 * i + 2;
    goto START;
  }
}

void up_heavy_heap(HeavyHeap *heap, int i) {
  int parent;
  
 START:
  if (i == 0) {
    return;
  }
  
  parent = (i - 1) / 2;
  if (heap->node_ptr[i]->score < heap->node_ptr[parent]->score) {
    heavy_swap(&(heap->node_ptr[i]), &(heap->node_ptr[parent]));
    i = parent;
    goto START;
  }
}

void update_heavy_heap(HeavyHeap *heap, float score, char *square, int length) {
  int i, size;

  size = heap->size;
  if (size < heap->max_size) {

    heap->node_ptr[size]->score = score;
    for (i = 0; i < length; i++) {
      heap->node_ptr[size]->square[i] = square[i];
    }
    up_heavy_heap(heap, heap->size);
    heap->size++;

  } else if (score > heap->node_ptr[0]->score) {

    heap->node_ptr[0]->score = score;
    for (i = 0; i < length; i++) {
      heap->node_ptr[0]->square[i] = square[i];
    }
    down_heavy_heap(heap, 0);
  }
}

HeavyNode *heavy_heap_extract_min(HeavyHeap *heap) {
  HeavyNode *node;

  node = heap->node_ptr[0];
  heap->size--;
  heap->node_ptr[0] = heap->node_ptr[heap->size];
  down_heavy_heap(heap, 0);

  return node;
}


/* Initialize the heavy heaps. */ 
void init_heavy_heap(HeavyHeap **heap, HeavyNode **ware_house) {
  int i;
  
  if (((*heap) = malloc(sizeof(HeavyHeap))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for heavy_heap head.\n");
    exit(EXIT_FAILURE);
  }

  if (((*heap)->node_ptr = malloc(max_heavy_heap_size * sizeof(HeavyNode*))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for light heap.\n");
    exit(EXIT_FAILURE);
  }

  if (((*ware_house) = malloc(max_heavy_heap_size * sizeof(HeavyNode))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for heavy ware_house.\n");
    exit(EXIT_FAILURE);
  }

  for (i = 0; i < max_heavy_heap_size; i++) {
    (*ware_house)[i].score = TINY;
    (*heap)->node_ptr[i] = &((*ware_house)[i]);
  }
  (*heap)->max_size = max_heavy_heap_size;
  (*heap)->size = 0;
}

void free_heavy_heap(HeavyHeap **heap, HeavyNode **ware_house) {
  free((*heap)->node_ptr);
  free((*heap));
  free((*ware_house));
}

/********************************************************/
/*              Table building functions                */
/********************************************************/

void build_alphabet_mapping() {
  int i;

  for (i = 0; i < 128; i++) {
    if (i < 'A' || i > 'Z') {
      alphabet_mapping[i] = -1;
    } else if (i < 'J') {
      alphabet_mapping[i] = i - 'A';
    } else if (i > 'J') {
      alphabet_mapping[i] = i - 'A' - 1;
    } else { /* i == 'J' */
      alphabet_mapping[i] = -1;
    }
  }

  for (i = 0; i < 25; i++) {
    if (i < 9) {
      number_to_alphabet[i] = 'A' + i;
    } else {
      number_to_alphabet[i] = 'A' + i + 1;
    }
  }
}

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


void build_log_probs(FILE *infile) {
  int i, j, i1, i2;
  float log_prob, prob;
  char c1, c2, row[512];
  
  for (i = 0; i < 25; i++) {
    for (j = 0; j < 25; j++) {
      log_probabilities[i][j] = 0;
    }
  }

  while (fgets(row, 511, infile)) {
    if (row[0] == '#') 
      continue;
    if (sscanf(row, "%c %c: %*d %*f %f", &c1, &c2, &log_prob) == 3) {

      if (c1 == 'J') {
	i1 = alphabet_mapping[(int) 'I'];
      } else {
	i1 = alphabet_mapping[(int) c1];
      }

      if (c2 == 'J') {
	i2 = alphabet_mapping[(int) 'I'];
      } else {
	i2 = alphabet_mapping[(int) c2];
      }

      if (log_probabilities[i1][i2] == 0) {
	log_probabilities[i1][i2] = log_prob;
      } else {
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
	  log_probabilities[i][j] = -30.0;
	}

      }
    }
  }
}

/********************************************************/
/*              Calling related functions.              */
/********************************************************/

void print_usage() {
  fprintf(stderr, "Usage: heavy [-h] [-cf <filename>] [-sf <filename>] -bf <filename>\n"); 
  fprintf(stderr, "              [-sp -4..4 -4..4 0|1] [-pre <string>] -nl <int> -nh <int>\n");
  fprintf(stderr, "Type square -h for help.\n");
}

void print_help() {
  fprintf(stderr, "Usage: heavy [-h] [-cf <filename>] [-sf <filename>] -bf <filename>\n"); 
  fprintf(stderr, "              [-sp -4..4 -4..4 0|1] [-pre <string>] -nl <int> -nh <int>\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -cf <filename>  The name of the file from which to read the cipher text.\n");
  fprintf(stderr, "                  The default is stdin.\n");
  fprintf(stderr, "  -sf <filename>  The name of the file on which to write the best squares.\n");
  fprintf(stderr, "                  The default is stdout.\n");
  fprintf(stderr, "  -bf <filename>  The name of the file from which to read the bigram stats.\n");
  fprintf(stderr, "  -sp <r> <s> <h> Specifies the rowshift, colshift and if horizontal corner\n");
  fprintf(stderr, "                  shift is applied.  Default is 1, 1, 1.\n");
  fprintf(stderr, "  -pre <string>   A piece of a row int the square. Must be english caps not 'J'.\n");
  fprintf(stderr, "  -nl <int>       The number of candidates to store in the first phase.\n");
  fprintf(stderr, "  -nh <int>       The number of candidates to store in the second phase.\n");
  fprintf(stderr, "  -h              Displays this information.\n");
}

void parse_command_line(int argc, char **argv, char **c_filename, 
			char **p_filename, char **b_filename,
			int *rowshift, int *colshift, int *horizontal,
			int **preset, int **sorted_preset, int *n_preset) {
  int i, j, k, tmp;

  *c_filename = NULL;
  *p_filename = NULL;
  *b_filename = NULL;
  *rowshift = 1;
  *colshift = 1;
  *horizontal = 1;
  *preset = NULL;
  *sorted_preset = NULL;
  *n_preset = 0;
  max_light_heap_size = 0;
  max_heavy_heap_size = 0;

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
      (*p_filename) = strdup(argv[i]);
    } else if (!strcmp("-bf", argv[i])) {
      if (++i == argc) {
	print_usage(); 
	exit(EXIT_FAILURE);
      }
      (*b_filename) = strdup(argv[i]);
    } else if (!strcmp("-pre", argv[i])) {
      if (++i == argc) {
	print_usage();
	exit(EXIT_FAILURE);
      }
      *n_preset = strlen(argv[i]);
      (*preset) = malloc((*n_preset) * sizeof(int));
      (*sorted_preset) = malloc((*n_preset) * sizeof(int));
      for (j = 0; j < (*n_preset); j++) {
	(*preset)[j] = alphabet_mapping[(int) toupper(argv[i][j])];
	(*sorted_preset)[j] = (*preset)[j];
	if ((*preset)[j] < 0) {
	  fprintf(stderr, "Error: Illegal preset string: %s\n", argv[i]);
	  exit(EXIT_FAILURE);
	}
      }
      for (j = 0; j < (*n_preset); j++) {
	for (k = j + 1; k < (*n_preset); k++) {
	  if ((*sorted_preset)[k] < (*sorted_preset)[j]) {
	    tmp = (*sorted_preset)[j];
	    (*sorted_preset)[j] = (*sorted_preset)[k];
	    (*sorted_preset)[k] = tmp;
	  }
	}
      }
    } else if (!strcmp("-nl", argv[i])) {
      if (++i == argc || sscanf(argv[i], "%d", &max_light_heap_size) != 1) {
	print_usage();
	exit(EXIT_FAILURE);
      }
    } else if (!strcmp("-nh", argv[i])) {
      if (++i == argc || sscanf(argv[i], "%d", &max_heavy_heap_size) != 1) {
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

  if (max_light_heap_size == 0 || max_heavy_heap_size == 0) {
    print_usage();
    exit(EXIT_FAILURE);
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
}

/********************************************************/
/*              I/O functions.                          */
/********************************************************/

/* Reads text from a file and stores it as numbers from 0 to 25. */
/* The letter 'J' should not be present. */
int read_text(FILE *infile, char **text) {
  char row[2048];
  int length = 512;
  int i, n = 0;

  if (((*text) = malloc(length * sizeof(char))) == NULL) {
    fprintf(stderr, "Error: Unable to allocate memory for the cipher text.\n");
    exit(EXIT_FAILURE);
  }
  while (fgets(row, 2047, infile)) {

    for (i = 0; i < strlen(row); i++) {

      if (isalpha(row[i])) {
	(*text)[n++] = alphabet_mapping[toupper(row[i])];

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

void print_logtable(FILE* outfile) {
  int i, j;
  
  for (i = 0; i < 25; i++) {
    for (j = 0; j < 25; j++) {
      fprintf(outfile, "%c %c: %e\n", number_to_alphabet[i], number_to_alphabet[j], log_probabilities[i][j]);
    }
  }
}

/********************************************************/
/*              Cipher specific functions.              */
/********************************************************/

float find_mean_score(char *square, int square_size) {
  int i, j, m;
  int ci_first, ci_last, p_first, p_last;
  const int *pair;
  float score, add;

  m = 0;
  score = 0;

  /* We should not include bigrams from the sub set. */
  for (i = 0; i < square_size; i++) {
    for (j = i + 1; j < square_size; j++) {
      pair = plain_to_cipher[i][j];
      ci_first = pair[0];
      ci_last = pair[1];
      
      /* We should not include bigrams from the sub set. */
      if (ci_first < square_size && ci_last < square_size) {
	p_first = square[i];
	p_last = square[j];
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


float score_square(char *cipher_text, int text_length, char *square, 
		   char *inv_square, int square_size, double mean) {
  int i, bigs;
  int ci_first, ci_last, p_first, p_last, last;
  const int *pair;
  float score;
  
  last = -1;
  score = 0.0;
  bigs = 0;
  for (i = 0; i < text_length; i += 2) {
    /* Find the i:th and i+1:st square index in the cipher text. */
    ci_first = inv_square[(int) cipher_text[i]];
    ci_last = inv_square[(int) cipher_text[i + 1]];

    if (ci_first < square_size && ci_last < square_size) {
      /* None of the cipher text characters are in the unsafe subset. */

      /* Find the corresponding plain text positions. */
      pair = cipher_to_plain[ci_first][ci_last];

      if (pair[0] < square_size && pair[1] < square_size) {
	/* None of the plain text characters are among the unsafe. */

	p_first = square[pair[0]];
	p_last = square[pair[1]];

	score += log_probabilities[p_first][p_last];
	bigs++;

	if (last >= 0) {
	  /* If we substituted the previous bigram we have to */
	  /* score the overlapping bigram. */
	  score += log_probabilities[last][p_first];
	  bigs++;
	}
	
	/* Set last to be the shifted representation of the last character. */
	last = p_last;
      } else {

	/* No substitution was made. */
	last = -1;
      }
    }
  }

  return score - mean * bigs; 
}

/********************************************************/
/*                The main function.                    */
/********************************************************/

int main(int argc, char *argv[]) {
  int i, j, text_length;
  
  char *c_filename, *s_filename, *b_filename;
  FILE *c_file, *s_file, *b_file;

  int rowshift, colshift, horizontal;
  int *preset, *sorted_preset, n_preset;

  char c1 = -1, c2, c3, c4, c5, c6;

  char *cipher_text;
  char *square, *inv_square;
  int square_size;

  float score, mean_score;

  int begin_with_light_heap;
  
  LightHeap *new_light_heap = NULL, *old_light_heap = NULL, *tmp_l;
  HeavyHeap *new_heavy_heap = NULL, *old_heavy_heap = NULL, *tmp_h;
  HeavyNode *h_node;
  LightNode *l_node;

  /* Initialize table used in parse_command_line. */
  build_alphabet_mapping();
  
  parse_command_line(argc, argv, &c_filename, &s_filename, &b_filename,
		     &rowshift, &colshift, &horizontal, &preset, &sorted_preset, &n_preset);

  if (n_preset < 9) {
    begin_with_light_heap = 1;
  } else {
    begin_with_light_heap = 0;
  }

  fprintf(stdout, "Number of preset characters: %d\n", n_preset);


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
  
  /* Initialize some tables. */
  build_substitution_tables(rowshift, colshift, horizontal);

  /* Build the tables for log probabilities. */
  build_log_probs(b_file);

/*   print_logtable(stderr); */
  
  /* Allocate the cipher text array and store the cipher */
  /* text read from c_file in it. */
  text_length = read_text(c_file, &cipher_text);

  /* Initialize the light heaps for the first step of the algorithm. */
  if (begin_with_light_heap) {
    init_light_heap(&light_heap_1, &light_ware_house_1);
    init_light_heap(&light_heap_2, &light_ware_house_2);
    new_light_heap = light_heap_1;
    old_light_heap = light_heap_2;
  } else {
    init_heavy_heap(&heavy_heap_1, &heavy_ware_house_1);
    init_heavy_heap(&heavy_heap_2, &heavy_ware_house_2);
    new_heavy_heap = heavy_heap_1;
    old_heavy_heap = heavy_heap_2;
  }
  
  /* Allocate the initial square and set the initial chars in */
  /* The 7 first cells. The first cell will always contain the */
  /* number 4 (letter 'E'). */
  if ((square = malloc(25 * sizeof(char))) == NULL) {
    fprintf(stderr, "Unable to allocate memory for the square.\n");
    exit(EXIT_FAILURE);
  }
  if ((inv_square = malloc(25 * sizeof(char))) == NULL) {
    fprintf(stderr, "Unable to allocate memory for the inverted square.\n");
    exit(EXIT_FAILURE);
  }
  
  /* Set the preset letters in the square. */
  for (i = 0; i < n_preset; i++) {
    square[i] = preset[i];
  }
  square_size = n_preset;

  /* Here we try all permutations of all subsets of size 6 of */
  /* the letters available. */
  square_size += 6; 
  for (c1 = 0; c1 < 25; c1++) {

    for (i = 0; i < n_preset; i++) {
      if (c1 == preset[i])
	break;
    }
    if (i < n_preset)
      continue;

    square[square_size - 6] = c1;
    
    for (c2 = 0; c2 < 25; c2++) {

      if (c2 == c1) 
	continue;

      for (i = 0; i < n_preset; i++) {
	if (c2 == preset[i])
	  break;
      }
      if (i < n_preset)
	continue;

      square[square_size - 5] = c2;

      for (c3 = 0; c3 < 25; c3++) {

	if  (c3 == c2 || c3 == c1) 
	  continue;

	for (i = 0; i < n_preset; i++) {
	  if (c3 == preset[i])
	    break;
	}
	if (i < n_preset)
	  continue;
	
	square[square_size - 4] = c3;
	
	for (c4 = 0; c4 < 25; c4++) {

	  if (c4 == c1 || c4 == c2 || c4 == c3) 
	    continue;

	  for (i = 0; i < n_preset; i++) {
	    if (c4 == preset[i])
	      break;
	  }
	  if (i < n_preset)
	    continue;

	  square[square_size - 3] = c4;
	  
          for (c5 = 0; c5 < 25; c5++) {

	    if (c5 == c1 || c5 == c2 || c5 == c3 || c5 == c4) 
	      continue;

	    for (i = 0; i < n_preset; i++) {
	      if (c5 == preset[i])
		break;
	    }
	    if (i < n_preset)
	      continue;

	    square[square_size - 2] = c5;
	  
	    for (c6 = 0; c6 < 25; c6++) {

	      if (c6 == c1 || c6 == c2 || c6 == c3 || c6 == c4 || c6 == c5) 
		continue;

	      for (i = 0; i < n_preset; i++) {
		if (c6 == preset[i])
		  break;
	      }
	      if (i < n_preset)
		continue;

	      square[square_size - 1] = c6;

	      /* Fill in the inv_square. */
	      for (i = 0; i < 25; i++) {
		inv_square[i] = square_size; 
	      }
	      for (i = 0; i < square_size; i++) {
		inv_square[(int) square[i]] = i;
	      }

	      /* Calculate the mean score of all bigrams that can be created. */
	      mean_score = find_mean_score(square, square_size);

	      /* Find the score for the cipher text. */
	      score = score_square(cipher_text, text_length, square, 
				   inv_square, square_size, mean_score);
	      
	      if (begin_with_light_heap) {
		update_light_heap(new_light_heap, score, square, square_size); 
	      } else {
		update_heavy_heap(new_heavy_heap, score, square, square_size); 
	      }
	    }
	  }
	}
      }
    }
  }
    

#ifdef DEBUG
    if (begin_with_light_heap) {
      while (new_light_heap->size > 0) {
	l_node = light_heap_extract_min(new_light_heap);
	for (i = 0; i < square_size; i++) {
	  fprintf(s_file, "%c", number_to_alphabet[(int) (l_node->square[i])]);
	}
	fprintf(s_file, ": %e\n", l_node->score);
      }
      exit(0);
    } else {
      while (new_heavy_heap->size > 0) {
	h_node = heavy_heap_extract_min(new_heavy_heap);
	for (i = 0; i < square_size; i++) {
	  fprintf(s_file, "%c", number_to_alphabet[(int) (h_node->square[i])]);
	}
	fprintf(s_file, ": %e\n", h_node->score);
      }
      exit(0);
    }
#endif
    

  /* If we can use the light heap in the beginning of our calculations. */
  if (begin_with_light_heap) {

    /* Now we begin the next phase where we add an element to */
    /* each of the squares we have saved and once again save the */
    /* best candidates. Iterate until we have built so much that */
    /* we have to change heap. */
    for ( ; square_size < 16; square_size++) {
      
      /* We want to see where we are */
      fprintf(stderr, "Square size: %d\n", square_size);
      
      /* swap the two heaps. */
      tmp_l = new_light_heap; 
      new_light_heap = old_light_heap;
      old_light_heap = tmp_l;
      
      /* Null the new heap. */
      new_light_heap->size = 0;
      
      /* Prepare for a heap change. */
      if (square_size == 15) {
	new_light_heap->max_size = max_heavy_heap_size;
      }
      
      /* Go through the heap beginning somewhere deep down. */
      for (i = old_light_heap->size - 1; i >= 0; i--) {
	
	/* Extract the square. */
	for (j = 0; j < square_size; j++) {
	  square[j] = old_light_heap->node_ptr[i]->square[j];
	}
	
	/* Compute the inverted square. */
	for (j = 0; j < 25; j++) {
	  inv_square[j] = square_size + 1; 
	}
	for (j = 0; j < square_size; j++) {
	  inv_square[(int) square[j]] = j;
	}
      
	/* Try all possible choices for the next letter. */
	for (j = 0; j < 25; j++) {

	  /* Do not try the ones that are already in the square. */
	  if (inv_square[j] < square_size) 
	    continue;
	
	  /* Add the letter to the square and update the inv_square. */
	  square[square_size] = j;
	  inv_square[j] = square_size;
	
	  /* Find the mean score. Maybe an approximated value */
	  /* would do. Then this could be done once for all choices */
	  /* of the last letter. */
	  mean_score = find_mean_score(square, square_size + 1);
	
	  /* Find the score for the cipher text. */
	  score = score_square(cipher_text, text_length, square, 
			       inv_square, square_size + 1, mean_score);
		
	  update_light_heap(new_light_heap, score, square, square_size + 1); 
	}
      }
    }

    /* Change heap type  and copy the contents of */
    /* new_light_heap to new_heavy_heap. */  
    fprintf(stderr, "Changing heaps...\n");

    /* Free the old light heap. */
    if (old_light_heap == light_heap_1) {
      free_light_heap(&light_heap_1, &light_ware_house_1);
    } else {
      free_light_heap(&light_heap_2, &light_ware_house_2);
    }
    old_light_heap = NULL;

    /* Allocate a new heavy heap. */
    init_heavy_heap(&heavy_heap_1, &heavy_ware_house_1);
    new_heavy_heap = heavy_heap_1;

    while (new_light_heap->size > 0) {
      l_node = light_heap_extract_min(new_light_heap);
      for (i = 0; i < square_size; i++) {
	square[i] = l_node->square[i];
      }
      update_heavy_heap(new_heavy_heap, l_node->score, square, square_size);
    }

    /* Free the new light heap. */
    if (new_light_heap == light_heap_1) {
      free_light_heap(&light_heap_1, &light_ware_house_1);
    } else {
      free_light_heap(&light_heap_2, &light_ware_house_2);
    }
    new_light_heap = NULL;

    /* Allocate the old heavy heap. */
    init_heavy_heap(&heavy_heap_2, &heavy_ware_house_2);  
    old_heavy_heap = heavy_heap_2;

    fprintf(stderr, "Done.\n");
  }

  /* Continue the calculations with the heavy heap instead. */
  for ( ; square_size < 25; square_size++) {
    /* We want to see where we are */
    fprintf(stderr, "Square size: %d\n", square_size);

    /* swap the two heaps. */
    tmp_h = new_heavy_heap;
    new_heavy_heap = old_heavy_heap; 
    old_heavy_heap = tmp_h;

    /* Null the new heap. */
    new_heavy_heap->size = 0;

    if (square_size == 24) {
      new_heavy_heap->max_size = 100;
    }
    
    /* Go through the heap beginning somewhere deep down. */
    for (i = old_heavy_heap->size - 1; i >= 0; i--) {

      /* Extract the square. */
      for (j = 0; j < square_size; j++) {
	square[j] = old_heavy_heap->node_ptr[i]->square[j];
      }
      
      /* Compute the inverted square. */
      for (j = 0; j < 25; j++) {
	inv_square[j] = square_size + 1; 
      }
      for (j = 0; j < square_size; j++) {
	inv_square[(int) square[j]] = j;
      }
      
      /* Try all possible choices for the next letter. */
      for (j = 0; j < 25; j++) {
	
	/* Do not try the ones that are already in the square. */
	if (inv_square[j] < square_size)
	  continue;
	
	/* Add the letter to the square and update the inv_square. */
	square[square_size] = j;
	inv_square[j] = square_size;
	
	/* Find the mean score. */
	mean_score = find_mean_score(square, square_size + 1);
	
	/* Find the score for the cipher text. */
	score = score_square(cipher_text, text_length, square, 
			     inv_square, square_size + 1, mean_score);
		
	update_heavy_heap(new_heavy_heap, score, square, square_size + 1); 
      }
    }
  }

  /* Output the best solutions. */
  while (new_heavy_heap->size > 0) {
    h_node = heavy_heap_extract_min(new_heavy_heap);
    for (i = 0; i < 25; i++) {
      fprintf(s_file, "%c", number_to_alphabet[(int) h_node->square[i]]);
    }
    fprintf(s_file, ": %e\n", h_node->score);
  }

  exit(EXIT_SUCCESS);
}


