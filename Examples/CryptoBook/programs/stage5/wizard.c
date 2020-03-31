/******************************************************************/
/*                                                                */
/*   File:        wizard.c                                        */
/*   Author:      Lars Ivansson                                   */
/*   Created:     April 20, 2000                                  */
/*   Modified:    October 17, 2000                                */
/*   Description: This program solves stage 5 in the cipher       */
/*                challange.                                      */
/*                                                                */
/*                To use this program a dictionary file is        */
/*                needed. The default path to this file is        */
/*                hard coded in the program. This file is just    */
/*                a file with words sorted in alphabetic order.   */
/*                There should be one word on each line.          */
/*                hard coded in the program.                      */
/*                                                                */
/*                                                                */
/******************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <limits.h>
#include "trie.h"

#define evaluate evaluate_sq
#define EXHAUSTIVE

#define MAX(A, B) ((A > B) ? A : B)

#define MIN(A, B) ((A < B) ? A : B)

#define SAFE_MALLOC(v, n) { if (((v) = malloc((n))) == NULL) { \
    fprintf(stderr, "Unable to allocate %dB memory for variable %s\n", \
	    (n), #v); \
    fprintf(stderr, "File: %s. Line: %d\n",__FILE__, __LINE__); \
    exit(EXIT_FAILURE); \
  } \
}

#define SAFE_REALLOC(v, n) { if (((v) = realloc((v),(n))) == NULL) { \
    fprintf(stderr, "Unable to allocate %dB memory for variable %s\n", \
	    (n), #v); \
    fprintf(stderr, "File: %s. Line: %d\n",__FILE__, __LINE__); \
    exit(EXIT_FAILURE); \
  } \
}

#undef isalpha
#undef isspace
#undef isalnum
#undef ispunct
#undef toupper
#undef tolower

/********************************************************/
/*                  Global variables.                   */
/********************************************************/

const char* dictionary_file=".";

int *cipher;
int cipher_length;
int cipher_max; 

char *plain_text;
int *btr;
int *wl;
int *scores;

/********************************************************/
/*                      Typedefs                        */
/********************************************************/

typedef enum {SUCCESS, EOT, ENLARGE_TEXT} t_status;

/********************************************************/
/*              Calling related functions.              */
/********************************************************/

void print_usage() {
  fprintf(stderr, "Usage: wizard [-h] [-bf <filename>] [-pf <filename>]\n");
  fprintf(stderr, "              [-df <filename>] [-cf <filename>]\n"); 
  fprintf(stderr, "Type wizard -h for help.\n");
}

void print_help() {
  fprintf(stderr, "Usage: wizard [-h] [-bf <filename>] [-pf <filename>]\n");
  fprintf(stderr, "              [-df <filename>] [-cf <filename>]\n"); 
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -bf <filename>  The name of the file from which to read the book text.\n");
  fprintf(stderr, "                  The default is stdin.\n");
  fprintf(stderr, "  -pf <filename>  The name of the file on which to write the output text.\n");
  fprintf(stderr, "                  The default is stdout.\n");
  fprintf(stderr, "  -df <filename>  The name of the dictionary file used to identify plain text.\n");
  fprintf(stderr, "                  The default is /X/X/X.\n");
  fprintf(stderr, "  -cf <filename>  The name of the cipher file containing the magic numbers.\n");
  fprintf(stderr, "                  The default numbers are from stage 5 in the CipherChallange.\n");
  fprintf(stderr, "  -h              Displays this information.\n");
}

void parse_command_line(int argc, 
			char **argv, 
			char **b_filename,
			char **p_filename, 
			char **d_filename,
			char **c_filename) {
  int i;

  *b_filename = NULL;
  *p_filename = NULL;
  *d_filename = NULL;
  *c_filename = NULL;

  for (i = 1; i < argc; i++) {
    if (!strcmp("-bf", argv[i])) {
      if (++i == argc) {
        print_usage(); 
        exit(EXIT_FAILURE);
      }
      (*b_filename) = strdup(argv[i]);
    } else if (!strcmp("-pf", argv[i])) {
      if (++i == argc) {
        print_usage(); 
        exit(EXIT_FAILURE);
      }
      (*p_filename) = strdup(argv[i]);
    } else if (!strcmp("-df", argv[i])) {
      if (++i == argc) {
        print_usage(); 
        exit(EXIT_FAILURE);
      }
      (*d_filename) = strdup(argv[i]);
    } else if (!strcmp("-cf", argv[i])) {
      if (++i == argc) {
        print_usage(); 
        exit(EXIT_FAILURE);
      }
      (*c_filename) = strdup(argv[i]);
    } else if (!strcmp("-h", argv[i])) {
      print_help();
      exit(EXIT_SUCCESS);
    } else {
      print_usage();
      exit(EXIT_FAILURE);
    }
  }
}

void set_cipher(int *cipher, int cipher_length, ...) {
  int i;
  va_list ap;

  va_start(ap, cipher_length);
  for (i = 0; i < cipher_length; i++) {
    cipher[i] = va_arg(ap, int);
  }
  va_end(ap);
} 

void scan_cipher(char *c_filename) {

  int i, length;
  FILE *c_file;
  
  if (c_filename != NULL) {
    if ((c_file = fopen(c_filename, "r")) == NULL) {
      fprintf(stderr, "Unable to open cipher file %s for reading.\n", c_filename);
      exit(EXIT_FAILURE);
    }    
    
    length = 1024;
    SAFE_MALLOC(cipher, length * sizeof(int));
    
    cipher_length = 0;
    while (!feof(c_file)) {
      if (fscanf(c_file, "%d", &(cipher[cipher_length])) == 1) {
	cipher_length++;
      }
      
      if (cipher_length >= length) {
	length += 1024;
	SAFE_REALLOC(cipher, length * sizeof(int));
      }
    }
    SAFE_REALLOC(cipher, cipher_length * sizeof(int));
    fclose(c_file);

    cipher_max = 0;
    for (i = 0; i < cipher_length; i++) {
      if (cipher[i] > cipher_max) {
	cipher_max = cipher[i];
      }
    }

  } else {
    cipher_length = 54;
    SAFE_MALLOC(cipher, cipher_length * sizeof(int));
    set_cipher(cipher, cipher_length, 
	       109, 182, 6, 11, 88, 214, 74, 77, 153, 177, 109,
	       195, 76, 37, 188, 166, 188, 73, 109, 158, 15, 208,
	       42, 5, 217, 78, 209, 147, 9, 81, 80, 169, 109, 22,
	       96, 169, 3, 29, 214, 215, 9, 198, 77, 112, 8, 30,
	       117, 124, 86, 96, 73, 177, 50, 161);
    cipher_max = 217;
  }

 SAFE_MALLOC(plain_text, (cipher_length + 1) * sizeof(char));
 SAFE_MALLOC(scores, cipher_length * sizeof(int));
 SAFE_MALLOC(btr, cipher_length * sizeof(int));
 SAFE_MALLOC(wl, cipher_length * sizeof(int));
}


/* Something for Staffan to write. */
void build_dictionary(FILE *infile) {
  int i, length;
  char c, buffer[256];

  fprintf(stderr, "Building trie...\n");
  while (fgets(buffer, 255, infile) != NULL) {
    buffer[strlen(buffer) - 1] = 0;

    if (buffer[0] >= 'a') {
      length = strlen(buffer);
      for (i = 0; i < length; i++) {
	
	c = buffer[i];
	if (isalpha(c)) {
	  buffer[i] = toupper(c);
	} else {
	  buffer[i] = 'X';
	}
      }
      
      addtotrie(buffer);
    }
  }
  fprintf(stderr, "Done.\n");
}

/* This function reads in more text from the infile and stores it in
   the circular array: text, after the position indicated by t_last.
   The function reads the maximal amount of text that there is place
   for in the array. If there is not place for any more text when the
   function is called, the message ENLARGE_TEXT is returned.  If EOF
   is set when the function is called EOT is returned. Otherwise
   SUCCESS is returned. */
t_status read_text(FILE *infile,  
		   char *text,  
		   int t_size, 
		   int t_first,  
		   int *t_last) { 
  
  static int n_read = 0;
  int in_white; 
  char c; 

  /* If we have reached EOF, return end of text. */
  if (feof(infile)) {
    return EOT;
  }
  
  /* If the index for the last character is the one before the index
     for the first character we need to allocate more memory. This
     should not happen very often, since the words must be extremely
     long for this to occur. */
  if (((*t_last) + 1) % t_size == t_first) {
    return ENLARGE_TEXT;
  }

  /* If the last character read was white space we are within white
     space, otherwise not. */
  if (text[(*t_last)] == ' ') {
    in_white = 1;
  } else {
    in_white = 0;
  }

  /* Increase t_last and start reading text. */
  (*t_last) = ((*t_last) + 1) % t_size;
  while ((c = fgetc(infile)) != EOF) { 

    n_read++;
    if (n_read % 10000 == 0) {
      fprintf(stderr, "Characters read: %d\n", n_read);
    } 

    if (in_white == 1) {

      /* We store the character only when it is an alpha numerical
	 character. */
      if (isalnum(c)) {
 
	in_white = 0;
	text[(*t_last)] = c;
	(*t_last) = ((*t_last) + 1) % t_size; 
      }

    } else { /* in_white == 0 */

      if (isspace(c)) {

	/* An ispunct-character (should always be a hash mark) followed
	   by white space should be removed. */
	if (ispunct(text[(*t_last) - 1])) {

	  text[(*t_last) - 1] = ' ';	

	} else {
	  
	  /* All white space should be converted into a single space. */
	  text[(*t_last)] = ' ';
	  (*t_last) = ((*t_last) + 1) % t_size; 
	}
	
	in_white = 1;

      } else if (ispunct(c)) {
	
	/* An ispunct-character is replaced by a hash mark or a dash. 
	   Sequences of such caracters are reduced to a single hash mark. */
	if (isalnum(text[(*t_last) - 1])) {
	  
	  if (c == '-') {
	    text[(*t_last)] = '-';	
	    (*t_last) = ((*t_last) + 1) % t_size; 
	  } else {
	    text[(*t_last)] = '#';	
	    (*t_last) = ((*t_last) + 1) % t_size; 
	  }
	} else {
	  text[(*t_last) - 1] = '#';	
	}

      } else {

	/* Ordinary alpha numeric character. Store it! */
	text[(*t_last)] = c;	
	(*t_last) = ((*t_last) + 1) % t_size; 
      }
    }

    /* If we have reached the index for t_first, we back of one step
       and return SUCCESS. */
    if ((*t_last) == t_first) {
      (*t_last) = ((*t_last) + t_size - 1) % t_size;
      return SUCCESS;
    }
  }

  return SUCCESS;
}

/* This function evaluates the plain text that can be obtained using
   the indices from the array words in the array text. If we do not
   just want to look at the initial character we may have to read more
   text.  Therefore all text-related parameters are passed to the
   function. The function returns SUCCESS or ENLARGE_TEXT depending on
   how the evaluation terminated. */
t_status evaluate_plain_text(FILE *outfile, 
			     int *words, 
			     char *text, 
			     int t_size,
			     int t_first, 
			     int *t_last) {

  int i, counter, score;
  char c;

  /* Counting from the beginning of the text. */
  for (i = 0; i < cipher_length; i++) { 
    c = toupper(text[words[cipher[i] - 1]]);
    if (isalpha(c)) {
      plain_text[i] = c;
    } else {
      plain_text[i] = 'X';
    }
  }
  plain_text[cipher_length] = 0;
  
  if ((score = evaluate(plain_text, scores, btr)) > 16 * cipher_length / 5) {
    fprintf(stderr, "%d: %s\n    ", score, plain_text);
    fprintf(outfile, "%d: %s\n    ", score, plain_text);

    counter = 0;
    for (i = cipher_length - 1; btr[i] > -1; i = btr[i]) {
      wl[counter++] = i - btr[i];
    }
    wl[counter] = i;
    
    for (i = counter; i > 0; i--) {
      wl[i - 1] += wl[i];
    }

    score = 0;
    for (i = 0; i < cipher_length; i++) {
      fprintf(stderr, "%c", plain_text[i]);
      fprintf(outfile, "%c", plain_text[i]);
      if (wl[counter] == i) {
	fprintf(stderr, "(%d)", (int) sqrt(scores[i] - score));
	fprintf(outfile, "(%d)", (int) sqrt(scores[i] - score));
	score = scores[i];
	counter--;
      }
    }
    fprintf(stderr, "\n");
    fprintf(outfile, "\n");
  }

  /* Counting from the end of the text. */
  for (i = 0; i < cipher_length; i++) { 
    c = toupper(text[words[cipher_max - cipher[i]]]);
    if (isalpha(c)) {
      plain_text[i] = c;
    } else {
      plain_text[i] = 'X';
    }
  }
  plain_text[cipher_length] = 0;

  if ((score = evaluate(plain_text, scores, btr)) > 16 * cipher_length / 5) {
    fprintf(stderr, "%d: %s\n    ", score, plain_text);
    fprintf(outfile, "%d: %s\n    ", score, plain_text);

    counter = 0;
    for (i = cipher_length - 1; btr[i] > -1; i = btr[i]) {
      wl[counter++] = i - btr[i];
    }
    wl[counter] = i;
    
    for (i = counter; i > 0; i--) {
      wl[i - 1] += wl[i];
    }

    score = 0;
    for (i = 0; i < cipher_length; i++) {
      fprintf(stderr, "%c", plain_text[i]);
      fprintf(outfile, "%c", plain_text[i]);
      if (wl[counter] == i) {
	fprintf(stderr, "(%d)", (int) sqrt(scores[i] - score));
	fprintf(outfile, "(%d)", (int) sqrt(scores[i] - score));
	score = scores[i];
	counter--;
      }
    }
    fprintf(stderr, "\n");
    fprintf(outfile, "\n");
  }

  /* Maybe we should look at the last character in each word as
     well. And use ceasar shift as well. */

  return SUCCESS;
}

/* This function tries all possible ways of counting words in the text
   starting from the index given by words[w_current - 1] in the array
   text. When a branching point is reached it makes a recursive call
   for the other branch and then continues with the main branch. When
   the beginning of all words related to this offset is found, the
   evaluation function is called. The function returns ENLARGE_TEXT,
   EOT or SUCCESS depending on what has happend during the
   execution. */
t_status search(FILE *infile, 
		FILE *outfile, 
		int *words, 
		int w_current,
		char *text, 
		int t_size,
		int t_first, 
		int *t_last,
		int depth) {
  
  int t_index;
  t_status status;

  t_index = words[w_current - 1]; 

  while (w_current < cipher_max) {

    /* See if we must scan more text. */
    if (t_index == (*t_last)) {

      status = read_text(infile, text, t_size, t_first, t_last);
      if (status == ENLARGE_TEXT) {
	return ENLARGE_TEXT;
      } else if (status == EOT) {
	return EOT;
      }
    }

    /* Which character are we looking at? */
    if (text[t_index] == ' ') {
      
      /* Here we have reached the end of a word. We set the index
	 words[w_current] to be the index of the next character and
	 increase the w_current counter. */
      words[w_current] = (t_index + 1) % t_size;
      w_current++;
	
    } else if (text[t_index] == '-') {

      /* Here we have reached a potential end-of-word and therefore we
	 make a branch. */
      if (depth < 5) {
	depth++;
	words[w_current] = (t_index + 1) % t_size;
	status = search(infile, outfile,
			words, w_current + 1,
			text, t_size, t_first, t_last, 
			depth);
	if (status == ENLARGE_TEXT) {
	  return ENLARGE_TEXT;
	}

      } else { /* depth >= 5 */

	words[w_current] = (t_index + 1) % t_size;
	w_current++;
      }

    } else if (text[t_index] == '#' && depth < 5) {

      /* Here we have reached a potential end-of-word and therefore we
	 make a branch. */
#ifdef EXHAUSTIVE
      depth++;
      words[w_current] = (t_index + 1) % t_size;
      status = search(infile, outfile,
		      words, w_current + 1,
		      text, t_size, t_first, t_last,
		      depth);
      if (status == ENLARGE_TEXT) {
	return ENLARGE_TEXT;
      }
#endif
    }  
    
    /* Increase the index counter for the next lap of the loop. */
    t_index = (t_index + 1) % t_size;
  }

  /* See if we should scan some more text. */
  if (t_index == (*t_last)) {
    
    status = read_text(infile, text, t_size, t_first, t_last);
    if (status == ENLARGE_TEXT) {
      return ENLARGE_TEXT;
    } else if (status == EOT) {
      return EOT;
    }
  }
  
  /* Now we have all information needed to compute the plain text.
     We therfore call evaluate_plain_text to do this. */
  status = evaluate_plain_text(outfile, words, 
			       text, t_size, t_first, t_last);
  if (status == ENLARGE_TEXT) {
    return ENLARGE_TEXT;
  }

  return SUCCESS;
}

/* This function monitors the decryption of the book cipher. */
void decrypt(FILE *infile, FILE *outfile) {
  int i;
  t_status status;
  int *words;
  int w_current;
  int w_size;
  char *text;
  int t_size, t_first, t_last;
  int next_found;

  /* First we allocate a circular array to store the text in as we
     read on during the decryption. */
  t_size = 65536;
  SAFE_MALLOC(text, t_size * sizeof(char));

  /* To read the initial block of text we need to do some dirty tricks
     in order to use the read_text function. After these statements
     the index of the first character in the text will be 1, the
     index of the last character will be 0, and the whole array
     will be full (unless we reach eof). */
  t_first = 0; t_last = 0;
  text[0] = ' ';
  read_text(infile, text, t_size, t_first, &t_last);
  t_first = 1;

  /* Now we allocate room for indices for the inital letters in the
     first 256 words in the text, counted from the index t_first. 
     if the cipher text should have higher numbers than 256 the size must be
     changed accordingly. */
  w_size = cipher_max + 1;
  SAFE_MALLOC(words, w_size * sizeof(int));
  words[0] = t_first;
  w_current = 1;

  /* Now we try to read from all possible offsets in the text until we
     reach the end of the text. */
  status = SUCCESS;
  while (status != EOT) {
    
    status = search(infile, outfile, 
		    words, w_current,
		    text, t_size, t_first, &t_last, 0);

    if (status == ENLARGE_TEXT) {
      
      /* Here we have reached a point where the size of text does not
	 suffice. This should be a very rare event and therefore we
	 throw a warning. */
      fprintf(stderr, "Warning: text is enlarged. This could mean a bug.\n");

      /* We reallocate a twice as large array. */
      SAFE_REALLOC(text, 2 * t_size * sizeof(char));
      
      /* We have to move the wrap-arround characters to the end of the
	 array. */
      for (i = 0; i < t_first; i++) {
	text[(t_size + i) % (2 * t_size)] = text[i];
      } 

      /* We have to change the indices to match the new positions
	 of the characters in the array text. */
      for (i = 0; i < w_size; i++) {
	if (words[i] < t_first) {
	  words[i] = (t_size + words[i]) % (2 * t_size);
	}
      }
      
      /* We have to compute the new value for t_last. */
      if (t_last < t_first) {
	t_last = t_size + t_last;
      }
      
      /* And finally compute the new value of t_size. */
      t_size *= 2;

    } else if (status == SUCCESS) {

      /* Now the current offset is tested. */

      /* Find the next word to start counting from. There must be such
	 a word already in the text array since we had a successful
	 return from search. */
      next_found = 0;
      while (!next_found) {
	
	if (text[t_first] == ' ') {
	  next_found = 1;
	} else if (text[t_first] == '-') {
	  next_found = 1;
	} else if (text[t_first] == '#') {
#ifdef EXHAUSTIVE
	  next_found = 1;
#endif	  
	}
	t_first = (t_first + 1) % t_size;
      }

      /* Set the new index of the first word, and prepare for the
	 trial of the new offset in the text. */
      words[0] = t_first;
      w_current = 1;
    }
  }
  
}

/********************************************************/
/*                The main function.                    */
/********************************************************/

int main(int argc, char *argv[]) {

  char *b_filename, *p_filename, *d_filename, *c_filename;
  FILE *b_file, *p_file, *d_file;

  parse_command_line(argc, argv, &b_filename,
		     &p_filename, &d_filename, &c_filename); 

  if (b_filename != NULL) {
    if ((b_file = fopen(b_filename, "r")) == NULL) {
      fprintf(stderr, "Unable to open book file %s for reading.\n", b_filename);
      exit(EXIT_FAILURE);
    }
  } else {
    b_file = stdin;
  }

  if (p_filename != NULL) {
    if ((p_file = fopen(p_filename, "w")) == NULL) {
      fprintf(stderr, "Unable to open output file %s for writing.\n", p_filename);
      exit(EXIT_FAILURE);
    }
  } else {
    p_file = stdout;
  }

  if (d_filename == NULL) {
    d_filename = strdup(dictionary_file);
  }
  if ((d_file = fopen(d_filename, "r")) == NULL) {
    fprintf(stderr, "Unable to open dictionary file %s for reading.\n", d_filename);
    exit(EXIT_FAILURE);
  }
  
  scan_cipher(c_filename);
  build_dictionary(d_file);
  decrypt(b_file, p_file);


  fprintf(stderr, "\n");
  exit(EXIT_SUCCESS);
}


