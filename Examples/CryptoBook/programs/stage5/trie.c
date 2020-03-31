#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include "trie.h"

#define SAFE_CALLOC(v, n, s) { if (((v) = calloc((n), (s))) == NULL) { \
    fprintf(stderr, "Unable to allocate %dB memory for variable %s\n", \
	    (n)*(s), #v); \
    fprintf(stderr, "File: %s. Line: %d\n",__FILE__, __LINE__); \
    exit(EXIT_FAILURE); \
  } \
}

struct trienode {
  char ending;
  struct trienode *p[26]; 
};

struct trienode rootnode = { };

struct trienode *root = &rootnode;

char triepos[] = "01234567891123456789212345678931234567894123456789512345678961234ABCDEFGHIJKLMNOPQRSTUVWXYZ";

int memleft = 0;
struct trienode *mem;

struct trienode *getmem(void) {
  if (!memleft) {
    SAFE_CALLOC(mem, 100000, sizeof(*mem));
    memleft = 100000;
  }
  return mem + --memleft;
}

void addtotrie(char *u) {
  int index;
  struct trienode *p = root;
  char *tmp = u;

  while (*tmp) {
    index = triepos[(int)*tmp++] - 'A';
    if (!(p->p[index]))
      p->p[index] = getmem();
    p = p->p[index];
  }
  p->ending = 1;
}


int triefindmaxprefix(char *finds, int *ending) {
  int index, l = 0;
  struct trienode *p = root;
  char *tmp = finds;

  while (*tmp) {
    index = triepos[(int)*tmp++] - 'A';
    if (p->p[index]) {
      p = p->p[index];
      l++;
    } else
      break;
  }

  (*ending) = p->ending;

  return l;
}

int triefind(char *finds, int minl) {
  int index, l = 0;
  struct trienode *p = root;
  char *tmp = finds;

  while (*tmp) {
    index = triepos[(int)*tmp++] - 'A';
    if (p->p[index]) {
      p = p->p[index];
      l++;
    } else
      break;
  }

  return l >= minl;
}


int triefindsubstr(char *s, int l) {
  int found = 0;

  for (; *s; s++)
    if (triefind(s, l))
      found = 1;

  return found;
}


int **isword = NULL;
int **isprefix = NULL;
int psl = 0;

void enlarge() {
  int i;
  for (i = 0; i < psl; i++) {
    free(isword[i]);
    free(isprefix[i]);
  }
  free(isword);
  free(isprefix);
  psl += 1024;
  SAFE_CALLOC(isword, psl, sizeof(int*));
  SAFE_CALLOC(isprefix, psl, sizeof(int*));
  for (i = 0; i < psl; i++) {
    SAFE_CALLOC(isword[i], psl, sizeof(int));
    SAFE_CALLOC(isprefix[i], psl, sizeof(int));
  }
}

int evaluate_sq(char *s, int *scores, int *btr) {
  int i, j, index, length;
  char *tmp;
  int score, subscore;
  struct trienode *p = root;

  
  length = strlen(s);
  if (length > psl) {
    enlarge();
  }


  for (i = 0; i < length; i++) {
    tmp = &(s[i]);    
    p = root;

    for (j = i; j < length; j++) {
      index = triepos[(int)*tmp++] - 'A';
      if (p->p[index]) {
	p = p->p[index];
      } else {
	break;
      }
      isword[i][j] = p->ending;
      isprefix[i][j] = 1;
    }
    for ( ; j < length; j++) {
      isword[i][j] = 0;
      isprefix[i][j] = 0;
    }
  }

  for (i = 0; i < length; i++) {

    if (isword[0][i]) {
      subscore = i + 1;
    } else {
      subscore = 0;
    }

    if (subscore > 2) {
      scores[i] = subscore * subscore;
    } else {
      scores[i] = 0;
    }
    btr[i] = -1;
    
    for (j = 0; j < i; j++) {

      if (isword[j + 1][i]) {
	subscore = i - j;
      } else {
	subscore = 0;
      }
      if (subscore > 2) {
	score = scores[j] + subscore * subscore;
      } else {
	score = scores[j];
      }

      if (score > scores[i]) {
	scores[i] = score;
	btr[i] = j;
      }
    }
  }
  score = scores[length - 1];  

  return score;
}

int evaluate_lin(char *s, int *scores, int *btr) {
  int i, j, index, length;
  char *tmp;
  int score, subscore;
  struct trienode *p = root;

  
  length = strlen(s);
  if (length > psl) {
    enlarge();
  }


  for (i = 0; i < length; i++) {
    tmp = &(s[i]);    
    p = root;

    for (j = i; j < length; j++) {
      index = triepos[(int)*tmp++] - 'A';
      if (p->p[index]) {
	p = p->p[index];
      } else {
	break;
      }
      isword[i][j] = p->ending;
      isprefix[i][j] = 1;
    }
    for ( ; j < length; j++) {
      isword[i][j] = 0;
      isprefix[i][j] = 0;
    }
  }

  for (i = 0; i < length; i++) {

    if (isword[0][i]) {
      subscore = i + 1;
    } else {
      subscore = 0;
    }

    if (subscore > 2) {
      scores[i] = subscore;
    } else {
      scores[i] = 0;
    }
    btr[i] = -1;
    
    for (j = 0; j < i; j++) {

      if (isword[j + 1][i]) {
	subscore = i - j;
      } else {
	subscore = 0;
      }
      if (subscore > 2) {
	score = scores[j] + subscore;
      } else {
	score = scores[j];
      }

      if (score > scores[i]) {
	scores[i] = score;
	btr[i] = j;
      }
    }
  }
  score = scores[length - 1];  

  return score;
}

