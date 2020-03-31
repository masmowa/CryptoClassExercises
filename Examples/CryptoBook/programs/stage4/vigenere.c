/******************************************************************/
/*                                                                */
/*   File:        vigenere.c                                      */
/*   Author:      Lars Ivansson                                   */
/*   Created:     March 5, 1996                                   */
/*   Modified:    October 17, 2000                                */
/*   Description: This program solves vigener ciphers. The        */
/*                program has the follwing syntax:                */
/*                                                                */
/*                vigenere <alphabetfile> <cipherfile>            */
/*                                                                */
/*                The alphabet file should be a file with         */
/*                one letter on each row. NB. it is vital that    */
/*                the letter is the first character on that row.  */
/*                                                                */
/*                The program prints the plaintext to stdout      */
/*                                                                */
/*                There are two hard coded constants in the       */
/*                program. The maximum message length N is        */
/*                set to 100000, and the maxium keyword length    */
/*                MAX_WORD is set to 20.                          */
/*                                                                */
/******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <ctype.h>

#define N 100000
#define MAX_WORD 20

#define SAFE_MALLOC(v, n) { if (((v) = malloc((n))) == NULL) { \
    fprintf(stderr, "Unable to allocate %dB memory for variable %s\n", \
	    (n), #v); \
    fprintf(stderr, "File: %s. Line: %d\n",__FILE__, __LINE__); \
    exit(EXIT_FAILURE); \
  } \
}

#define SAFE_REALLOC(v, n) { if (((v) = realloc((v), (n))) == NULL) { \
    fprintf(stderr, "Unable to reallocate %dB memory for variable %s\n", \
	    (n), #v); \
    fprintf(stderr, "File: %s. Line: %d\n",__FILE__, __LINE__); \
    exit(EXIT_FAILURE); \
  } \
}

typedef struct{
  double prob;
  int first;
  int second;
  int shift;
}shifttype;

int plaintext[N], cipher[N];
int length;

int alphabet_mapping[256];
char *number_to_alphabet;


int **freq_mat;

void init_tables() {
  int i;

  for (i = 0; i < 256; i++) {
    alphabet_mapping[i] = -1;
  }
}

void read_alphabet_file(FILE *infile, int* length) {
  char row[128], c;
  int i, n;
  
  *length = 32;  
  SAFE_MALLOC(number_to_alphabet, (*length) * sizeof(char));

  n = 0;
  while (fgets(row, 128, infile)) {
    
    if (sscanf(row, "%c" , &c) != 1) 
      break;
    
    alphabet_mapping[(int) toupper(c)] = n;
    number_to_alphabet[n] = c;
    n++;

    if (n == (*length)) {
      (*length) += 32;
      
      SAFE_REALLOC(number_to_alphabet, (*length) * sizeof(char));
    }
  }

  (*length) = n;
  SAFE_REALLOC(number_to_alphabet, (*length) * sizeof(char));

  SAFE_MALLOC(freq_mat, MAX_WORD * sizeof(int*));
  for (i = 0; i < MAX_WORD; i++) {
    SAFE_MALLOC(freq_mat[i], (*length) * sizeof(int));
  }  
}

void read_text (FILE *infile, int *buffer, int *length){
  int c, i=0;

  while ((c=getc(infile))!=EOF){
    if (alphabet_mapping[toupper(c)] >= 0) {
      buffer[i]=alphabet_mapping[toupper(c)];
      i++;
    }
  }
  *length=i;
}

void write_text (FILE *outfile, int *buffer, int length, int m){
  int i=0;

  for (i = 0; i < length; i++) {
    putc(number_to_alphabet[buffer[i]], outfile);
    if (m!=0) {
      if ((i + 1) % m == 0) {
	      putc('\n',outfile);
      }
    }
  }

  putc('\n',outfile);
}

int measure_frequencies(int *buffer, int length, int alphabet_size,
			int start, int step, int *f_vec){
  int i,total=0;

  for (i = 0; i < alphabet_size; i++)
    f_vec[i]=0;
  
  for (i = start; i < length; i += step){
    f_vec[buffer[i]]++;
    total++;
  }
  f_vec[alphabet_size]=total;

  return(total);
}

int find_keylength(int *cipher, int c_length, int **freq_mat, int alphabet_size) {
  int m, spos, ni, k, hits, key_length, mopt=0;
  double prob, subprob, maxprob=0;

  for (m = 1; m <= MAX_WORD; m++){
    prob = 0;
    for (spos = 0; spos < m; spos++){
      hits = measure_frequencies(cipher, c_length, alphabet_size, spos, m, freq_mat[spos]);
      subprob = 0;

      for (k = 0; k < alphabet_size; k++){
	ni = freq_mat[spos][k];
	subprob += ni * (ni - 1);
      }
      prob += subprob / (hits * (hits - 1));
    }
    prob /= m;

    printf("Keyword length %2d: %.4f\n",m,prob);
    if (prob > maxprob){
      maxprob = prob;
      mopt = m;
    }
  }
  printf("\nGive keyword length (optimal m=%d): ", mopt);
  scanf("%d", &key_length);
  for (spos = 0; spos < key_length; spos++){
    hits = measure_frequencies(cipher, c_length, alphabet_size, spos, key_length, freq_mat[spos]);
  }
  return(key_length);
}

int compare (const void *i, const void *j){
  

  if ((((shifttype*) i)->prob) > (((shifttype*) j)->prob))
    return (0);
  else
    return (1);
}

void decrypt (int *cipher, int *plaintext, int c_length, 
	      int m, int **key, int **freq_mat, int alphabet_size){
  int fst,i,j,k,ekv,shift,relshift,optshift,key_number,n=0;
  double prob=0, newprob=0;
  char *keystr, c;
  shifttype *infovec;

  infovec = malloc(m * (m - 1) / 2 * sizeof(shifttype));
  keystr = malloc((m + 1) * sizeof(char));

  for (i = 0; i < m; i++){

    prob=0;

    for (j = i + 1; j < m; j++){
      prob=0;
      optshift=0;
      for (shift = 0; shift < alphabet_size; shift++){
	for (k = 0; k < alphabet_size; k++){
	  newprob += freq_mat[i][k] * freq_mat[j][(k + alphabet_size - shift) % alphabet_size];
	}
	newprob /= freq_mat[i][alphabet_size]*freq_mat[j][alphabet_size];
	if (newprob > prob){
	  prob = newprob;
	  optshift = shift;
	}
      }
      infovec[n].prob = prob; infovec[n].first = i;  
      infovec[n].second = j;  infovec[n].shift = optshift;
      n++;
    }    
  }
  qsort(infovec, n , sizeof(shifttype), compare);

  for (fst = 0; fst < alphabet_size; fst++){
    for (i = 0;i < MAX_WORD; i++)
      key[fst][i] = -30;
    key[fst][0] = fst;

    for (i = 1; i < m; i++){
      for (ekv = 0;((key[fst][infovec[ekv].first] == -30 && 
		     key[fst][infovec[ekv].second] == -30) ||
		    (key[fst][infovec[ekv].first] != -30 && 
		     key[fst][infovec[ekv].second] != -30)); ekv++){}
      if (key[fst][infovec[ekv].first] != -30){
	relshift = alphabet_size - infovec[ekv].shift;
	key[fst][infovec[ekv].second] =
	  (relshift + key[fst][infovec[ekv].first]) % alphabet_size;
      }else{
	key[fst][infovec[ekv].first] =
	  (infovec[ekv].shift + key[fst][infovec[ekv].second]) % alphabet_size;
      }
    }

    for (i = 0; i < m; i++) {
      keystr[i] = number_to_alphabet[key[fst][i]];
    }
    keystr[m]='\0';
    printf("\n%2d)%s: ",fst + 1,keystr);
    
    for (i = 0; i < 40 && i < c_length; i++){ 
      c = number_to_alphabet[(cipher[i] + alphabet_size - key[fst][i % m]) % alphabet_size];
      putchar(c);
    }
  }
  
  printf("\n\nGive selected keyword index: ");
  scanf("%d",&key_number);
  for (i = 0; i < c_length; i++){
    c = (cipher[i] + alphabet_size - key[key_number - 1][i % m]) % alphabet_size;
    plaintext[i]=c;
  }

  free(keystr);
  free(infovec);
}

int main(int argc, char *argv[]){
  int i, key_length, **key;
  int alphabet_size;
  FILE *alphabetfile, *cipherfile;

  if (argc < 2){
    printf("Syntax error!\nUsage: vigenere alphabetfile cipherfile > plain\n");
    exit(0);
  }
  
  init_tables();

  if ((alphabetfile = fopen(argv[1],"r")) == NULL) {
    fprintf(stderr, "Error: Unable to open alphabet file %s for reading.\n", argv[1]);
    exit(EXIT_FAILURE);    
  }

  if ((cipherfile=fopen(argv[2],"r")) == NULL) {
    fprintf(stderr, "Error: Unable to open input file %s for reading.\n", argv[2]);
    exit(EXIT_FAILURE);    
  }

  read_alphabet_file(alphabetfile, &alphabet_size);

  fprintf(stderr, "alphabet_size=%d\n", alphabet_size);
  
  SAFE_MALLOC(key, alphabet_size * sizeof(int*));
  for (i = 0; i < alphabet_size; i++) {
    SAFE_MALLOC(key[i], MAX_WORD * sizeof(int));
  }

  read_text(cipherfile, cipher, &length);
  key_length = find_keylength(cipher, length, freq_mat, alphabet_size);
  decrypt(cipher, plaintext, length, key_length, key, freq_mat, alphabet_size);
  write_text(stdout, plaintext, length, 50);
  return EXIT_SUCCESS;
}


