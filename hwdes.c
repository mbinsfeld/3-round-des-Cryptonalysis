#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

// My (slow) implementation of DES

// Currently set for 3 rounds with no IP or inverse IP perms.
//
// Currently set to plaintext 748502cd38451097, key 1a624c89520dec46
//   which produces ciphertext 03c70306d8a09f10, consistent with Stinson's
//   first pt/ct pair in example 3.3

// Copyright 2010 by John Black
//
// Permission is granted to students of CSCI 7000 at CU to use, modify,
//   and freely take pieces of this code for use in homework.



#define NUMRNDS 3

// Set these to 1 to turn them on; 0 turns them off
#define APPLY_IP   0
#define APPLY_IPI  0
#define FINAL_REVERSE 0

// Set this from 0-2 to change pt/ct pairs
#define PAIRS 0 

void des_encrypt(int *pt, int *ct, int *key);
void getkey(int *key, char *rk, int round);
void unpack(int *pt, char *ca);
void pack(int *ct, char *ca);
void dump(char *ca, int len);
void ASboxTables();
void attack_DES();
void BuildINTables();
void unpack_32(int *pt, char *ca);
void pack_6(int *ct, char *ca);
int* find_xor_pairs(int inputxor);
void BuildINTables();

//int sOut[8][exp2(6)][exp2[4]]

//Step 1: getCvals(ct) //basically just p inverse
//Step 2: Build tables of possible sbox outputs for each possible input xor
//Step 3: Figure out e vals by doing a few things and stuff

//Input/output pairs
int pairs[][2][2][2] = {
    {
        { {0x748502cd, 0x38451097}, {0x2e48787d, 0xfb8509e6} },
        { {0x38747564, 0x38451097}, {0xfc19cb45, 0xb6d9f494} }
    },
    {
        { {0x48691102, 0x6acdff31}, {0xac777016, 0x3ddc98e1} },
        { {0x375bd31f, 0x6acdff31}, {0x7d708f6d, 0x4bc7ef16} }
    },
    {
        { {0x357418da, 0x013fec86}, {0x5a799643, 0x9823cf12} },
        { {0x12549847, 0x013fec86}, {0xae46e276, 0x16c26b04} }
    }
};

int main()
{
    //ASboxTables();
    int pt[2]={0x748502cd, 0x38451097};
    int ct[2];
    int key[2]={0x1a624c89, 0x520dec46};

    //des_encrypt(pt, ct, key);
    attack_DES();
    printf("Ciphertext: %08x, %08x\n", ct[0], ct[1]);
}

//INTables[s][inputxor][outputxor][possibilities];
int INTables[8][64][64][64];

// the expansion function E()
char exp1[]={  0,
	     32,  1,  2,  3,  4,  5,
              4,  5,  6,  7,  8,  9,
	      8,  9, 10, 11, 12, 13,
	     12, 13, 14, 15, 16, 17,
	     16, 17, 18, 19, 20, 21,
	     20, 21, 22, 23, 24, 25,
	     24, 25, 26, 27, 28, 29,
	     28, 29, 30, 31, 32,  1};

// these permutations, pc1 and pc2, are used in key scheduling
static unsigned char pc1[] = { 0,
       57, 49, 41, 33, 25, 17,  9,   1, 58, 50, 42, 34, 26, 18,
       10,  2, 59, 51, 43, 35, 27,  19, 11,  3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,   7, 62, 54, 46, 38, 30, 22,
       14,  6, 61, 53, 45, 37, 29,  21, 13,  5, 28, 20, 12,  4 };

static unsigned char pc2[] = { 0, 
       14, 17, 11, 24,  1,  5,       3, 28, 15,  6, 21, 10,
       23, 19, 12,  4, 26,  8,      16,  7, 27, 20, 13,  2,
       41, 52, 31, 37, 47, 55,      30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,      46, 42, 50, 36, 29, 32 };

// The S-boxes (the heart of DES)
//
static unsigned char s[][64] = {
{ // S1
  14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
   0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
   4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
  15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 },
{ // S2
  15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
   3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
   0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
  13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 },
{ // S3
  10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
  13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
  13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
   1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 },
{ // S4
   7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
  13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
  10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4, 
   3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 },
{ // S5
   2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
  14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
   4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
  11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 },
{ // S6
  12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
  10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
   9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
   4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 },
{ // S7
   4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
  13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
   1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
   6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 },
{ // S8
  13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
   1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
   7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
   2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
};

void BuildINTables(){
  //INTables[s][inputxor][outputxor][possibilities];
  //int INTables[8][64][64][64];
  //each sbox
  for(int sbox = 0; sbox < 8; sbox++){
    //all possible input xors
    for(unsigned int inputxor = 0; inputxor < 64; inputxor++){
      int* possibilitiesArray = find_xor_pairs(inputxor);
      //each possibility
      for(unsigned int possibility = 0; possibility < sizeof(possibilitiesArray)/sizeof(possibilitiesArray[0]); possibility++){
        int temp = possibilitiesArray[possibility];
        int outputxor = s[sbox][temp];
        INTables[sbox][inputxor][outputxor][possibility] = possibilitiesArray[possibility];
      }
    }
  }
}



int* find_xor_pairs(int inputxor){
  //int possibilities[(int)exp2(12)]
  int possibilities[64];
  int count = 0;
  for(int i = 0; i < 64; i++){
    for(int j = 0; j >= 64; j++){
      if((i^j) == inputxor){
        possibilities[count] = i;
        count ++;
        possibilities[count + 1] = j;
        count ++;
      }
    }
  }
  //int temp[count];
  int* temp = malloc(count * sizeof(int));
  for(int i = 0; i < count; count++){
    temp[i] = possibilities[i];
  }
  return temp; 
}

// the permutation P is applied after the S-boxes
static char p[] = { 0,
16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
 2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25 };


void attack_DES(){

  int *l0a = &pairs[PAIRS][0][0][0];
  int *l0b = &pairs[PAIRS][1][0][0];
  int *r0a = &pairs[PAIRS][0][0][1];
  int *r0b = &pairs[PAIRS][1][0][1];
  int *l3a = &pairs[PAIRS][0][1][0];
  int *l3b = &pairs[PAIRS][1][1][0];
  int *r3a = &pairs[PAIRS][0][1][1];
  int *r3b = &pairs[PAIRS][1][1][1];

  char l3a_t[33], l3b_t[33], r3a_t[33], r3b_t[33], C_t[33], E_t[49];
  char l0a_t[33], l0b_t[33], inverted[33];
  int i, back_to_int;
  char *E[9], *C[9];
  int temp_e[7], temp_c[5];

  unpack_32(l3a, l3a_t);
  unpack_32(l3b, l3b_t);
  unpack_32(r3a, r3a_t);
  unpack_32(r3b, r3b_t);
  unpack_32(l0a, l0a_t);
  unpack_32(l0b, l0b_t);

  //First we traverse down f to find E
  //Diff for L3/R2
  for (i = 1; i <= 32; i++){
    l3a_t[i] ^= l3b_t[i];
  }

  //Expand Left
  for (i = 1; i <= 48; i++)
      E_t[i] = l3a_t[exp1[i]];

  //Now we will traverse up f to find C
  //Diff for R3
  for (i = 1; i <= 32; i++){
    r3a_t[i] ^= r3b_t[i];
  }

  //Diff for L0
  for (i = 1; i <= 32; i++){
    l0a_t[i] ^= l0b_t[i];
  }

  //Difference of differences of L0 and R3
  for (i = 1; i <= 32; i++){
    inverted[i] = l0a_t[i] ^ r3a_t[i];
  }

  //Reverse P using inverted array to find C
  for (i = 1; i <= 32; i++)
    C_t[p[i]] = inverted[p[i]];

   dump(E_t, 48);
  //Put E and C possibilities into array as ints
  /*int len = 0;
  int j = 0;
  int k = 0;
  for (i = 1; i < 48; i++){
    if(i%6==0){
      temp_e[j] = E_t[i];
      pack_6(temp_e, E[k]);
      k++;
      j = 0;
    }
    else{
      temp_e[j] = E_t[i];
      j++;
    }

      }
    dump(E, 48);
*/
}

void des_encrypt(int *pt, int *ct, int *key)
{
    char ip[65];
    char ipi[65];
    char pta[65], ptb[65];
    char cta[65];
    char ex[49], rk[49];
    char rval[33], mask[33], temp[33];
    int  i, j;
    int  x=0;
    int  y=8;
    int  round = 1;


    // set up ip and ip inverse
    for (i=1; i <= 64; i += 2)
    {
	ip[((x+4) << 3) + y] = i; ip[(x << 3) + y] = i+1;
	ipi[i] = ((x+4) << 3) + y; ipi[i+1] = (x << 3) + y;

	x++;
	if (i % 8 == 7) { y--; x=0; }
    }

    // to avoid horrendous bit masking we break everything into char arrays
    unpack(pt, pta);

    // apply ip to the plaintext pta to get ptb
    if (APPLY_IP)
    {
	for (i = 1; i <= 64; i++)
	    ptb[i] = pta[ip[i]];
	printf("After IP: "); dump(ptb, 64);
    }
    else
	for (i = 1; i <= 64; i++)
	    ptb[i] = pta[i];

    for (round=1; round <= NUMRNDS; round++)
    {
        printf("\n\n*** Round %d:\n", round);
	// apply the expansion function E() to get ex from ptb's right half
	for (i = 1; i <= 48; i++)
	    ex[i] = ptb[exp1[i]+32];
	printf("Expansion: "); dump(ex, 48);

	// get key for this round
	getkey(key, rk, round);
	printf("Round Key: "); dump(rk, 48);
	
	// xor the round key rk into the expanded right half ex
	for (i = 1; i <= 48; i++)
	    ex[i] ^= rk[i];
	printf("XOR output: ");  dump(ex, 48);

	// and now apply the 8 S-boxes
	for (i = 1; i <= 8; i++)
	{
	    int sval;
	    int j;

	    j = (i-1)*6;
	    sval = s[i-1][(ex[j+1]*2+ex[j+6])*16 +
		    ex[j+2]*8 + ex[j+3]*4 + ex[j+4]*2 + ex[j+5]];
	    for (j=4; j >= 1; j--)
	    {
		rval[(i-1)*4 + j] = (sval & 1);
		sval >>= 1;
	    }
	}
	printf("S-Box output: "); dump(rval, 32);

	// finally apply the P permutation
	for (i = 1; i <= 32; i++)
	    mask[i] = rval[p[i]];
	printf("Mask Value: "); dump(mask, 32);

	// now we do the Feistel dance: move right side of ptb to
	// the left, then store mask xor that left side in the right
	for (i = 1; i <= 32; i++)
	    temp[i] = ptb[i];        // copy the left side
	for (i = 1; i <= 32; i++)
	    ptb[i] = ptb[i+32];      // move right half to left
	for (i = 1; i <= 32; i++)
	    ptb[i+32] = temp[i] ^ mask[i];
	printf("Round Output: "); dump(ptb, 64);
    }
    // Almost done; now apply IP^-1 to ptb (with halves reversed)
    if (FINAL_REVERSE)
    {
	for (i=1; i <= 32; i++)
	    temp[i] = ptb[i];      // copy the left half
	for (i = 1; i <= 32; i++)
	    ptb[i] = ptb[i+32];    // move right half to left
	for (i=1; i <= 32; i++)
	    ptb[i+32] = temp[i];   // put right half back 
    }
    
    if (APPLY_IPI)
	for (i=1; i <= 64; i++)
	    cta[i] = ptb[ipi[i]];
    else
	for (i=1; i <= 64; i++)
	    cta[i] = ptb[i];

    printf("\n\nCiphertext: "); dump(cta, 64);

    pack(ct, cta);
    
}

void getkey(int *key, char *rk, int round)
{
    char t[65], s[57];
    int i;
    char p;
    int k;

    // we transfer k1 and k2 (the key) into the t array
    unpack(key, t);

    // now apply the pc1 permutation
    for (i=1; i <= 56; i++)
        s[i] = t[pc1[i]];

    // next circular shift each half once for i up to the round number
    // but double shift all except 1, 2, 9, and 16 
    for (k=1; k <= round; k++)
    {
	p = s[1]; for (i=1; i <=27; i++)  s[i] = s[i+1]; s[28] = p;
	p = s[29]; for (i=29; i <=55; i++)  s[i] = s[i+1]; s[56] = p;
	if (k == 1  ||  k == 2  ||  k == 9  ||  k == 16) continue;
	p = s[1]; for (i=1; i <=27; i++)  s[i] = s[i+1]; s[28] = p;
	p = s[29]; for (i=29; i <=55; i++)  s[i] = s[i+1]; s[56] = p;
    }

    // finally, apply pc2 to these 56 bits to produce the 48-bit round key
    for (i=1; i <= 48; i++)
        rk[i] = s[pc2[i]];

}

// this routine unpacks 64-bit values into a char array
void unpack(int *pt, char *ca)
{
    int i;
    int a = pt[0];
    int b = pt[1];

    for (i=32; i >= 1; i--)
    {
	ca[i] = (a & 1);
	a >>= 1;
	ca[i+32] = (b & 1);
	b >>= 1;
    }

    //dump(ca, 64);
}
//unpacks 32 bit values into a char array
void unpack_32(int *pt, char *ca)
{
    int i;
    int a = pt[0];

    for (i=32; i >= 1; i--)
    {
  ca[i] = (a & 1);
  a >>= 1;

    }

    //dump(ca, 64);
}

// this routine packs a 0-1 char array into two 32-bit ints
void pack(int *ct, char *ca)
{
    int i;

    ct[0] = ct[1] = 0;

    for (i=1; i <= 32; i++)
    {
	ct[0] <<= 1;        ct[0] += ca[i];  
	ct[1] <<= 1;        ct[1] += ca[i+32];  
    }
}

// this routine packs a 0-1 char array into a 6-bit int
void pack_6(int *ct, char *ca)
{
    int i;

    ct[0] = 0;

    for (i=1; i <= 6; i++)
    {
  ct[0] <<= 1;        ct[0] += ca[i];   
    }
}

// dump a 0-1 char array for debugging purposes
void dump(char *ca, int len)
{
    int i;
    for (i=1; i <= len; i++)
    {
        printf("%d", ca[i]);
	if (i % 4 == 0) printf(" ");
    }
    printf("\n");
}
