#ifndef JET_TEST_H
#define JET_TEST_H

#include "string.h"

#include "Scheme.h"
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <complex.h>
#include <time.h>
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/mat_ZZ.h>
#include <gmp.h>

#include "Sampling.h"
#include "params.h"
#include "FFT.h"
#include "Random.h"
#include "Algebra.h"

using namespace std;
using namespace NTL;

// Convert string ID to Vector
void convertIDtoVector(vec_ZZ& vid, string strID);

// Encrypt a block, size = N0/8 bytes
// C[2][N0]: output cipher text;
// msgBlock: input message block with a fixed size of N0/8
// strID: identity
// MPKD: master pulib key
void IBE_Encrypt_Block(long C[2][N0], const char msgBlock[N0/8], string strID, const MPK_Data *MPKD);

// Decrypt a cipher text block C[2][N0] to a message block with a length of N0/8;
// msgBlock: Decrypted result
// C: cipher text as a 2-D vector 
void IBE_Decrypt_Block(char msgBlock[N0/8], const long C[2][N0], const CC_t * const SKid_FFT);

// Encrypt a file
void JET_IBE_Encrypt_File(char* cfile, const char* mfile, string strID, const MPK_Data *MPKD);

// Decrypt a cipher file into another file
void JET_IBE_Decrypt_File(char *dfile, const char* cfile, const CC_t * const SKid_FFT);


//
// Perform Base64 encode to in[], output into out[],
// nLength: length of in[] in byte
void b64e_array(unsigned char* out, unsigned char *in, int nLength);
//void b64e_array(unsigned char* out, long int C[N0]);


// Perform Based64 decode to in, output into out
// nLength: the length of in should be divided by 4  
//void b64d_array(char *out, unsigned char *in, int nLength);
void b64d_array(unsigned char *out, unsigned char *in, int nLength);

// Print the ASCII value of the index table
void print_table();

/* Print Encrypted and Decrypted data packets */
void print_data(const char *tittle, const void* data, int len);

#endif
