/*

Copyright or © or Copr. Thomas Prest.

Thomas.Prest@ENS.fr

This software is a computer program which purpose is to provide to the 
research community a proof-of-concept implementation of the identity-based
encryption scheme over NTRU lattices, described in the paper
"Efficient Identity-Based Encryption over NTRU Lattices", of
Léo Ducas, Vadim Lyubashevsky and Thomas Prest, available at
homepages.cwi.nl/~ducas/ , www.di.ens.fr/~lyubash/
and www.di.ens.fr/~prest/ .

This software is governed by the CeCILL license under French law and
abiding by the rules of distribution of free software.  You can  use, 
modify and/ or redistribute the software under the terms of the CeCILL
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info". 

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability. 

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or 
data to be ensured and,  more generally, to use and operate it in the 
same conditions as regards security. 

The fact that you are presently reading this means that you have had
knowledge of the CeCILL license and that you accept its terms.

*/



#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <complex.h>
#include <time.h>
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/mat_ZZ.h>
#include <gmp.h>


#include "params.h"
#include "io.h"
#include "FFT.h"
#include "Sampling.h"
#include "Random.h"
#include "Algebra.h"
#include "Scheme.h"

#include "Test.h"

#include <fstream>
#include <sstream>

#include <math.h>       /* ceil */

#include <openssl/aes.h>  // for AES API in openssl

#include <iostream>

using namespace std;
using namespace NTL;

/* AES key for Encryption and Decryption */
const static int AES_KEY_LENGTH = 16;
const static unsigned char aes_key[]=\
{0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
 
void IBLE_Bench(int nb_run, string strID, unsigned char msg_inptu[N0/8], MSK_Data * MSKD, MPK_Data * MPKD);

//==============================================================================
//==============================================================================
//                                  MAIN
//==============================================================================
//==============================================================================


int main()
{


		
    //cout << "\n=======================================================================\n";
    //cout << "This program is a proof-of concept for efficient IBE over lattices.\n";
    //cout << "It generates a NTRU lattice of dimension 2N and associated modulus q,\n";
	// cout << "and perform benches and tests, for user key extraction and encryption/decryption.";
    //cout << "\n=======================================================================\n\n";

    ZZX MSK[4];
    ZZ_pX phiq, MPK;
    unsigned int i;
 
    MSK_Data * MSKD = new MSK_Data;
    MPK_Data * MPKD = new MPK_Data;
 
    const ZZX phi = Cyclo();

    srand(rdtsc()); // initialisation of rand

	cout <<"Public parameters: ";
    cout << "N = " << N0  << ", q = " << q0 << endl;
   
    ZZ_p::init(q1);
    zz_p::init(q0);

    phiq = conv<ZZ_pX>(phi);
    ZZ_pXModulus PHI(phiq);


    cout << "\n===================================================================\n KEY GENERATION: ";
	clock_t t1, t2; 
	// IBE key generation time
	float diff_kg;

    t1 = clock();
    for(i=0; i<1; i++)
    {
        Keygen(MPK, MSK);
    }

    CompleteMSK(MSKD, MSK);
    CompleteMPK(MPKD, MPK);

    t2 = clock();
    diff_kg = ((float)t2 - (float)t1)/1000000.0F;
    cout <<  diff_kg << " secs";
  

	/* Input data to encrypt */
	char  mfile[64];
	string strID;
	
	strID = "eini@netkdd.edu.cn";
	
	strcpy(mfile, "message.txt");
	unsigned char msg_input[N0/8];
	ifstream ifile(mfile, ios::in);
	ifile.read((char*)msg_input, N0/8);

	// Bench the IBLE
	int nb_run = 100;
	IBLE_Bench(nb_run, strID, msg_input, MSKD, MPKD);
	
    free(MSKD);
    free(MPKD);

	ifile.close();
    return 0;
}

// IBLE Bech procedure
void IBLE_Bench(int nb_run, string strID, unsigned char msg_input[N0/8], MSK_Data * MSKD, MPK_Data * MPKD)
{
	int i = 1;
	cout<<fixed;
	cout.precision(4);
	// Open trace file
	ofstream ofile("trace_IBLE.txt", ios::out|ios::trunc);
	ofile<<fixed;
	ofile.precision(4);
	ofile<<"#time resolution: ms (milli-second)\n";
	ofile<<"#Content Ecryption\tIBE Encryption\tIBE Decryption\tContent Decryption\n";

	while(nb_run >=1)
	{
		cout << "\n ========= The Run #" << i <<" =========================\n";
		cout << "\n===================================================================\n Content Encryption: ";
		/* Init vector */
		unsigned char iv[AES_BLOCK_SIZE];
		memset(iv, 0x00, AES_BLOCK_SIZE);
	
		/* Buffers for Encryption and Decryption */
		unsigned char enc_out[sizeof(msg_input)];

/* AES-128 bit CBC Encryption */
		AES_KEY enc_key, dec_key;
		clock_t t1, t2; 
		float diff_ce;
		t1 = clock();
		AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
		AES_cbc_encrypt(msg_input, enc_out, sizeof(msg_input), &enc_key, iv, AES_ENCRYPT);

		t2 = clock();
		diff_ce = ((float)t2 - (float)t1)/1000.0F; // in ms
		cout <<  diff_ce << " ms";
		ofile << diff_ce <<"\t";

	    /* AES-128 bit CBC Decryption */
		// don't forget to set iv vector again, else you can't decrypt data properly
		// memset(iv, 0x00, AES_BLOCK_SIZE); 
		// AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
		// AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv, AES_DECRYPT);
	
		/* Printing and Verifying */

		//print_data("\n Original ",aes_input, sizeof(aes_input));

		// you can not print data as a string, because after Encryption its not ASCII

		//	print_data("\n The AES encrypted:",enc_out, sizeof(enc_out));
//	cout<<"\nThe AES encrypted message: \n"<< hex << enc_out << endl;

		cout << "\n===================================================================\n IBE ENCRYPTION: ";
 
		// Read IBE input: key of AES
		char ibeInputBlock[N0/8];
		memset(ibeInputBlock, '0', N0/8);
		memcpy(ibeInputBlock, aes_key, AES_KEY_LENGTH);

		//cout<<"\nThe message is \n";
//	cout << hex << msgBlock << endl;
//	print_data("\n IBE Input: ",ibeInputBlock, AES_KEY_LENGTH);
		// Block encryption
		long cText[2][N0]; // Store IBE content

		float diff_ke;
		t1 = clock();
		IBE_Encrypt_Block(cText, ibeInputBlock, strID, MPKD);

		t2 = clock();
		diff_ke = ((float)t2 - (float)t1)/1000.0F;
		cout <<  diff_ke << " ms." ;
		ofile << diff_ke <<"\t";

		/*  	cout<<"The encrypted text is \n";
				cout<<"cText[0] = \n";
				for(int j=0; j<16; j++)
				{
				cout << hex << cText[0][j] <<"\t";
				}
				cout<<endl;
				cout<<"cText[1] = \n";
				for(int j=0; j<8; j++)
				{
				cout << hex << cText[1][j] << "\t";
				}
				cout << endl;
		*/

		ZZX SK_id[2];

		// Seems to be private key
		CC_t SKid_FFT[N0];

		vec_ZZ vid;
		vid.FixLength(N0);
		convertIDtoVector(vid, strID);
	
		IBE_Extract(SK_id, vid, MSKD);
		ZZXToFFT(SKid_FFT, SK_id[1]);

		///////////////	Base64 Endcode and Decode /////////////
//		cout << "\n===================================================================\n BASE64 ENCODING: ";

		// C0+C1: 
		int nLengthInput =  2*N0*sizeof(long);

		// Length of B64 encoded 
		int nB64Size = 4*ceil(nLengthInput/3);

		// Store the B64 encoded result
		unsigned char *b64e = new unsigned char[nB64Size+1];

		// B64 encoded (C0+C1) together
		t1 = clock();
		b64e_array(b64e, (unsigned char*)cText, nLengthInput);

		t2 = clock();
	
		//	float diff_64e = ((float)t2 - (float)t1)/1000.0F;
//		cout << diff_64e << " ms ";

		// cout << "\nThe Base64 encoded C is \n";
		// cout << b64e << endl;
		// B64 decode test
//		cout << "\n===================================================================\n BASE64 DECODING: ";
 
		long int DC[2][N0] ={0};

		unsigned char b64d[ 2*N0*sizeof(long)];
	
		t1 = clock();
		b64d_array(b64d, b64e, nB64Size);
		t2 = clock();
	
//		float diff_64d = ((float)t2 - (float)t1)/1000.0F;
//		cout << diff_64d << " ms ";


		//	cout << "\nThe B64 decoded of C[0] is \n";
		// should converted to long int and then display
		long int *pL = (long *)b64d;

		//
		for(int j=0; j < N0; j++)
		{
			DC[0][j] = *(pL+j);
		}

		//	cout << "\nThe B64 decoded of C[1] is \n";
		for(int k=0, j=N0; k<N0; k++,j++)
		{
			DC[1][k] = *(pL+j);
		}
//	cout << endl;
		cout << "\n===================================================================\n IBE DECRYPTION: ";
		char oMsg2[N0/8];

		t1 = clock();
		IBE_Decrypt_Block(oMsg2, DC, SKid_FFT);

		t2 = clock();
		float diff_kd = ((float)t2 - (float)t1)/1000.0F; // in ms
		cout << diff_kd << " ms ";
		ofile << diff_kd << "\t";
		//  	cout << "\nThe dcrypted message using key after Base64 is " << endl;
		// for(int i=0; i<N0/8; i++)
		// {
		// 	cout << oMsg2[i];
		// }
		// cout <<endl;
//	print_data("\n IBE Decrypted: ", oMsg2, AES_KEY_LENGTH);

		cout << "\n===================================================================\n Contetn DECRYPTION: ";
	
		/* AES-128 bit CBC Decryption */
		// don't forget to set iv vector again, else you can't decrypt data properly
		memset(iv, 0x00, AES_BLOCK_SIZE);

		t1 = clock();

		// using IBE decrypted output
		//AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
		AES_set_decrypt_key((unsigned char*)oMsg2, sizeof(aes_key)*8, &dec_key); // Size of key is in bits

		// Store the decrypted content
		unsigned char dec_out[sizeof(msg_input)];
		AES_cbc_encrypt(enc_out, dec_out, sizeof(msg_input), &dec_key, iv, AES_DECRYPT);

		t2 = clock();
		float diff_cd = ((float)t2 - (float)t1)/1000.0F;
		cout << diff_cd << " ms \n\n";
		ofile << diff_cd << "\t\n";

		//print_data("\n Decrypted",dec_out, sizeof(dec_out));
//	cout<<"\nThe Decrypted message: "<< dec_out <<endl;

		unsigned int k=0;
		for(; k<sizeof(msg_input); k++)
		{
			if(dec_out[k] != msg_input[k])
			{
				cout << "Content decryption error!!!\n";
				ofile << "Content decryption error!!!\n";
				break;
			}
		}

		if(k==sizeof(msg_input)) cout<<"Content decryption successfully!\n";

		delete[] b64e;

		nb_run--;
		i++;
	}

	ofile.close();
}
