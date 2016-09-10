
#include "Test.h"
#include <fstream>

#include <bitset>         // std::bitset

#include <stdlib.h>



using namespace std;
using namespace NTL;

/*
** Translation Table as described in RFC1113
*/
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
** Translation Table to decode (created by author)
*/
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

/*
** returnable errors
**
** Error codes returned to the operating system.
**
*/
#define B64_SYNTAX_ERROR        1
#define B64_FILE_ERROR          2
#define B64_FILE_IO_ERROR       3
#define B64_ERROR_OUT_CLOSE     4
#define B64_LINE_SIZE_TO_MIN    5
#define B64_SYNTAX_TOOMANYARGS  6

/*
** encodeblock
**
** encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
static void encodeblock( unsigned char *in, unsigned char *out, int len )
{
  out[0] = (unsigned char) cb64[ (int)(in[0] >> 2) ];
  out[1] = (unsigned char) cb64[ (int)(((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)) ];
  out[2] = (unsigned char) (len > 1 ? cb64[ (int)(((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)) ] : '=');
  out[3] = (unsigned char) (len > 2 ? cb64[ (int)(in[2] & 0x3f) ] : '=');
}

// Convert Base64 encoded char to its index
// '=' to its ascii (0x3D)
unsigned char Get_Based64_Id(unsigned char ch)
{
	unsigned char id = 0;
	if(ch >= 'A' && ch <= 'Z') //A-->Z, 0x41-->0x5a;id =0-25
	{
		id = ch -0x41;
	}
	else if(ch >= 'a' && ch <='z') // 0x61-->0x7a, id=26=51
	{
		id = ch - 0x47;
	}
	else if(ch >='0' && ch <='9') //0x30--0x39, id=52-61
	{
		id = ch + 4;
	}
	else if(ch == '+') // 0x2B, id=62
	{
		id = ch + 19;
	}
	else if (ch == '/') // 0x2F, id=63
	{
		id = ch + 16;
	}
	else //'=', 0x3D
	{
		id = 0x3D;
	}

	return id;
}

/*
** decodeblock
**
** decode 4 '6-bit' characters into 3 8-bit binary bytes
*/
static void decodeblock( unsigned char *in, unsigned char *out )
{   
    out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
    out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
    out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}


//==============================================================================
//==============================================================================
//                             BENCHES AND TESTS
//                   FOR EXTRACTION AND ENCRYPTION/DECRYPTION
//==============================================================================
//==============================================================================

// Convert a string to its ASCII contained in a vector of ZZ
void convertToASCII(string letter)
{
	ZZ z;
	vec_ZZ v;
// Set the length of z
	//v.SetMaxLength(2*letter.length());
//	v.QuickSetLength(letter.length());
	v.FixLength(letter.length());
	
    for (unsigned int i = 0; i < letter.length(); i++)
    {
        char x = letter.at(i);
		v[i] = conv<ZZ>(int(x));
		cout << "i= " << int(x) << "\t";
		cout << "v[i] = " << v[i] << endl;
     }
	
	//for(unsigned int j=0; j<v.length(); j++)
	cout<<"Length of v is " << v.length()<<endl;
	cout << "v= " << v << endl;
}

// Convert string ID to Vector
void convertIDtoVector(vec_ZZ& vid, string strID)
{
	char ch;
	for(unsigned int i=0; i<strID.length(); i++)
	{
		ch= strID.at(i);
		vid[i] = conv<ZZ>(int(ch));
	 }
}

// Extract secret key for a string ID
void JET_Extract(ZZX SK_id[2], string strID, const MSK_Data * const MSKD)
{
	vec_ZZ vid;
	vid.FixLength(N0);
	convertIDtoVector(vid, strID);

	IBE_Extract(SK_id, vid, MSKD);
}

// Encrypt a message (in length of N0)

void Bench_Extract(const unsigned int nb_extr, MSK_Data * MSKD)
{
    clock_t t1, t2;
    float diff;
    unsigned int i;
    vec_ZZ vid;
    ZZX SK_id[2];

	string strID;

	// Open the id file
	ifstream input("id.txt", ifstream::in);
 
	// char id_Alice[30];
	// strcpy(id_Alice, "alice@gmail.com");
	// cout << "id_Alice = "<< id_Alice << endl;

	// unsigned int id_length = strlen(id_Alice);
	// for(j=0; j<id_length;j++)
	// {
	// 	id[j] = (ZZ*)id_Alice[j];
	// }
	//id[j] = '\0';
	vid.FixLength(N0); // Set the fixed length of vid
//	vid.SetMaxLength(N0);
	
	
    t1 = clock();

    //cout << "0%" << flush;
    for(i=0; i<nb_extr; i++)
    {
		vid = RandomVector();
		// cout<<"Enter the ID string: ";
		// cin >> strID;
		// Get the ID line
		getline(input, strID);

		// vid.SetLength(strID.length()); // Set the length of vid
		// cout<< "Length of vid = " << vid.length() << endl;

		// convert string ID to vector ID
		//convertIDtoVector(vid, strID);

		// cout<< "id[0] = " << id[0] << endl;

		//JET_Extract(SK_id, strID, MSKD);
        IBE_Extract(SK_id, vid, MSKD);

		//cout <<"String ID is " << strID << endl;
		cout <<" vid = " << vid << endl;
		cout << "Extracted Key #" << i+1 << endl;
		cout <<"SK_id [0] = " << SK_id[0] << endl;
		cout <<"SK_id [1] = " << SK_id[1] << endl;

		IBE_Verify_Key(SK_id, vid, MSKD);
 
		// Display the process
		// The origianl version will segment fault when nb_extr = 1
		// if((i+1)%(nb_extr/10)==0)
        // {
        //     cout << "..." << (i+1)/(nb_extr/10) << "0%" << flush;
        // }
		//cout << "Key Extracted: **** " <<  (i+1) <<"/"<< nb_extr;

    }

	cout << endl;
	
    t2 = clock();
    diff = ((float)t2 - (float)t1)/1000000.0F;
    cout << "\n\nIt took " << diff << " seconds to extract " << nb_extr << " keys." << endl;
    cout << "That's " << (diff/nb_extr)*1000 << " milliseconds per key." << endl << endl;

	// Change an input email address into a vector of ZZ for later key extraction
	// string plainText;
    // cout << "Enter your email address: ";
    // cin >> plainText;
	// cout<<"The converted vector is "<<endl;
    // convertToASCII(plainText);

	 
  }


void Bench_Encrypt(const unsigned int nb_cryp, MPK_Data * MPKD, MSK_Data * MSKD)
{
    clock_t t1, t2;
    double diff;
    unsigned int i,j;
    vec_ZZ vid;
    ZZX SK_id[2], w;
    CC_t SKid_FFT[N0];
    long int message[N0], decrypted[N0];
    long int identity[N0], Ciphertext[2][N0];

	
	string strID;
	ifstream input("id.txt", ifstream::in);

	cout<<"Read ID input file ...\n";
	getline(input, strID); // Input ID from the id.txt
	cout << "The string ID is " << strID << endl;

	// convert string ID to binary vector
	 vid.FixLength(N0); // Set the fixed length of vid
	 convertIDtoVector(vid, strID);
	//vid = RandomVector();
	cout<<"vid = "<<vid<<endl;
	

	cout<<"Read message file ...\n";
	string strMsg;
	ifstream msgFile("message.txt", ifstream::in);
	getline(msgFile, strMsg);
	
	string bstrMsg; // string message in binary
	for (std::size_t i = 0; i < strMsg.size(); ++i)
	{
		bitset<8> b(strMsg.c_str()[i]);
		bstrMsg += b.to_string();
	}

	cout <<"The bit length of message is " << 8*strMsg.size() << endl;
	cout<<"The binary format of message is "<< bstrMsg << endl;
	
	 IBE_Extract(SK_id, vid, MSKD);
	//JET_Extract(SK_id, strID, MSKD);

	// vid.FixLength(N0);
	// convertIDtoVector(vid, strID);
	// cout << "The vector ID is " << vid << endl;

	IBE_Verify_Key(SK_id, vid, MSKD);

	
    ZZXToFFT(SKid_FFT, SK_id[1]);

	
    for(i=0; i<N0; i++)
    {
        identity[i] = conv<long int>(vid[i]);
		
    }




	
    t1 = clock();

   
    for(i=0; i<nb_cryp; i++)
    {
	
		for(j=0; j<N0; j++)
		{
			//message[j] = (rand()%2); // 0 or 1

			message[j] = bstrMsg[j] - '0';

			// using the input file as message
			// if(j <= size)
			// 	message[j] = memblock[j];
			// else
			// 	message[j] = (rand()%2);

		}
	
		
		//	cout << "N0 = " << N0 << endl;
		
		cout << "The message is [" ;
		for(j=0;j<N0;j++)
		{
			cout<<message[j] <<"\t";
		}
		cout << "]" <<endl;
		
	
        
        IBE_Encrypt(Ciphertext, message, identity, MPKD);
		
		//cout<<"The ciphered txt is \n";
		//cout<< "Ciphertext[0] = [";
		// for(j=0; j<N0; j++)
		// {
		// 	cout << Ciphertext[0][j] <<"\t";
		// }
		// cout<<endl<<endl;
		// cout<< "Ciphertext[1] = [";
		// for(j=0; j<N0; j++)
		// {
		// 	cout << Ciphertext[1][j] <<"\t";
		// }
		// cout<<endl<<endl;

		
        IBE_Decrypt(decrypted, Ciphertext, SKid_FFT);
	
		cout << "The decrypted one is [";
		for(j=0; j<N0; j++)
		{
			cout << decrypted[j] <<"\t";
		}
		cout<<"]" << endl;

		for(j=0; j<N0; j++)
        {
			if(message[j] != decrypted[j])
            {
                cout << "ERROR : Dec(Enc(m)) != m " << endl;
                break;
            }
        }
		// nb_cryp =1, will broken
//		if((i+1)%(nb_cryp/10)==0)
        // {
        //     cout << "..." << (i+1)/(nb_cryp/10) << "0%" << flush;
        // }
    }

    t2 = clock();
    diff = ((double)t2 - (double)t1)/1000000.0l;
    cout << "\n\nIt took " << diff << " seconds to do " << nb_cryp << " encryptions and decryptions." << endl;
    cout << "That's " << (diff/nb_cryp)*1000 << " milliseconds per encryption+decryption." << endl;
    cout << "That's " << (diff/nb_cryp)*1000*1024/N0 << " milliseconds per encryption+decryption per Kilobit." << endl << endl;


	// Output in binary file
	// ofstream ofile("ofile.png", ios::out|ios::binary);
	// if(ofile.is_open())
	// {
	// 	cout <<"Outputing file ...\n";
	// 	ofile.write(memblock, size);
	// 	ofile.close();
	// }
	// else
	// {
	// 	cout<<"Errot to open output file!!!"<<endl;
	// 	delete[] memblock;
	// 	return;
	// }
	

	


	//delete[] memblock;
}

// Encrypt a block, size = N0/8 bytes
// C[2][N0]: output cipher text;
// msgBlock: input message block with a fixed size of N0/8
// strID: identity with a length smaller than N0/8;
// MPKD: master pulib key
void IBE_Encrypt_Block(long C[2][N0], const char msgBlock[N0/8], string strID, const MPK_Data *MPKD)
{
	// Convert strID to long identity
	long identity[N0] = {0};

	char ch;
	for(unsigned int i=0; i<strID.length(); i++)
	{
		ch= strID.at(i);
		identity[i] = long(ch);
	 }

     // Read message into m[N0]
	long m[N0] = {0};
	for(int j=0; j<N0/8; j++ )
	{
		char ch = msgBlock[j];
		long tl[8];
		for (int i = 7; i >= 0; --i)
		{
			tl[i] =  (ch & (1 << i)) ? 1 : 0 ;
		}

		for(int k=0; k<8; k++)
		{
			m[8*j+k] = tl[7-k];
		}
	}	


	// IBE
	IBE_Encrypt(C, m, identity, MPKD);
	
}

// Decrypt a cipher text block C[2][N0] to a message block with a length of N0/8;
// msgBlock: Decrypted result
// C: cipher text as a 2-D vector 
void IBE_Decrypt_Block(char msgBlock[N0/8], const long C[2][N0], const CC_t * const SKid_FFT)
{
	long int decrypted[N0];

	// Decrypt
	IBE_Decrypt(decrypted, C, SKid_FFT);

	// convert decrypted vector to message
	for(int i=0; i<N0; i +=8)
	{
		char ch = '\0';
		for(int k=0; k<8; k++)
		{
			ch += decrypted[i+k]<<(7-k);
		}
		msgBlock[i/8] = ch;
	}

}

// Encrypt a file (size may larger than N0)
// cfile: output ciphered file name;
// mfile: plain file name
// strID: string identity, e.g. an email address
// MPKD: struct of master parameters
void JET_IBE_Encrypt_File(char* cfile, const char* mfile, const string strID, const MPK_Data *MPKD)
{
	// Convert string ID to long identity
	long identity[N0] = {0};


	vec_ZZ id;
	
	id.FixLength(N0);
	convertIDtoVector(id, strID);
	
	for(int i=0; i<N0; i++)
    {
        identity[i] = conv<long int>(id[i]);
    }
	
	// read message file into long m[N0] blocks
	// Read a file into memory
	long m[N0] = {0};

	// N0/8 bytes can be processed every time
	char memblock[N0/8] = {'\0'};
	

	cout <<"Reading message file ...\n";
	streampos size;
	ifstream ifile(mfile, ios::in|ios::binary|ios::ate);
	// effect read bytes
	int nByte = 0;
	if(ifile.is_open())
	{
		size = ifile.tellg(); // obtain the file size
	
		ifile.seekg(0, ios::beg);
	
		if(size<=(N0/8))
		{
			nByte = size;
		}
		else
		{
			nByte = N0/8;

			// later for block circlic
		}
		ifile.read(memblock, nByte);
		ifile.close();
	}
	else
	{
		cout << "Unable to open input message file!!!\n";
		return;
	}

	// nByte must <= N0/8
	for(int j=0; j<nByte; j++ )
	{
		char ch = memblock[j];
		long tl[8];
		for (int i = 7; i >= 0; --i)
		{
			tl[i] =  (ch & (1 << i)) ? 1 : 0 ;
		}

		for(int k=0; k<8; k++)
		{
			m[8*j+k] = tl[7-k];
		}
	}	
	

	cout<<"The plain message is \n";
	for(int j=0; j<16; j++)
	{
		cout << hex << m[j] <<"\t";
	}
	cout << endl;

	// IBE
	cout<<"Encrypting ....\n";
	long C[2][N0];
	IBE_Encrypt(C, m, identity, MPKD);

	cout<<"The encrypted text is \n";
	cout<<"C[0] = \n";
	for(int j=0; j<8; j++)
	{
		cout << hex << C[0][j] <<"\t";
	 }
	cout<<endl;
	cout<<"C[1] = \n";
	for(int j=0; j<8; j++)
	{
		cout << hex << C[1][j] << "\t";
	}
	cout << endl;

	// Output in File
	ofstream ofile(cfile, ios::out);
	ofile.write((char*)C, 2*N0*sizeof(long));

	ofile.close();
	
	return;
}


// Decrypt a crypted file to original file
// dfile: decrypted file name
// cfile: encrypted file name
// SKid_FFT: FFT conversion of extracted key SK_id

void JET_IBE_Decrypt_File(char *dfile, const char* cfile, const CC_t * const SKid_FFT)
{
	long int C[2][N0];
	long int decrypted[N0];
	
	long int *lblock = new long int[2*N0*sizeof(long int)];
	// Read encrypted file into long 2-D vector
	ifstream ifile(cfile, ios::in);
	if(ifile.is_open())
	{
		ifile.seekg(0, ios::beg);
		//ifile.read(memblock, size);
		ifile.read((char*)lblock, 2*N0*sizeof(long));
		long *pl = lblock;
		for(int i=0; i<N0;i++)
		{
			C[0][i] = *(pl++);
		}
		for(int i=0; i<N0; i++)
		{
			C[1][i] = *(pl++);
		}
		
	}
	else
	{
		cout << "Error: open cipherex text file!!! \n";
	}

	// Decrypt
	cout << "Decrypting ...\n";
	cout<<"The input cipher text is \n";
	cout<<"C[0] = \n";
	for(int j=0; j<8; j++)
	{
		cout << hex << C[0][j] <<"\t";
	 }
	cout<<endl;
	cout<<"C[1] = \n";
	for(int j=0; j<8; j++)
	{
		cout << hex << C[1][j] << "\t";
	}
	cout << endl;
	
	IBE_Decrypt(decrypted, C, SKid_FFT);

	
	cout << "The decrypted is \n";
	for(int j=0; j<16; j++)
	{
		cout << hex << decrypted[j] <<"\t";
	}
	cout << endl;

	// Save decrypted into file
	
	char message[N0/8];

	for(int i=0; i<N0; i +=8)
	{
		char ch = '\0';
		for(int k=0; k<8; k++)
		{
			ch += decrypted[i+k]<<(7-k);
		}
		message[i/8] = ch;
	}

	ofstream ofile(dfile, ios::out|ios::binary);
	if(ofile.is_open())
	{
		cout <<"Outputing file ...\n";
		ofile.write(message, N0/8);
		ofile.close();
	}
	else
	{
		cout<<"Errot to open output file!!!"<<endl;
		
		return;
	}
			
	
	
	delete[] lblock;
}

// Perform Base64 encode to a out string,
// nLength: length of in[] in byte
void b64e_array(unsigned char* out, unsigned char* in, int nByte)
{
	//int nByte = N0*sizeof(long int);
	assert(nByte >= 3);
	int i=0;
	
	while(nByte-3*i >= 3)
	{
		//encodeblock((unsigned char*)C+3*i, out+4*i, 3);
		encodeblock(in + 3*i, out + 4*i, 3);
		i++;	
	}
	//encodeblock((unsigned char*)C+3*i, out+4*i, nByte-3*i);
	encodeblock(in+3*i, out+4*i, nByte-3*i);
	
}

// Perform Based64 decode to in, output into out
// nLength: the length of in should be divided by 4
// 4-byte string ==> 3-byte string
void b64d_array(unsigned char *out, unsigned char *in, int nLength)
{
	int nCycle = nLength/4;
	
	for(int i=0; i< nCycle; i++)
	{
		for(int k=0; k<4; k++)
		{
			// Search for symbol id
			in[i*4 +k] = Get_Based64_Id(in[i*4 +k]);
		}
		
		decodeblock(in+i*4, out+i*3);
	}
}

// Print the ASCII value of the index table
void print_table()
{
	for(int i=0; i<64; i++)
	{
		cout << (unsigned)cb64[i] << endl;
	}
}

/* Print Encrypted and Decrypted data packets */
void print_data(const char *tittle, const void* data, int len)
{
	printf("%s : ",tittle);
	const unsigned char * p = (const unsigned char*)data;
	int i = 0;
	
	for (; i<len; ++i)
		printf("%02X ", *p++);
	
	printf("\n");
}
