# IBLE
An Identity Based License Encryption test programm in Linux C/C++, which encrypts the content using AES/CTR, thenIBE encrypts the secret key using an IBE scheme with email address as the ID, including Base64 encode and decode and performance benchmarking.



Thanks to the Identity-Based Encryption over NTRU Lattices, refer to README.md.old.txt.

How to use?
==========================
1. Download the master zip file: IBLE-master.zip;
2. Decompress the zip file: "unzip IBLE-master.zip", a directory of IBLE-master/ (change the directore name as you like) will be automatically generated;
3.  cd IBLE-master/; make; ./IBE
4.  the main function in the source file: IBE.cc, which runs 100 times with p= 1024, defined in params.h.
