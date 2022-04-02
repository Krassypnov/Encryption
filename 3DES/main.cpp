#include <iostream>
#include "DES.h"

void main()
{
	DES des("file.txt", "output.txt", "keys.txt", DES_ENC);
	des.Start();
	
	des.setFilesName("output.txt", "output_decrypt.txt", "keys.txt");
	des.setEncryptionMode(DES_DEC);
	des.Start();
	
}