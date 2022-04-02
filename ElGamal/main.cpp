#include <iostream>
#include "EGamal.h"

int main()
{
	EGamal object("encode_table.txt", "text.txt", "pg.txt");
	object.generateKeys("public_key", "private_key");
	object.Encode("public_key", "encrytpted_data");

	EGamal decrytp("encode_table.txt", "encrytpted_data", "pg.txt");
	decrytp.Decode("private_key", "decrypted_data.txt");

	return 0;
}