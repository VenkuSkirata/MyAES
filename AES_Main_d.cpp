/*
#############################################################
#				  AES IMPLEMENTATION						#
#					made by: Venku							#
#	main.cpp	-	using example							#
#	AES.h		-	declarations of encrypt-functions		#
#	AES.cpp		-	definitions  of encrypt-functions		#
#			You can use it whatever you want.				#
#############################################################
*/

#include "AES.h"
#include <stdlib.h>
#include <cstdio>

int main(int argc, char** argv) {
	//text block - example 1
	uint8_t text1[17] = { 0x32, 0x88, 0x31, 0xe0,
						 0x43, 0x5a, 0x31, 0x37,
						 0xf6, 0x30, 0x98, 0x07,
						 0xa8, 0x8d, 0xa2, 0x34, 0x00 };

	//text block - example 2
	uint8_t text2[] = "Hello, world!!!1";

	//key example - 16 bytes
	uint8_t key_128[17] = { 0x2b, 0x28, 0xab, 0x09,
							0x7e, 0xae, 0xf7, 0xcf,
							0x15, 0xd2, 0x15, 0x4f,
							0x16, 0xa6, 0x88, 0x3c, 0x00 };

	//key example - 24 bytes
	uint8_t key_192[25] = { 0x8e, 0xda, 0xc8, 0x80, 0x62, 0x52,
							0x73, 0x0e, 0x10, 0x90, 0xf8, 0x2c,
							0xb0, 0x64, 0xf3, 0x79, 0xea, 0x6b,
							0xf7, 0x52, 0x2b, 0xe5, 0xd2, 0x7b, 0x00 };

	//key example - 32 bytes
	uint8_t key_256[33] = { 0x60, 0x15, 0x2b, 0x85, 0x1f, 0x3b, 0x2d, 0x09,
							0x3d, 0xca, 0x73, 0x7d, 0x35, 0x61, 0x98, 0x14,
							0xeb, 0x71, 0xae, 0x77, 0x2c, 0x08, 0x10, 0xdf,
							0x10, 0xbe, 0xf0, 0x81, 0x07, 0xd7, 0xa3, 0xf4, 0x00 };

	//example 1
	printf("==========example 1========\n");
	AES::encrypt(text1, key_128);
	AES::decrypt(text1, key_128);

	for (int i = 0; i < 16; i += 4) {
		printf("%02x, %02x, %02x, %02x\n", text1[i + 0], text1[i + 1], text1[i + 2], text1[i + 3]);
	}

	//example 2
	printf("==========example 2========\n");
	std::string test = std::string((char*)text2);
	AES::encrypt(test, key_192);
	AES::decrypt(test, key_192);
	printf("%s\n", text2);

	system("pause");
	return 0;
}
