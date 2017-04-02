#include "AES.h"
#include <string>
#include <vector>

using namespace std;

const size_t BLOCK_SIZE = 16;


namespace AES_128 {
	const size_t NK = 4;
	const size_t NR = 10;
}
namespace AES_192 {
	const size_t NK = 6;
	const size_t NR = 12;
}
namespace AES_256 {
	const size_t NK = 8;
	const size_t NR = 14;
}

const uint8_t sBox[16][16] = {
	{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
	{ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
	{ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
	{ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
	{ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
	{ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
	{ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
	{ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
	{ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
	{ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
	{ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
	{ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
	{ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
	{ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
	{ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
	{ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
};

const uint8_t invSbox[16][16] = {
	{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
	{ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
	{ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
	{ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
	{ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
	{ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
	{ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
	{ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
	{ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
	{ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
	{ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
	{ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
	{ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
	{ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
	{ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
	{ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
};

const uint8_t rcon[11][4] = {
	{ 0x00, 0x00, 0x00, 0x00 },
	{ 0x01, 0x00, 0x00, 0x00 },
	{ 0x02, 0x00, 0x00, 0x00 },
	{ 0x04, 0x00, 0x00, 0x00 },
	{ 0x08, 0x00, 0x00, 0x00 },
	{ 0x10, 0x00, 0x00, 0x00 },
	{ 0x20, 0x00, 0x00, 0x00 },
	{ 0x40, 0x00, 0x00, 0x00 },
	{ 0x80, 0x00, 0x00, 0x00 },
	{ 0x1b, 0x00, 0x00, 0x00 },
	{ 0x36, 0x00, 0x00, 0x00 }
};

void rotWord4b(uint8_t* item, short iter) {
	while (iter > 0) {
		uint8_t temp = item[3];
		item[3] = item[0];
		item[0] = item[1];
		item[1] = item[2];
		item[2] = temp;
		--iter;
	};
}
inline uint8_t gmult(uint8_t a, uint8_t b) {

	uint8_t p = 0, i = 0, hbs = 0;

	for (i = 0; i < 8; ++i) {
		if (b & 1) {
			p ^= a;
		}

		hbs = a & 0x80;
		a <<= 1;
		if (hbs) a ^= 0x1b; 	
		b >>= 1;
	}

	return static_cast<uint8_t>(p);
}
void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d) {

	d[0] = gmult(a[0], b[0]) ^ gmult(a[3], b[1]) ^ gmult(a[2], b[2]) ^ gmult(a[1], b[3]);
	d[1] = gmult(a[1], b[0]) ^ gmult(a[0], b[1]) ^ gmult(a[3], b[2]) ^ gmult(a[2], b[3]);
	d[2] = gmult(a[2], b[0]) ^ gmult(a[1], b[1]) ^ gmult(a[0], b[2]) ^ gmult(a[3], b[3]);
	d[3] = gmult(a[3], b[0]) ^ gmult(a[2], b[1]) ^ gmult(a[1], b[2]) ^ gmult(a[0], b[3]);
}

void sbBts(uint8_t* block, size_t count, const uint8_t from[16][16]) {

	/*Getting the current value as 0xXY and setting it 
	*to the from[x][y]*/
	for (int i = 0; i < count; ++i) {
		//first value
		size_t x = block[i] >> 4;
		//second value
		size_t y = block[i] & 0x0f;

		block[i] = from[x][y];
	}
}
void subBytes(uint8_t* block, size_t count) {
	sbBts(block, count, sBox);
}
void invSubBytes(uint8_t* block, size_t count) {
	sbBts(block, count, invSbox);
}

void shiftRows(uint8_t* block) {
	for (int i = 1; i < 4; ++i) {
		rotWord4b(block + (i * 4), i);
	}
}
void invShiftRows(uint8_t* block) {
	for (int i = 1; i < 4; ++i) {
		rotWord4b(block + (i * 4), 4 - i);
	}
}

void mxClmns(uint8_t* block, uint8_t *a) {
	uint8_t res[4];

	for (int i = 0; i < 4; ++i) {
		uint8_t col[4], res[4];
		//get column
		for (int j = i; j < BLOCK_SIZE; j += 4) {
			col[j / 4] = block[j];
		}

		//multiply column by a
		//with res = output
		coef_mult(a, col, res);

		//write result
		for (int j = i; j < BLOCK_SIZE; j += 4) {
			block[j] = res[j / 4];
		}
	}
}
void mixColumns(uint8_t* block) {
	uint8_t a[] = { 0x02, 0x01, 0x01, 0x03 };

	mxClmns(block, a);
}
void invMixColumns(uint8_t* block) {
	uint8_t a[] = { 0x0e, 0x09, 0x0d, 0x0b };
	
	mxClmns(block, a);
}

//made by the FIPS 197 (analog of)
void makeRoundKeys(std::vector<uint8_t* >& dest, const uint8_t* key,
					const size_t nk, const size_t nr) {
	//Check keysize and push
	//the key into the vector
	switch (nk) {
		case 4: {
			uint8_t* first = new uint8_t[17];
			memcpy(first, key, 16);
			first[16] = 0x00;
			dest.insert(dest.begin(), first);
			break;
		}
		case 6: {
			uint8_t *first = new uint8_t[17]
				{ key[0],  key[1],  key[2],  key[3],
				  key[6],  key[7],  key[8],  key[9],
				  key[12], key[13], key[14], key[15],
				  key[18], key[19], key[20], key[21], 0x00 };
			dest.insert(dest.begin(), first);

			uint8_t *second = new uint8_t[17]
			{	key[4],  key[5],  '.', '.',
				key[10], key[11], '.', '.',
				key[16], key[17], '.', '.',
				key[22], key[23], '.', '.', 0x00 };
			dest.insert(dest.end(), second);
			break; 
		}
		case 8: {
			uint8_t *first = new uint8_t[17]
			{ key[0],  key[1],  key[2],  key[3],
			  key[8],  key[9],  key[10], key[11],
			  key[16], key[17], key[18], key[19],
			  key[24], key[25], key[26], key[27], 0x00 };
			dest.insert(dest.begin(), first);

			uint8_t *second = new uint8_t[17] 
			{ key[4],  key[5],  key[6],  key[7],
			  key[12], key[13], key[14], key[15],
			  key[20], key[21], key[22], key[23],
			  key[28], key[29], key[30], key[31], 0x00 };
			dest.insert(dest.end(), second);
			break; 
		}
		default: { 
			throw invalid_argument("Nk (columns number) should be one of the: 4, 6, 8.");
			return;
		}
	}

	uint8_t temp[5]; //may be Wi-1 and Wi
	temp[4] = 0x00; 
	size_t totalColumns = 4 * (nr + 1);

	for (int i = nk; i < totalColumns; ++i) {
		//Current indeces of column
		//we work on
		size_t vectorIndex = i / 4,
			columnIndex = i % 4;

		//Add an empty item to the vector on case of 
		//there is less items we need
		if (dest.size() - 1 < vectorIndex) {
			uint8_t *item = new uint8_t[17];
			item[BLOCK_SIZE] = 0x00;
			memset(item, '.', BLOCK_SIZE);
			dest.push_back(item);
		}

		//Making Wi-1 column
		if (columnIndex == 0) {
			temp[0] = dest[vectorIndex - 1][3];
			temp[1] = dest[vectorIndex - 1][7];
			temp[2] = dest[vectorIndex - 1][11];
			temp[3] = dest[vectorIndex - 1][15];
		}
		else {
			temp[0] = dest[vectorIndex][columnIndex - 1];
			temp[1] = dest[vectorIndex][columnIndex + 3];
			temp[2] = dest[vectorIndex][columnIndex + 7];
			temp[3] = dest[vectorIndex][columnIndex + 11];
		}

		//transformations as in the FIPS-197
		if (i % nk == 0) {
			rotWord4b(temp, 1);
			subBytes(temp, 4);
			temp[0] = temp[0] ^ rcon[i / nk][0];
			temp[1] = temp[1] ^ rcon[i / nk][1];
			temp[2] = temp[2] ^ rcon[i / nk][2];
			temp[3] = temp[3] ^ rcon[i / nk][3];

		}
		else if ((nk > 6) && (i % nk == 4)) {
			subBytes(temp, 4);
		}

		size_t vectorIndexToGet = (i - nk) / 4,
			   lineIndexToGet = (i - nk) % 4;

		dest[vectorIndex][columnIndex + 0] =  dest[vectorIndexToGet][lineIndexToGet + 0]  ^ temp[0];
		dest[vectorIndex][columnIndex + 4] =  dest[vectorIndexToGet][lineIndexToGet + 4]  ^ temp[1];
		dest[vectorIndex][columnIndex + 8] =  dest[vectorIndexToGet][lineIndexToGet + 8]  ^ temp[2];
		dest[vectorIndex][columnIndex + 12] = dest[vectorIndexToGet][lineIndexToGet + 12] ^ temp[3];
	}
}
void addRoundKey(uint8_t* block, const uint8_t* key) {
	for (int i = 0; i < BLOCK_SIZE; i++) {
			block[i] = block[i] ^ key[i];
	}
}

bool checkKey(const uint8_t *const key, size_t &nk, size_t &nr)  {
	switch (strlen((char*)key)) {
		case 16: {
			nr = AES_128::NR;
			nk = AES_128::NK;
			return true;
		}
		case 24: {
			nr = AES_192::NR;
			nk = AES_192::NK;
			return true;
		}
		case 32: {
			nr = AES_256::NR;
			nk = AES_256::NK;
			return true;
		}
		default: {
			throw invalid_argument("Password lenght is incorrect: only BLOCK_SIZE\\24\\32 keylength avaible.");
			return false;
		}
	}
}
void deleteRoundKeys(vector<uint8_t*> items) {
	for (size_t i = 0; i < items.size(); ++i)
	{
		delete[] items[i];
	}
}


namespace AES {
	void encrypt(uint8_t* block, const uint8_t* cipherKey) {
		size_t nr, nk;
		if (!checkKey(cipherKey, nk, nr))
			return;

		//Making the keys for each round
		//and one more to use at the first time
		vector<uint8_t*> roundKeys;
		makeRoundKeys(roundKeys, cipherKey, nk, nr);

		//Ciphering
		addRoundKey(block, roundKeys[0]);

		for (int j = 0; j < nr - 1; ++j) {
			subBytes(block, BLOCK_SIZE);
			shiftRows(block);
			mixColumns(block);
			addRoundKey(block, roundKeys[j + 1]);
		}
		subBytes(block, BLOCK_SIZE);
		shiftRows(block);
		addRoundKey(block, roundKeys[nr]);

		//cleaning the memory
		deleteRoundKeys(roundKeys);
	}
	void decrypt(uint8_t* block, const uint8_t* cipherKey) {
		size_t nr, nk;
		if (!checkKey(cipherKey, nk, nr)) return;

		//Making the keys for each round
		//and one more to use at the first time
		vector<uint8_t*> roundKeys;
		makeRoundKeys(roundKeys, cipherKey, nk, nr);

		//Deciphering
		addRoundKey(block, roundKeys[nr]);
		for (int j = nr - 1; j > 0; j--) {
			invShiftRows(block);
			invSubBytes(block, BLOCK_SIZE);
			addRoundKey(block, roundKeys[j]);
			invMixColumns(block);
		}
		invShiftRows(block);
		invSubBytes(block, BLOCK_SIZE);
		addRoundKey(block, roundKeys[0]);

		//cleaning the memory
		deleteRoundKeys(roundKeys);
	}


	void encrypt(char* block, const uint8_t* cipherKey) {
		encrypt((uint8_t*)block, cipherKey);
	}
	void encrypt(std::string block, const uint8_t* cipherKey) {
		uint8_t* temp = (uint8_t*)block.data();
		encrypt(temp, cipherKey);
	}
	void encrypt(uint8_t* block, const char* cipherKey) {
		encrypt(block, (uint8_t*)cipherKey);
	}
	void encrypt(char* block, const char* cipherKey) {
		encrypt((uint8_t*)block, (uint8_t*)cipherKey);
	}
	void encrypt(std::string block, const char* cipherKey) {
		uint8_t* temp = (uint8_t*)block.data();
		encrypt(temp, (uint8_t*)cipherKey);
	}
	void encrypt(uint8_t* block, const std::string cipherKey) {
		encrypt(block, (uint8_t*)cipherKey.c_str());
	}
	void encrypt(char* block, const std::string cipherKey) {
		encrypt((uint8_t*)block, (uint8_t*)cipherKey.c_str());

	}
	void encrypt(std::string block, const std::string cipherKey) {
		uint8_t* temp = (uint8_t*)block.data();
		encrypt(temp, (uint8_t*)cipherKey.c_str());
	}

	void decrypt(char* block, const uint8_t* cipherKey) {
		decrypt((uint8_t*)block, cipherKey);
	}
	void decrypt(std::string block, const uint8_t* cipherKey) {
		uint8_t* temp = (uint8_t*)block.data();
		decrypt(temp, cipherKey);
	}
	void decrypt(uint8_t* block, const char* cipherKey) {
		decrypt(block, (uint8_t*)cipherKey);
	}
	void decrypt(char* block, const char* cipherKey) {
		decrypt((uint8_t*)block, (uint8_t*)cipherKey);
	}
	void decrypt(std::string block, const char* cipherKey) {
		uint8_t* temp = (uint8_t*)block.data();
		decrypt(temp, (uint8_t*)cipherKey);
	}
	void decrypt(uint8_t* block, const std::string cipherKey) {
		decrypt(block, (uint8_t*)cipherKey.c_str());
	}
	void decrypt(char* block, const std::string cipherKey) {
		decrypt((uint8_t*)block, (uint8_t*)cipherKey.c_str());

	}
	void decrypt(std::string block, const std::string cipherKey) {
		uint8_t* temp = (uint8_t*)block.data();
		decrypt(temp, (uint8_t*)cipherKey.c_str());
	}
}