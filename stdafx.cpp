// stdafx.cpp : source file that includes just the standard includes
// ConsoleApplication1.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include <bitset>
#include <Poco\MD5Engine.h>
#include <glm\glm.hpp>
#include "stdafx.h"

#pragma region Backend
#pragma region Sbox, InvSbox, Rcon
const unsigned long sBox[16][16] = {
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

const unsigned long invSbox[16][16] = {
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

const unsigned long rcon[10][4] = {
	{0x01, 0x00, 0x00, 0x00 },
	{0x02, 0x00, 0x00, 0x00},
	{0x04, 0x00, 0x00, 0x00},
	{0x08, 0x00, 0x00, 0x00},
	{0x10, 0x00, 0x00, 0x00},
	{0x20, 0x00, 0x00, 0x00},
	{0x40, 0x00, 0x00, 0x00},
	{0x80, 0x00, 0x00, 0x00},
	{0x1b, 0x00, 0x00, 0x00},
	{0x36, 0x00, 0x00, 0x00}
};
#pragma endregion

#pragma region Convert zone
string toHex(int item) {
	string tmp("");
	stringstream sstream;
	sstream << hex << item;
	tmp = sstream.str();
	if (tmp.length() == 1 && tolower(tmp[0]) == 'a') 
		tmp.insert(tmp.begin(), '0');
	return tmp;
}
string toDec(unsigned char *item) {
	string tmp("");
	stringstream sstream;
	unsigned char t1 = item[0];
	unsigned char t2 = item[1];
	unsigned char t3;
	if (t1 > '9')
		t1 = t1 - 87;
	else
		t1 = t1 - 48;

	if (t2 > '9')
		t2 = t2 - 87;
	else
		t2 = t2 - 48;

		t3 = t1 * 16 + t2 * 1;

	sstream << t3;
	tmp = sstream.str();
	return tmp;
}
bitset<8> hexToBin(string item) {
	unsigned temp;
	stringstream ss;
	ss << hex << item;
	ss >> temp;
	bitset<8> result(temp);
	return result;
}
string binToHex(bitset<8> item) {
	string result;
	stringstream ss;
	ss << hex << item.to_ulong();
	ss >> result;
	if (result.length() == 1)
		result.insert(result.begin(), '0');
	return result;
}
string ulToHex(unsigned long item) {
	string temp;
	stringstream ss;
	ss << hex << item;
	ss >> temp;
	if (temp.length() == 1)
		temp.insert(temp.begin(), '0');
	return temp;
}
#pragma endregion

string hexPlus(string A, string B, string C) {
	unsigned temp = 0;
	bitset<8> a = hexToBin(A);
	bitset<8> b = hexToBin(B);
	bitset<8> c = hexToBin(C);
	
	return binToHex(a ^ b ^ c);
}
void rotWord8b(string &item, short iter) {
	string temp("");
	size_t length = item.length() - 1;
	while (iter > 0) {
		temp = item[0]; temp += item[1];
		item += temp;
		item = string(item.begin() + 2, item.end());
		--iter;
	};
}
uint8_t gmult(uint8_t a, uint8_t b) {

	uint8_t p = 0, i = 0, hbs = 0;

	for (i = 0; i < 8; i++) {
		if (b & 1) {
			p ^= a;
		}

		hbs = a & 0x80;
		a <<= 1;
		if (hbs) a ^= 0x1b; // 0000 0001 0001 1011	
		b >>= 1;
	}

	return (uint8_t)p;
}
void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d) {

	d[0] = gmult(a[0], b[0]) ^ gmult(a[3], b[1]) ^ gmult(a[2], b[2]) ^ gmult(a[1], b[3]);
	d[1] = gmult(a[1], b[0]) ^ gmult(a[0], b[1]) ^ gmult(a[3], b[2]) ^ gmult(a[2], b[3]);
	d[2] = gmult(a[2], b[0]) ^ gmult(a[1], b[1]) ^ gmult(a[0], b[2]) ^ gmult(a[3], b[3]);
	d[3] = gmult(a[3], b[0]) ^ gmult(a[2], b[1]) ^ gmult(a[1], b[2]) ^ gmult(a[0], b[3]);
}
#pragma endregion

#pragma region Interface

vector<string> splitText(string origin, unsigned blocksize) {
	vector<string> blocks;

	for (unsigned i = 0; i < origin.size(); i += blocksize) {
		if ((i % blocksize) == 0) {
			blocks.push_back("");
			int index = i / blocksize;
			for (unsigned j = i; j < i + blocksize && j < origin.size(); j++)
				blocks[index] += origin[j];
		}
	}

	return blocks;
}
string md5(string password) {
	string result("");
	Poco::MD5Engine engine;

	engine.update(password);
	Poco::DigestEngine::Digest dig = engine.digest();
	
	for (auto const& it : dig) {
		stringstream sstream;
		sstream << hex << (unsigned)it;
		if (sstream.str().size() == 1)
			result += "0";
		result += sstream.str();
	}
	
	return result;
}

void makeRoundKeys(vector<string> &roundKeys, const string cipherKey) {
	roundKeys = vector<string>(10);
	roundKeys.insert(roundKeys.begin(), cipherKey);
	for (int i = 1; i < 11; i++)
		roundKeys[i] = string(32, '0');

	for (int i = 1; i < 11; i++) {
		string Wi = "";
		string Wi_4 = "";
		string Rcon = "";

		//making first column
		//of a 4-word key
		for (int j = 6; j < 32; j += 8) {
			Wi += roundKeys[i-1][j];
			Wi += roundKeys[i-1][j + 1];
		}

		for (int j = 0; j < 32; j += 8) {
			Wi_4 += roundKeys[i - 1][j];
			Wi_4 += roundKeys[i - 1][j + 1];
		}

		for (int j = 0; j < 4; j++) {
			Rcon += ulToHex(rcon[i-1][j]);
		}

		rotWord8b(Wi, 1);
		subBytes(Wi);
		
		//XORing the columns
		string temp("");
		for (int j = 0; j < 8; j += 2) {
			string A, B, C;
			(A = Wi_4[j]) += Wi_4[j + 1];
			(B = Wi[j])	  +=   Wi[j + 1];
			(C = Rcon[j]) += Rcon[j + 1];
			temp += hexPlus(A, B, C);
		}
		
		//push the temp-column in
		for (int j = 0, k = 0; j < 32, k < 8; j += 8, k += 2) {
			roundKeys[i][j] = temp[k];
			roundKeys[i][j + 1] = temp[k+1];
		}
		//end of the making
		//of the first column


		//making the next three columns
		//mostly like before without 
		//adding the cipher-key
		for (int j = 2; j < 8; j += 2) {
			Wi = "";	Wi_4 = ""; temp = "";

			for (int k = j; k < 32; k += 8) {
				Wi += roundKeys[i][k - 2];
				Wi += roundKeys[i][k - 1];
			}
			
			for (int k = j; k < 32; k += 8) {
				Wi_4 += roundKeys[i-1][k];
				Wi_4 += roundKeys[i-1][k + 1];
			}


			for (int k = 0; k < 8; k += 2) {
				string A(""), B("");
				(A = Wi_4[k]) += Wi_4[k + 1];
				(B = Wi[k]) += Wi[k + 1];
				temp += hexPlus(A, B, "00");
			}

			for (int k = j, l = 0; k < 32, l < 8; k += 8, l += 2) {
				roundKeys[i][k] = temp[l];
				roundKeys[i][k + 1] = temp[l + 1];
			}
		}
	}

}

void subBytes(string& block) {
	size_t lenght = block.length();
	string temp("");
	for (int i = 0; i < lenght; i += 2) {
		unsigned x, y = x = 0;
		string tX, tY = tX = "";

		tX = block[i]; tY = block[i + 1];
		x = stoi(tX, nullptr, 16);
		y = stoi(tY, nullptr, 16);
		if (toHex(sBox[x][y]).length() == 1)
			temp += "0";
		temp += toHex(sBox[x][y]);
	}
	block = temp;
}
void invSubBytes(string& block) {
	size_t lenght = block.length();
	string temp("");
	for (int i = 0; i < lenght; i += 2) {
		unsigned x, y = x = 0;
		string tX, tY = tX = "";

		tX = block[i]; tY = block[i + 1];
		x = stoi(tX, nullptr, 16);
		y = stoi(tY, nullptr, 16);
		if (toHex(invSbox[x][y]).length() == 1)
			temp += "0";
		temp += toHex(invSbox[x][y]);
	}
	block = temp;
}

void shiftRows(string& block) {
	size_t length = block.length();

	string temp = "";

	for (int i = 0; i < length; i+=8) {
		string row = "";
		for (int j = 0; (j < 8) && (j+i < length); j++) {
			row += block[i + j];
		}
		rotWord8b(row, i / 8);
		temp += row;
	}

	block = temp;
}
void invShiftRows(string& block) {
	size_t length = block.length();

	string temp = "";

	for (int i = 0; i < length; i += 8) {
		string row = "";
		for (int j = 0; (j < 8) && (j + i < length); j++) {
			row += block[i + j];
		}
		rotWord8b(row, 4 - (i / 8));
		temp += row;
	}

	block = temp;
}

void mixColumns(string& block) {
	// a(x) = {02} + {01}x + {01}x2 + {03}x3
	uint8_t a[] = { 0x02, 0x01, 0x01, 0x03 };

	uint8_t col[4], res[4];

	for (int i = 0; i < 8; i += 2) {
		for (int j = i; j < 32; j += 8) {
			string temp = "";
			temp = block[j];
			temp += block[j + 1];
			col[j / 8] = (uint8_t)hexToBin(temp).to_ulong();
		}

		coef_mult(a, col, res);

		for (int j = i; j < 32; j += 8) {
			string temp = "";
			temp = ulToHex(res[j / 8]);
			block[j] = temp[0];
			block[j + 1] = temp[1];
		}
	}
}
void invMixColumns(string& block) {
	// a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
	uint8_t a[] = { 0x0e, 0x09, 0x0d, 0x0b };

	uint8_t col[4], res[4];

	for (int i = 0; i < 8; i += 2) {
		for (int j = i; j < 32; j += 8) {
			string temp = "";
			temp = block[j];
			temp += block[j + 1];
			col[j / 8] = (uint8_t)hexToBin(temp).to_ulong();
		}

		coef_mult(a, col, res);

		for (int j = i; j < 32; j += 8) {
			string temp = "";
			temp = ulToHex(res[j / 8]);
			block[j] = temp[0];
			block[j + 1] = temp[1];
		}
	}
}

void addRoundKey(string& block, const string key) {
	size_t length = block.length();
	string temp(32, '0');
	for (int i = 0; i < 8; i += 2) {
		string col = "", keyCol = "", res = "";
		for (int j = i; j < length; j += 8) {
			col += block[j];
			col += block[j + 1];
		}

		for (int j = i; j < length; j += 8) {
			keyCol += key[j];
			keyCol += key[j + 1];
		}

		for (int j = 0; j < 8; j+=2) {
			string A, B, C = "00";
			A = col[j]; A += col[j + 1];
			B = keyCol[j]; B += keyCol[j + 1];
			res += hexPlus(A, B, C);
		}

		for (int j = i, k = 0; j < length, k < 8; j += 8, k += 2) {
			temp[j] = res[k];
			temp[j+1] = res[k+1];
		}
	}
	block = temp;
}

#pragma endregion