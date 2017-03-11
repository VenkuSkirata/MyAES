#pragma once

#include "targetver.h"

#include <locale>
#include <vector>
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>
#include <chrono>
#include <bitset>

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

using namespace std;

string toHex(bitset<8> item);
string toHex(unsigned long item);
bitset<8> hexToBin(string item);

vector<string> splitText(string, unsigned);

string md5(const string);

void subBytes(string&);
void invSubBytes(string&);

void shiftRows(string&);
void invShiftRows(string&);

void mixColumns(string&);
void invMixColumns(string&);

void makeRoundKeys(vector<string>& dest, const string key);
void addRoundKey(string& block, const string key);