#pragma once

#include "targetver.h"

#include <locale>
#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

#include <vector>
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>

using namespace std;

string toHex(int);
string toDec(unsigned char*);

vector<string> splitText(string, unsigned);

string md5(const string);

void makeRoundKeys(vector<string>&, const string);

void subBytes(string&);
void shiftRows(string&);
void mixColumns(string&);
void addRoundKey(string&, const string);