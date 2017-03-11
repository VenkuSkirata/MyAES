#include "stdafx.h"
using namespace chrono;
struct File {
private:
	string	 m_name;
	string	 m_text;
	bool	 m_isOpened;
	
public:
	File() = default;
	File(string name) :
		m_name(name), m_text("") {
		if (open(name))
			cout << "File opened.\n";
		else 
			cout << "Error opening file\n";

	}
	~File() = default;

	bool open(string name) {
		fstream file(name.c_str(), fstream::in);
		if (file.is_open()) {
			m_isOpened = true;
			string line;

			while (getline(file, line))
				m_text += line + '\n';

			file.close();
			return true;
		}
		return false;
	}
	bool save(string name) const {
		return save(name, m_text);
	}

	/*Encryption by AES with 128bit keylength
	*key - any value of any lenght */
	void encrypt(string password) {
		if (!m_isOpened) return;
		string cipherKey = md5(password); 
		string temp = "";

		//plain to hex
		for (unsigned i = 0; i < m_text.length(); i++)
				temp += toHex((unsigned char)m_text[i]);

		//making vector with 16byte-string
		auto blocks = splitText(temp, 32);

		//adding zeros at the end of the last 
		//item of vector in the case of length < 32
		while ((blocks.cend()-1)->length() < 32) {
			(blocks.end()-1)->push_back('0');
		}

		system_clock::time_point pointStart, pointEnd;
		pointStart = system_clock::now();
		//Ciphering
		vector<string> roundKeys;
		makeRoundKeys(roundKeys, cipherKey);
		for (int i = 0; i < blocks.size(); i++) {
			addRoundKey(blocks[i], roundKeys[0]);
			for (int j = 0; j < 10; j++) {		
				subBytes(blocks[i]);				
				shiftRows(blocks[i]);
				if (j < 9) mixColumns(blocks[i]);
				addRoundKey(blocks[i], roundKeys[j + 1]);
			}
		}
		pointEnd = system_clock::now();
		cout << "Encrypted in: " << duration_cast<milliseconds>(pointEnd - pointStart).count() << "ms" << endl;

		m_text = "";
		for (auto item : blocks) {
			m_text += item;
		}

	}

	/*Decryption by AES with 128bit keylength
	*key - any value of any lenght */
	void decrypt(string key) {
		if (!m_isOpened) return;
		string temp("");
		vector<string> roundKeys;
		string cipherKey = md5(key);
				
		//deciphering
		makeRoundKeys(roundKeys, cipherKey);
		auto blocks = splitText(m_text, 32);

		for (int i = 0; i < blocks.size(); i++) {
			addRoundKey(blocks[i], roundKeys[10]);
			for (int j = 9; j >= 0; j--) {
				invShiftRows(blocks[i]);
				invSubBytes(blocks[i]);
				addRoundKey(blocks[i], roundKeys[j]);
				if (j != 0)
					invMixColumns(blocks[i]);
			}
		}

		//hex to plain
		temp = "";
		for (int i = 0; i < blocks.size(); i++) {
			string word = "";
			for (int j = 0; j < 32; j += 2) {
				word = blocks[i][j];
				word += blocks[i][j+1];
				if (word != "00")
					temp += static_cast<unsigned char>(hexToBin(word.c_str()).to_ulong());
			}
		}
		m_text = move(temp);
	}

	string getText() const {
		return m_text;
	}
	bool setText(string text) {
		m_text = text;
	}

private:
	bool save(string path, string text) const {
		fstream file(path, fstream::out);
		if (file.is_open()) {
			file << text;
			file.close();
			return true;
		}
		return false;
	}
};

int _tmain(int argc, _TCHAR* argv[])
{
	setlocale(LC_ALL, "Russian");

	File file = File("./Resources/file");

	file.encrypt("1111");

	file.decrypt("1111");
	
	file.save("./Resources/plain.txt");
	system("pause");
	return 0;
}

