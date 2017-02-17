#include "stdafx.h"

enum FileMode {
	RO,
	WO,
	RW
};

struct File {
private:
	string	 m_name;
	string	 m_text;
	FileMode m_mode;
	bool	 m_isOpened;
public:
	File() = default;
	File(string name, FileMode mode) :
		m_name(name), m_mode(mode), m_text("") {
		if (open(name, mode))
			cout << "File opened.\n";
		else 
			cout << "Error opening file\n";

	}
	~File() = default;

	bool open(string name, FileMode mode) {
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
		fstream file(name, fstream::out);
		if (file.is_open()) {
			file << m_text;
			file.close();
			return true;
		}
		return false;
	}

	void encrypt(string password) {
		auto blocks = splitText(m_text, 16);
		//string cipherKey = md5(password);
		string cipherKey = "2b28ab097eaef7cf15d2154f16a6883c";
		m_text = "";
		for (unsigned i = 0; i < blocks.size(); i++)
			for (auto it : blocks[i]) 
				m_text += toHex((unsigned char)it);

		blocks = splitText(m_text, 32);
		
		vector<string> roundKeys;
		makeRoundKeys(roundKeys, cipherKey);
		/*
		for(int i = 0; i < 10; i++) {
			subBytes(blocks[i]);
			shiftRows(blocks[i]);
			if(i > 10) mixColumns(blocks[i]);
			addRoundKey(blocks[i], roundKeys[i]);
		}
		*/
		m_text = "";
		for (auto item : roundKeys) {
			m_text += item + "\n--------------------\n";
		}
		save("Keys.txt");
	}
	void decrypt(string key) {
		string temp("");
		for (unsigned i = 0; i < m_text.size() - 1; i += 2) {
			unsigned char textChar[2];
			textChar[0] = (unsigned char) m_text[i];
			textChar[1] = (unsigned char) m_text[i + 1];
			temp += toDec(textChar);
		}
		m_text = temp;
	}

	string getText() const {
		return m_text;
	}
	bool setText(string text) {
		m_text = text;
	}
};

int _tmain(int argc, _TCHAR* argv[])
{
	setlocale(LC_ALL, "Russian");

	File file = File("./Resources/file", RW);

	file.encrypt("1111");
	file.decrypt("1111");
	
	cout << "=========\n" << file.getText() << "\n=========\n";

	system("pause");
	return 0;
}

