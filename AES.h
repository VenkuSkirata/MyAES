#include <stdint.h>
#include <string>

namespace AES {
	void encrypt(uint8_t* block, const uint8_t* cipherKey);
	void encrypt(char* block, const uint8_t* cipherKey);
	void encrypt(std::string block, const uint8_t* cipherKey);
	void encrypt(uint8_t* block, const char* cipherKey);
	void encrypt(char* block, const char* cipherKey);
	void encrypt(std::string block, const char* cipherKey);
	void encrypt(uint8_t* block, const std::string cipherKey);
	void encrypt(char* block, const std::string cipherKey);
	void encrypt(std::string block, const std::string cipherKey);

	
	void decrypt(uint8_t* block, const uint8_t* cipherKey);
	void decrypt(char* block, const uint8_t* cipherKey);
	void decrypt(std::string block, const uint8_t* cipherKey);
	void decrypt(uint8_t* block, const char* cipherKey);
	void decrypt(char* block, const char* cipherKey);
	void decrypt(std::string block, const char* cipherKey);
	void decrypt(uint8_t* block, const std::string cipherKey);
	void decrypt(char* block, const std::string cipherKey);
	void decrypt(std::string block, const std::string cipherKey);
}