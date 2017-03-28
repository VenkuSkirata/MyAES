#include <stdint.h>

namespace AES {
	void encrypt(uint8_t* text, uint8_t* cipherKey);
	void decrypt(uint8_t* text, uint8_t* cipherKey);
}