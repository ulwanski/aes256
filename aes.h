#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <string>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEYLEN  256
#define AES_IVLEN   16
#define AES_ROUNDS  6
#define AES_BUFSIZE 8192000 // 7,81 MB

class AES {

	private:
    EVP_CIPHER_CTX *aesEncryptCtx;
    EVP_CIPHER_CTX *aesDecryptCtx;
	unsigned char *aesKey;
	
	public:
	AES(unsigned char *key);
	AES(std::string *key);
	~AES();
	static int GenerateKey(unsigned char **aesKey);
	static int GenerateKey(std::string *aesKey);
	static int AESKeyFromPassword(unsigned char **aesKey, char *password);
	static int AESKeyFromPassword(std::string *aesKey, std::string *password);
	static int AESKeyFromPassword(std::string *aesKey, const char *password);
	int Encrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg, unsigned char **aesIV);
	int Decrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char **decMsg, unsigned char *aesIV);
	int Encrypt(std::FILE* inFile, std::FILE* outFile, unsigned char **aesIV, unsigned int bufferSize = AES_BUFSIZE);
	int Decrypt(std::FILE* inFile, std::FILE* outFile, unsigned char *aesIV,  unsigned int bufferSize = AES_BUFSIZE);

	private:
	static void sha256(const char *string, unsigned char outputBuffer[65]);

};

#endif
