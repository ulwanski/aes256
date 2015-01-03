#include "aes.h"

AES::AES(unsigned char *key){
    aesEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    aesDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));

    EVP_CIPHER_CTX_init(aesEncryptCtx);
    EVP_CIPHER_CTX_init(aesDecryptCtx);

	this->aesKey = (unsigned char*)malloc(AES_KEYLEN/8);
	memcpy(this->aesKey, key, AES_KEYLEN/8);
}

AES::AES(std::string *key){
    aesEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
    aesDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));

    EVP_CIPHER_CTX_init(aesEncryptCtx);
    EVP_CIPHER_CTX_init(aesDecryptCtx);

	this->aesKey = (unsigned char*)malloc(AES_KEYLEN/8);
	memcpy(this->aesKey, key->c_str(), AES_KEYLEN/8);
}

AES::~AES(){
    EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
    EVP_CIPHER_CTX_cleanup(aesDecryptCtx);
	free(aesKey);
}

void AES::sha256(const char *string, unsigned char *hash){
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
}

int AES::GenerateKey(unsigned char **aesKey){
	*aesKey = (unsigned char*)malloc(AES_KEYLEN/8);
	RAND_bytes(*aesKey, AES_KEYLEN/8);
	return AES_KEYLEN/8;
}

int AES::GenerateKey(std::string *aesKey){
	unsigned char *buffer = (unsigned char*)malloc(AES_KEYLEN/8);
	RAND_bytes(buffer, AES_KEYLEN/8);
	aesKey->clear();
	aesKey->append((const char*)buffer);
	aesKey->shrink_to_fit();
	free(buffer);
	return AES_KEYLEN/8;
}

int AES::AESKeyFromPassword(unsigned char **aesKey, char *password){
	*aesKey = (unsigned char*)malloc(AES_KEYLEN/8);
	AES::sha256(password, *aesKey);
	return AES_KEYLEN/8;
}

int AES::AESKeyFromPassword(std::string *aesKey, std::string *password){
	unsigned char *buffer = (unsigned char*)malloc(AES_KEYLEN/8);
	AES::sha256(password->c_str(), buffer);
	aesKey->clear();
	aesKey->append((const char*)buffer);
	aesKey->shrink_to_fit();
	free(buffer);
	return AES_KEYLEN/8;
}

int AES::AESKeyFromPassword(std::string *aesKey, const char *password){
	unsigned char *buffer = (unsigned char*)malloc(AES_KEYLEN/8);
	AES::sha256(password, buffer);
	aesKey->clear();
	aesKey->append((const char*)buffer);
	aesKey->shrink_to_fit();
	free(buffer);
	return AES_KEYLEN/8;
}

int AES::Encrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg, unsigned char **aesIV){
	size_t blockLen  = 0;
    size_t encMsgLen = 0;
	*aesIV = (unsigned char*)malloc(AES_IVLEN);
	if(RAND_bytes(*aesIV, AES_IVLEN) == 0) return 0;
 
    *encMsg = (unsigned char*)malloc(msgLen + AES_BLOCK_SIZE);
    if(encMsg == NULL) return 0;
 
    if(!EVP_EncryptInit_ex(aesEncryptCtx, EVP_aes_256_cbc(), NULL, aesKey, *aesIV)) return 0;
    if(!EVP_EncryptUpdate(aesEncryptCtx, *encMsg, (int*)&blockLen, (unsigned char*)msg, msgLen)) return 0;
    encMsgLen += blockLen;
    if(!EVP_EncryptFinal_ex(aesEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen)) return 0;
    EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
    return encMsgLen + blockLen;
}

int AES::Decrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char **decMsg, unsigned char *aesIV){
	size_t decLen   = 0;
    size_t blockLen = 0;
 
    *decMsg = (unsigned char*)malloc(encMsgLen);
    if(*decMsg == NULL) return 0;
 
    if(!EVP_DecryptInit_ex(aesDecryptCtx, EVP_aes_256_cbc(), NULL, this->aesKey, aesIV)) return 0;
    if(!EVP_DecryptUpdate(aesDecryptCtx, (unsigned char*)*decMsg, (int*)&blockLen, encMsg, (int)encMsgLen)) return 0;
    decLen += blockLen;
    if(!EVP_DecryptFinal_ex(aesDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen)) return 0;
    decLen += blockLen;
    EVP_CIPHER_CTX_cleanup(aesDecryptCtx);
    return (int)decLen;
}

int AES::Encrypt(std::FILE* inFile, std::FILE* outFile, unsigned char **aesIV, unsigned int bufferSize){
    int encMsgLen = 0;
	*aesIV = (unsigned char*)malloc(AES_IVLEN);
	if(RAND_bytes(*aesIV, AES_IVLEN) == 0) return 0;
    if(!EVP_EncryptInit_ex(aesEncryptCtx, EVP_aes_256_cbc(), NULL, aesKey, *aesIV)) return 0;
	
	// Multiple of 16 bytes buffers
	unsigned char *bufferIn  = (unsigned char*)malloc(bufferSize);
	unsigned char *bufferOut = (unsigned char*)malloc(bufferSize);
	
	int readLength = 0, writeLength = 0;

	while( ( readLength = std::fread(bufferIn ,sizeof(char), AES_BUFSIZE, inFile) ) > 0){
		if(!EVP_EncryptUpdate(aesEncryptCtx, bufferOut, &writeLength, bufferIn, readLength)) return 0;
		fwrite(bufferOut, sizeof(unsigned char), writeLength, outFile);
		encMsgLen += writeLength;
	}

    if(!EVP_EncryptFinal_ex(aesEncryptCtx, bufferOut, &writeLength)) return 0;
	fwrite(bufferOut, sizeof(unsigned char), writeLength, outFile);

    EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
	free(bufferIn);
	free(bufferOut);
    return encMsgLen + writeLength;
}

int AES::Decrypt(std::FILE* inFile, std::FILE* outFile, unsigned char *aesIV, unsigned int bufferSize){
	size_t decLen   = 0;
    size_t blockLen = 0;
 
    if(!EVP_DecryptInit_ex(aesDecryptCtx, EVP_aes_256_cbc(), NULL, this->aesKey, aesIV)) return 0;

	// Multiple of 16 bytes buffers
	unsigned char *bufferIn  = (unsigned char*)malloc(bufferSize);
	unsigned char *bufferOut = (unsigned char*)malloc(bufferSize);
 
	int readLength = 0, writeLength = 0;

	while( ( readLength = std::fread(bufferIn ,sizeof(char), AES_BUFSIZE, inFile) ) > 0){
		if(!EVP_DecryptUpdate(aesDecryptCtx, bufferOut, &writeLength, bufferIn, readLength)) return 0;
		fwrite(bufferOut, sizeof(unsigned char), writeLength, outFile);
		decLen += blockLen;
	}

    if(!EVP_DecryptFinal_ex(aesDecryptCtx, bufferOut, &writeLength)) return 0;
	fwrite(bufferOut, sizeof(unsigned char), writeLength, outFile);

    decLen += blockLen;
    EVP_CIPHER_CTX_cleanup(aesDecryptCtx);
	free(bufferIn);
	free(bufferOut);
    return (int)decLen;
}

