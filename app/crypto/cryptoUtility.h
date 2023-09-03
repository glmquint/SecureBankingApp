#include "util.h"

#define SIGNLEN 384
#define NONCELEN 8
#define COMMAND_SIZE 4
#define DHPARLEN 1190
#define TTL 300
#define SALT_SIZE 8
#define IVLEN EVP_CIPHER_iv_length(EVP_aes_128_cbc())
#define SHA256LEN EVP_MD_size(EVP_sha256())
#define AES128LEN EVP_CIPHER_key_length(EVP_aes_128_cbc())


bool verifyHash(unsigned char* calculatedHash, unsigned char * receivedHash,const EVP_MD * shaAlgo);
unsigned char * getHash(unsigned char * msg, size_t len, unsigned char * salt,const EVP_MD * shaAlgo);
EVP_PKEY* readPublicKey(std::string filepath);
EVP_PKEY* readPrivateKey(std::string filepath, std::string password);
unsigned char * AESencrypt(const unsigned char* buffer, size_t bufferSize, const unsigned char* key, const unsigned char* iv,int & ciphertextlen);
unsigned char * AESdecrypt(const unsigned char* ciphertext, size_t ciphertextSize, const unsigned char* key, const unsigned char* iv,int& plaintextlen);
unsigned char * RSAEncrypt(EVP_PKEY* publicKey,unsigned char * plaintext, size_t plaintextlen);
unsigned char * RSAdecrypt(EVP_PKEY* privateKey, unsigned char * ciphertext,int& plaintextlen);
unsigned char * generateAESKey();
unsigned char * generate_IV();
void securefree(unsigned char * buffer,int len);
unsigned char * createDigitalEnvelope(EVP_PKEY * publick,std::string command, unsigned char* content, size_t content_size, int sender,int& ciphertextlen);
unsigned char* decryptDigitalEnvelope(EVP_PKEY * privk, unsigned char * buffer,int len, int &plainTextLen);
EVP_PKEY *generateDHKey();
unsigned char * derivateDHSharedSecret(EVP_PKEY *my_key, EVP_PKEY *other_key, unsigned char* nonce_1, unsigned char* nonce_2);
void printEVPKey(EVP_PKEY* pkey);
unsigned char *signMsg(EVP_PKEY *privkey, const unsigned char *hash, const size_t hash_len);
int verify_signature(EVP_PKEY *pubkey, const unsigned char *signature,
                    const size_t signature_len, const unsigned char *hash,
                    const size_t hash_len);
EVP_PKEY* convertToEVP_PKEY(const unsigned char* keyData, size_t keyLength);
unsigned char *convertToUnsignedChar(EVP_PKEY *pkey, int *length);
void printBufferHex(const unsigned char* buffer, size_t size);
unsigned char * createNonce();
unsigned char * createCiphertext(std::string msg, int id, unsigned char* sharedSecret,
                                unsigned char** IV, unsigned char** to_hashed,
                                unsigned char** HMAC, unsigned char * HMACKey, unsigned char** to_enc, int* length, int* enc_len);
std::string decryptCipherText(unsigned char *buffer,int cipherSize,unsigned char * session_key,unsigned char * HMACKey);
unsigned char * getHMAC(unsigned char *msg, const int msg_len,unsigned char *key,unsigned int &digestlen);
bool encryptFile(EVP_PKEY* pubKey, string clear_buff, string targetPath);
string decryptFile(EVP_PKEY * privateKey, string clearFilePath);

