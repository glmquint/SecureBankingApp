#ifndef CRYPTOUTIL_H
#define CRYPTOUTIL_H

#include "../util/Logger.h"
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define LOGIN_CMD "LOGIN"
#define ECHO_CMD  "ECHO:"
#define HELLO_CMD "HELLO"
#define CMDLEN 5
#define NONCELEN 8

#define BUFFER_SIZE 4096
#define SIGNLEN 384
#define NONCELEN 8
#define DHPARLEN 1190
#define TTL 300
#define SALT_SIZE 8
#define IVLEN EVP_CIPHER_iv_length(EVP_aes_128_cbc())
#define SHA256LEN EVP_MD_size(EVP_sha256())
#define AES128LEN EVP_CIPHER_key_length(EVP_aes_128_cbc())

std::string Base64Encode(const unsigned char* data, size_t length);
unsigned char* Base64Decode(const std::string& encodedData, size_t& outLength);
EVP_PKEY* readPrivateKey(std::string filepath, std::string password);
EVP_PKEY *generateDHKey();
void securefree(unsigned char *buffer, int len);
unsigned char *createNonce();
unsigned char *derivateDHSharedSecret(EVP_PKEY *my_key, EVP_PKEY *other_key, unsigned char *nonce_1, unsigned char *nonce_2);
unsigned char *convertToUnsignedChar(EVP_PKEY *pkey, int *length);
EVP_PKEY* convertToEVP_PKEY(const unsigned char* keyData, size_t keyLength);
unsigned char * generate_IV();
unsigned char *getHash(unsigned char *msg, size_t len, unsigned char *salt, const EVP_MD *shaAlgo);
unsigned char *signMsg(EVP_PKEY *privkey, const unsigned char *hash, const size_t hash_len);
unsigned char * AESencrypt(const unsigned char* buffer, size_t bufferSize, const unsigned char* key, const unsigned char* iv,int& ciphertextlen);
unsigned char * AESdecrypt(const unsigned char* ciphertext, size_t ciphertextSize, const unsigned char* key, const unsigned char* iv,int& plaintextlen);
EVP_PKEY* readPublicKey(std::string filepath);
int verify_signature(EVP_PKEY *pubkey, const unsigned char *signature,
                    const size_t signature_len, const unsigned char *hash,
                    const size_t hash_len);
std::string decryptCipherText(unsigned char *buffer,int cipherSize,unsigned char * session_key,unsigned char * HMACKey);
unsigned char * createCiphertext(std::string msg, unsigned char* sharedSecret,
                                unsigned char** IV, unsigned char** to_hashed,
                                unsigned char** HMAC,unsigned char * HMACKey, unsigned char** to_enc, int* length, int* enc_len);
unsigned char * getHMAC(unsigned char *msg, const int msg_len,unsigned char *key,unsigned int &digestlen);
bool verifyHash(unsigned char* calculatedHash, unsigned char * receivedHash,const EVP_MD * shaAlgo);

std::string consume(std::string &buffer, size_t num);
// // Given an EVP_PKEY, converts it to unsigned char * return also the length of the unsigned char* buffer
// unsigned char *convertToUnsignedChar(EVP_PKEY *pkey, int *length) {
    // unsigned char *buffer = nullptr;
    // BIO *bio = BIO_new(BIO_s_mem());

    // if (bio != nullptr) {
        // if (PEM_write_bio_PUBKEY(bio, pkey) == 1) {
            // *length = BIO_pending(bio);
            // buffer = new unsigned char[*length];
            // BIO_read(bio, buffer, *length);
        // }

        // BIO_free(bio);
    // }

    // return buffer;
// }

class Nonce
{
private:
    unsigned char* m_nonce;
public:
    Nonce();
    Nonce(int nonce_len);
    Nonce(const Nonce &nonce);
    unsigned char* get();
    ~Nonce();
};



#endif