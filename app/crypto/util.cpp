#include "util.h"

// Given a unsigned char * buffer of length "length",
// return the equivalent Base64 string used for debugging purposes
std::string Base64Encode(const unsigned char *data, size_t length)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *base64Bio = BIO_new(BIO_f_base64());
    BIO_push(base64Bio, bio);

    // Disable line breaks in the Base64 output
    BIO_set_flags(base64Bio, BIO_FLAGS_BASE64_NO_NL);

    // Write the data to the BIO
    BIO_write(base64Bio, data, length);
    BIO_flush(base64Bio);

    // Determine the size of the encoded data
    long bioSize = BIO_get_mem_data(bio, nullptr);

    // Create a string and read the encoded data from the BIO
    std::string encodedData(bioSize, '\0');
    BIO_read(bio, (void *)encodedData.data(), bioSize);

    // Cleanup
    BIO_free_all(base64Bio);

    return encodedData;
}
// Given a string in Bas64 format it decodes it, return a unsigned char *
unsigned char *Base64Decode(const std::string &encodedData, size_t &outLength)
{
    // Create a BIO object for reading from the encoded string
    BIO *bio = BIO_new_mem_buf(encodedData.c_str(), encodedData.length());
    BIO *base64Bio = BIO_new(BIO_f_base64());
    BIO_push(base64Bio, bio);

    // Disable line breaks in the Base64 input
    BIO_set_flags(base64Bio, BIO_FLAGS_BASE64_NO_NL);

    // Determine the size of the decoded data
    size_t maxDecodedLength = encodedData.length() / 4 * 3; // Conservative estimate
    unsigned char *decodedData = new unsigned char[maxDecodedLength];

    // Perform the Base64 decoding
    outLength = BIO_read(base64Bio, decodedData, encodedData.length());

    // Cleanup
    BIO_free_all(base64Bio);

    return decodedData;
}
// Given a path return the private key, access is permitted with the use of the password
EVP_PKEY *readPrivateKey(std::string filepath, std::string password)
{
    EVP_PKEY *prvkey = nullptr;
    FILE *file = fopen(filepath.c_str(), "r");
    if (!file)
    {
        Logger::error("Private key not found!");
        return prvkey;
    }
    prvkey = PEM_read_PrivateKey(file, NULL, NULL, const_cast<char *>(password.c_str()));
    if (!prvkey)
    {
        Logger::error("PEM_read_PrivateKey failed!");
        fclose(file);
        return prvkey;
    }
    fclose(file);
    return prvkey;
}
// Generate the DH key
EVP_PKEY *generateDHKey()
{

    EVP_PKEY *DH_params = NULL;
    EVP_PKEY *DH_pub_key = NULL;

    DH_params = EVP_PKEY_new();
    if (!DH_params)
    {
        Logger::error("Error in generating DH params");
        return NULL;
    }
    DH *default_DH = DH_get_2048_224();
    int ret = EVP_PKEY_set1_DH(DH_params, default_DH);
    if (ret != 1)
    {
        Logger::error("Error in setting the dh params");
        EVP_PKEY_free(DH_params);
        return NULL;
    }

    EVP_PKEY_CTX *ctx_DH = EVP_PKEY_CTX_new(DH_params, nullptr);
    if (!ctx_DH)
    {
        Logger::error("Error in setting the public key algorithm context");
        EVP_PKEY_free(DH_params);
        EVP_PKEY_CTX_free(ctx_DH);
        return NULL;
    }

    EVP_PKEY_keygen_init(ctx_DH);
    ret = EVP_PKEY_keygen(ctx_DH, &DH_pub_key);
    if (ret != 1)
    {
        Logger::error("Error in generating the key");
        EVP_PKEY_free(DH_params);
        EVP_PKEY_CTX_free(ctx_DH);
        return NULL;
    }

    DH_free(default_DH);
    EVP_PKEY_CTX_free(ctx_DH);
    EVP_PKEY_free(DH_params);
    return DH_pub_key;
}

// Free a buffer of length len, set the memory to 0 before freeing
void securefree(unsigned char *buffer, int len)
{
    memset(buffer, 0, len);
    free(buffer);
    buffer = nullptr;
}
// Generate the HMAC with the key "key"
unsigned char *getHMAC(unsigned char *msg, const int msg_len, unsigned char *key, unsigned int &digestlen)
{
    unsigned char *digest = (unsigned char *)malloc(SHA256LEN);
    if (!digest)
    {
        return nullptr;
    }
    return HMAC(EVP_sha256(), key, SHA256LEN, msg, msg_len, digest, &digestlen);
}
// Given a message msg, encrypts it with AES 128 cbc using sharedSecret as encryption key and HMACKey as HMAC key
// the other parameters are used to help manage memory in the above calls, also return length of the plaintext and ciphertext
unsigned char *createCiphertext(std::string msg, unsigned char *sharedSecret,
                                unsigned char **IV, unsigned char **to_hashed,
                                unsigned char **HMAC, unsigned char *HMACKey, unsigned char **to_enc, int *length, int *enc_len)
{

    int to_enc_len = msg.length();

    *IV = generate_IV();
    if (!*IV)
    {
        fprintf(stderr, "error in generating the IV\n");
        return nullptr;
    }

    *to_enc = (unsigned char *)malloc(to_enc_len);
    if (!*to_enc)
    {
        fprintf(stderr, "error in generating the buffer for encryption\n");
        return nullptr;
    }
    memcpy(*to_enc, msg.c_str(), msg.length());

    int AES_len = 0;
    unsigned char *cipherText = AESencrypt(*to_enc, to_enc_len, sharedSecret, *IV, AES_len);
    if (!cipherText)
    {
        fprintf(stderr, "error in generating the cipherText\n");
        return nullptr;
    }

    int to_hashed_len = IVLEN + AES_len;
    *to_hashed = (unsigned char *)malloc(to_hashed_len);
    if (!*to_hashed)
    {
        fprintf(stderr, "error in generating the buffer of the MAC\n");
        return nullptr;
    }
    memcpy(*to_hashed, *IV, IVLEN);
    memcpy(*to_hashed + IVLEN, cipherText, AES_len);
    unsigned int digestLen = 0;
    *HMAC = getHMAC(*to_hashed, to_hashed_len, HMACKey, digestLen);

    if (!*HMAC)
    {
        fprintf(stderr, "error in generating the MAC\n");
        return nullptr;
    }

    unsigned char *concat_msg = (unsigned char *)malloc(IVLEN + SHA256LEN + AES_len);
    memcpy(concat_msg, *IV, IVLEN);
    memcpy(concat_msg + IVLEN, *HMAC, SHA256LEN);
    memcpy(concat_msg + SHA256LEN + IVLEN, cipherText, AES_len);

    securefree(cipherText, AES_len);

    *length = IVLEN + SHA256LEN + AES_len;
    *enc_len = AES_len;
    Logger::success("created ciphertext for " + msg + " payloading to: " + Base64Encode(concat_msg, (size_t)*length));
    Logger::debug("length: " + std::to_string(*length));
    Logger::debug("enc_len: " + std::to_string(*enc_len));
    return concat_msg;
}

// Given two hashes check if they are equals with the shaAlgo algorithm
bool verifyHash(unsigned char *calculatedHash, unsigned char *receivedHash, const EVP_MD *shaAlgo)
{
    Logger::info("verifying hashes... calculated: " + Base64Encode(calculatedHash, EVP_MD_size(shaAlgo)) + " received: " + Base64Encode(receivedHash, EVP_MD_size(shaAlgo)));
    if (CRYPTO_memcmp(calculatedHash, receivedHash, EVP_MD_size(shaAlgo)) == 0)
        return true;

    return false;
}

// Decrypt a cipherText contained in buffer of length cipherSize, use session_key and HMACKey as decrypt key for
// AES 128 and HMAC key
std::string decryptCipherText(unsigned char *buffer, int buflen, unsigned char *session_key, unsigned char *HMACKey)
{
    int cipherSize = buflen - IVLEN - SHA256LEN;
    unsigned char *IV = (unsigned char *)malloc(IVLEN);
    memcpy(IV, buffer, IVLEN);
    int decrypted_size = 0;
    unsigned char *decrypted = AESdecrypt(buffer + IVLEN + SHA256LEN, cipherSize, session_key, IV, decrypted_size);
    if (!decrypted)
    {
        securefree(IV, IVLEN);
        return "";
    }
    Logger::success("decrypted len " + std::to_string(decrypted_size));
    unsigned char *hash_received = (unsigned char *)malloc(SHA256LEN);
    memcpy(hash_received, buffer + IVLEN, SHA256LEN);

    unsigned char *to_hashed = (unsigned char *)malloc(IVLEN + cipherSize);
    memcpy(to_hashed, IV, IVLEN);
    memcpy(to_hashed + IVLEN, buffer + IVLEN + SHA256LEN, cipherSize);
    unsigned int lenMAC = 0;
    unsigned char *calculatedHash = getHMAC(to_hashed, IVLEN + cipherSize, HMACKey, lenMAC);
    securefree(IV, IVLEN);
    if (!verifyHash(calculatedHash, hash_received, EVP_sha256()))
    {
        Logger::error("Error, calculated hash != computed hash");
        securefree(hash_received, SHA256LEN);
        securefree(to_hashed, IVLEN + decrypted_size - SHA256LEN);
        securefree(calculatedHash, SHA256LEN);
        return "";
    }
    securefree(hash_received, SHA256LEN);
    securefree(to_hashed, IVLEN + decrypted_size);
    securefree(calculatedHash, SHA256LEN);
    std::string operation((char *)decrypted, decrypted_size);
    securefree(decrypted, decrypted_size);
    return operation;
}
// Given a received signature of length signature_len, confront it with a given hash of length hash_len
int verify_signature(EVP_PKEY *pubkey, const unsigned char *signature,
                     const size_t signature_len, const unsigned char *hash,
                     const size_t hash_len)
{

    Logger::info("verifying signature:");
    Logger::debug("signature: " + Base64Encode(signature, signature_len));
    Logger::debug("hash: " + Base64Encode(hash, hash_len));
    if (!pubkey)
    {
        Logger::error("Error public key is not existent");
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        Logger::error("Error in allocating digest");
        return -1;
    }

    int ret = EVP_VerifyInit(ctx, EVP_sha256());
    if (ret != 1)
    {
        Logger::error("Error in initializing the digest");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_VerifyUpdate(ctx, hash, hash_len);
    if (ret != 1)
    {
        Logger::error("Error in updating the digest");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_VerifyFinal(ctx, signature, signature_len, pubkey);
    if (ret == 0)
    {
        Logger::error("Signature not valid");
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    else if (ret == -1)
    {
        Logger::error("Error in verifing the signature");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    Logger::success("signature verified");
    EVP_MD_CTX_free(ctx);
    return 1;
}
// Given a path return the public key stored in the file
EVP_PKEY *readPublicKey(std::string filepath)
{
    EVP_PKEY *pubkey = nullptr;
    FILE *file = fopen(filepath.c_str(), "r");
    if (!file)
    {
        Logger::error("Public key not found!");
        return pubkey;
    }
    pubkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    if (!pubkey)
    {
        Logger::error("PEM_read_PUBKEY failed!");
        fclose(file);
        return pubkey;
    }
    fclose(file);
    return pubkey;
}
// Decrypt the buffer with AES-128 in CBC mode, return the plaintext and the plaintext length
unsigned char *AESdecrypt(const unsigned char *ciphertext, size_t ciphertextSize, const unsigned char *key, const unsigned char *iv, int &plaintextlen)
{
    // const int blockLength = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        Logger::error("Error in EVP_CIPHER_CTX_new()!");
        return nullptr;
    }

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1)
    {
        Logger::error("Error in EVP_DecryptInit_ex()!");
        return nullptr;
    }

    // Determine the required output buffer size
    int maxOutputLength = ciphertextSize;
    unsigned char *outputBuffer = (unsigned char *)malloc(maxOutputLength);
    int outputLength = 0;

    // Perform the decryption
    if (EVP_DecryptUpdate(ctx, outputBuffer, &outputLength, ciphertext, ciphertextSize) != 1)
    {
        Logger::error("Error in EVP_DecryptUpdate()!");
        return nullptr;
    }

    // Finalize the decryption
    int finalOutputLength = 0;
    EVP_DecryptFinal_ex(ctx, outputBuffer + outputLength, &finalOutputLength);
    outputLength += finalOutputLength;
    plaintextlen = outputLength;
    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    return outputBuffer;
}
// Encrypts the buffer with AES-128 in CBC mode, return the ciphertext and the ciphertext length
unsigned char *AESencrypt(const unsigned char *buffer, size_t bufferSize, const unsigned char *key, const unsigned char *iv, int &ciphertextlen)
{
    // Initialize the encryption context
    const int blockLength = EVP_CIPHER_block_size(EVP_aes_128_cbc());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        Logger::error("Error in EVP_CIPHER_CTX_new()!");
        return nullptr;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1)
    {
        Logger::error("Error in EVP_EncryptInit_ex()!");
        return nullptr;
    }

    // Determine the required output buffer size
    int maxOutputLength = bufferSize + blockLength;
    unsigned char *outputBuffer = (unsigned char *)malloc(maxOutputLength);
    int outputLength = 0;

    // Perform the encryption
    if (EVP_EncryptUpdate(ctx, outputBuffer, &outputLength, buffer, bufferSize) != 1)
    {
        Logger::error("Error in EVP_EncryptUpdate()!");
        return nullptr;
    }

    // Finalize the encryption
    int finalOutputLength = 0;
    EVP_EncryptFinal_ex(ctx, outputBuffer + outputLength, &finalOutputLength);
    outputLength += finalOutputLength;
    ciphertextlen = outputLength;
    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    return outputBuffer;
}
// Given a hash message of length hash_len, sign it with the private key
unsigned char *signMsg(EVP_PKEY *privkey, const unsigned char *hash, const size_t hash_len)
{
    if (!privkey)
    {
        Logger::error("Error private key is not existent");
        return NULL;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        Logger::error("Error in allocating digest");
        return NULL;
    }
    int ret = EVP_SignInit(ctx, EVP_sha256());
    if (ret != 1)
    {
        Logger::error("Error in initializing the digest");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    ret = EVP_SignUpdate(ctx, hash, hash_len);
    if (ret != 1)
    {
        Logger::error("Error in updating the digest");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    unsigned int signature_len = EVP_PKEY_size(privkey);

    unsigned char *signature = (unsigned char *)malloc(signature_len);
    if (!signature)
    {
        Logger::error("Failed malloc");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    ret = EVP_SignFinal(ctx, signature, &signature_len, privkey);
    if (ret != 1)
    {
        Logger::error("Error in signing the digest");
        EVP_MD_CTX_free(ctx);
        free(signature);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);

    Logger::success("SIGNATURE\n" + Base64Encode(signature, signature_len));
    return signature;
}
// Use RSA to encrypt a message plaintext of length plaintextlen with the public key publicKey
bool RSAEncrypt(EVP_PKEY* publickey, const unsigned char* plaintext, size_t plaintextlen, unsigned char*& ciphertext, size_t& ciphertextlen) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publickey, nullptr);
    if (!ctx) {
        return false;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 || EVP_PKEY_encrypt(ctx, nullptr, &ciphertextlen, plaintext, plaintextlen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    ciphertext = new unsigned char[ciphertextlen];

    if (EVP_PKEY_encrypt(ctx, ciphertext, &ciphertextlen, plaintext, plaintextlen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        delete[] ciphertext;
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

// Use RSA to decrypt a message ciphertext with the private key privateKey, return also the length of the plaintext
bool RSADecrypt(EVP_PKEY* privatekey, const unsigned char* ciphertext, size_t ciphertextlen, unsigned char*& plaintext, size_t& plaintextlen) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privatekey, nullptr);
    if (!ctx) {
        Logger::error("error with new ctx");
        return false;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 || EVP_PKEY_decrypt(ctx, nullptr, &plaintextlen, ciphertext, ciphertextlen) <= 0) {
        Logger::error("error while decrypt init");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    plaintext = new unsigned char[plaintextlen];

    if (EVP_PKEY_decrypt(ctx, plaintext, &plaintextlen, ciphertext, ciphertextlen) <= 0) {
        Logger::error("error while decrypt ");
        EVP_PKEY_CTX_free(ctx);
        delete[] plaintext;
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

// Given a unsigned char * of length len and a salt "salt", return the hash of the msg with the shaAlgo algorithm
unsigned char *getHash(unsigned char *msg, size_t len, unsigned char *salt, const EVP_MD *shaAlgo)
{
    unsigned char *digest;
    unsigned int digestlen;
    EVP_MD_CTX *ctx;
    /* Buffer allocation for the digest */
    digest = (unsigned char *)malloc(EVP_MD_size(shaAlgo));
    if (!digest)
    {
        Logger::error("Failed malloc!");
        return nullptr;
    }
    /* Context allocation */
    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        Logger::error("Failed context allocation!");
        return nullptr;
    }
    EVP_DigestInit(ctx, shaAlgo);
    if (salt)
    {
        EVP_DigestUpdate(ctx, salt, SALT_SIZE);
    }
    EVP_DigestUpdate(ctx, msg, len);
    EVP_DigestFinal(ctx, digest, &digestlen);
    EVP_MD_CTX_free(ctx);
    // Logger::info("Digest is:");
    // printBufferHex(digest, digestlen);
    return digest;
}
// Generate a random IV used for AES 128
unsigned char *generate_IV()
{
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    unsigned char *iv = (unsigned char *)malloc(iv_len);
    int ret = RAND_bytes(iv, iv_len);
    if (ret != 1 || !iv)
    {
        Logger::error("Failed malloc or RAND_bytes!");
        free(iv);
        return nullptr;
    }
    return iv;
}
// Given an EVP_PKEY, converts it to unsigned char * return also the length of the unsigned char* buffer
unsigned char *convertToUnsignedChar(EVP_PKEY *pkey, int *length)
{
    unsigned char *buffer = nullptr;
    BIO *bio = BIO_new(BIO_s_mem());

    if (bio != nullptr)
    {
        if (PEM_write_bio_PUBKEY(bio, pkey) == 1)
        {
            *length = BIO_pending(bio);
            buffer = new unsigned char[*length];
            BIO_read(bio, buffer, *length);
        }

        BIO_free(bio);
    }

    return buffer;
}

// Given two DH public key, generate the shared secret, nonces are use to introduce freshness
unsigned char *derivateDHSharedSecret(EVP_PKEY *my_key, EVP_PKEY *other_key, unsigned char *nonce_1, unsigned char *nonce_2)
{

    EVP_PKEY_CTX *ctx_key = EVP_PKEY_CTX_new(my_key, nullptr);
    if (!ctx_key)
    {
        Logger::error("Error in allocating the context");
        return NULL;
    }

    unsigned char *shared_secret = nullptr;
    size_t secret_length = 0;

    int ret = EVP_PKEY_derive_init(ctx_key);
    if (ret != 1)
    {
        Logger::error("Error in initializing context for DH secret derivation");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    ret = EVP_PKEY_derive_set_peer(ctx_key, other_key);
    if (ret != 1)
    {
        Logger::error("Error in setting the peer\'s public key for Diffie-Hellman secret derivation");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    ret = EVP_PKEY_derive(ctx_key, nullptr, &secret_length);
    if (ret != 1)
    {
        Logger::error("Error in deriving the secret length");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    shared_secret = (unsigned char *)malloc(secret_length);

    if (!shared_secret)
    {
        Logger::error("Failed malloc");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    ret = EVP_PKEY_derive(ctx_key, shared_secret, &secret_length);

    EVP_PKEY_CTX_free(ctx_key);
    if (ret != 1)
    {
        Logger::error("Error in deriving the shared secret");
        securefree(shared_secret, secret_length);
        return NULL;
    }
    Logger::success("Shared secret in base64\n" + Base64Encode(shared_secret, secret_length));

    // Concat the derived share secret and the nonces
    unsigned char *fresh_shared_secret = (unsigned char *)malloc(secret_length + 2 * NONCELEN);
    memcpy(fresh_shared_secret, shared_secret, secret_length);
    memcpy(fresh_shared_secret + secret_length, nonce_1, NONCELEN);
    memcpy(fresh_shared_secret + secret_length + NONCELEN, nonce_2, NONCELEN);
    securefree(shared_secret, secret_length);

    // hash the share secret and nonces
    unsigned char *secretHashed = getHash(fresh_shared_secret, secret_length + 2 * NONCELEN, nullptr, EVP_sha384());
    if (!secretHashed)
    {
        securefree(fresh_shared_secret, secret_length + 2 * NONCELEN);
        return nullptr;
    }

    securefree(fresh_shared_secret, secret_length + 2 * NONCELEN);
    return secretHashed;
}
// Generate the nonces
unsigned char *createNonce()
{
    unsigned char *nonce = (unsigned char *)malloc(NONCELEN);
    if (!RAND_bytes(nonce, NONCELEN))
    {
        free(nonce);
        printf("RAND_bytes failure\n");
        return nullptr;
    }
    return nonce;
}

// Given an unsigned char * of length keyLength, converts it to EVP_PKEY
EVP_PKEY *convertToEVP_PKEY(const unsigned char *keyData, size_t keyLength)
{
    // Load private key data into a BIO
    BIO *bio = BIO_new_mem_buf(keyData, keyLength);

    // Read the private key from the BIO
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    // Clean up the BIO
    BIO_free(bio);

    return key;
}

std::string consume(std::string &buffer, size_t num)
{
    std::string consumed;
    if (num > buffer.length())
    {
        Logger::error("not enough characters to consume");
    }
    else
    {
        consumed = buffer.substr(0, num);
        buffer.erase(0, num);
    }
    return consumed;
}

Nonce::Nonce() : m_nonce(nullptr)
{
}

Nonce::Nonce(int nonce_len) : m_nonce(nullptr)
{
    m_nonce = (unsigned char *)malloc(nonce_len);
    if (!RAND_bytes(m_nonce, nonce_len))
    {
        free(m_nonce);
        Logger::error("RAND_bytes failed");
    }
}

Nonce::Nonce(const Nonce &nonce)
{
    memcpy(m_nonce, nonce.m_nonce, NONCELEN);
}

Nonce::Nonce(unsigned char *nonce)
{
    m_nonce = (unsigned char*)malloc(NONCELEN);
    std::memcpy(m_nonce, nonce, NONCELEN);
}

unsigned char *Nonce::get()
{
    return m_nonce;
}

bool Nonce::operator==(const Nonce &other) const
{
    //printf("%x %x %x %x %x %x %x %x\n", m_nonce[0], m_nonce[1], m_nonce[2], m_nonce[3], m_nonce[4], m_nonce[5], m_nonce[6], m_nonce[7] );
    //printf("%x %x %x %x %x %x %x %x\n", other.m_nonce[0], other.m_nonce[1], other.m_nonce[2], other.m_nonce[3], other.m_nonce[4], other.m_nonce[5], other.m_nonce[6], other.m_nonce[7] );
    //std::fflush(stdout);
    if (m_nonce == nullptr)
        return false;
    return !std::memcmp(m_nonce, other.m_nonce, NONCELEN);
}

Nonce::~Nonce()
{
    free(m_nonce);
}