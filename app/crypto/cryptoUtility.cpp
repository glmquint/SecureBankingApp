#include "cryptoUtility.h"

// Given two hashes check if they are equals with the shaAlgo algorithm
bool verifyHash(unsigned char* calculatedHash, unsigned char * receivedHash,const EVP_MD * shaAlgo){
    if(CRYPTO_memcmp(calculatedHash, receivedHash,EVP_MD_size(shaAlgo)) == 0)
        return true;
    
    return false;
}

// Given a unsigned char * of length len and a salt "salt", return the hash of the msg with the shaAlgo algorithm
unsigned char * getHash(unsigned char * msg, size_t len, unsigned char * salt,const EVP_MD * shaAlgo){
    unsigned char* digest;
    unsigned int digestlen;
    EVP_MD_CTX* ctx;
    /* Buffer allocation for the digest */
    digest = (unsigned char*)malloc(EVP_MD_size(shaAlgo));
    if(!digest){
        DEBUG_PRINT(("Failed malloc!"));
        return nullptr;
    }
    /* Context allocation */ 
    ctx = EVP_MD_CTX_new();
    if(!ctx){
        DEBUG_PRINT(("Failed context allocation!"));
        return nullptr;
    }
    EVP_DigestInit(ctx, shaAlgo);
    if(salt){
        EVP_DigestUpdate(ctx, salt, SALT_SIZE);
    }
    DEBUG_PRINT(("Msg size: %lu",len));
    EVP_DigestUpdate(ctx, msg, len); 
    EVP_DigestFinal(ctx, digest, &digestlen);
    EVP_MD_CTX_free(ctx);
    DEBUG_PRINT(("Digest is:"));
    //printBufferHex(digest, digestlen);
    return digest;
}

// Given a path return the public key stored in the file
EVP_PKEY* readPublicKey(std::string filepath) {
    EVP_PKEY* pubkey = nullptr;
    FILE* file = fopen(filepath.c_str(), "r");
    DEBUG_PRINT(("Keypath %s",filepath.c_str()));
    if (!file) {
        DEBUG_PRINT(("Public key not found!"));
        return pubkey;
    }
    pubkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    if (!pubkey) {
        DEBUG_PRINT(("PEM_read_PUBKEY failed!"));
        fclose(file);
        return pubkey;
    }
    fclose(file);
    return pubkey;
}

// Given a path return the private key, access is permitted with the use of the password
EVP_PKEY* readPrivateKey(std::string filepath, std::string password) {
    EVP_PKEY* prvkey=nullptr;
    FILE* file = fopen(filepath.c_str(), "r");
    if(!file) { 
        DEBUG_PRINT(("Private key not found!"));
        return prvkey;
    }
    prvkey= PEM_read_PrivateKey(file, NULL, NULL, const_cast<char*>(password.c_str()));
    if(!prvkey) { 
        DEBUG_PRINT(("PEM_read_PrivateKey failed!"));
        fclose(file);
        return prvkey;
    }
    fclose(file);
    return prvkey;
}

// Encrypts the buffer with AES-128 in CBC mode, return the ciphertext and the ciphertext length
unsigned char * AESencrypt(const unsigned char* buffer, size_t bufferSize, const unsigned char* key, const unsigned char* iv,int& ciphertextlen) {
    // Initialize the encryption context
    const int blockLength = EVP_CIPHER_block_size(EVP_aes_128_cbc());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        DEBUG_PRINT(("Error in EVP_CIPHER_CTX_new()!"));
        return nullptr;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
        DEBUG_PRINT(("Error in EVP_EncryptInit_ex()!"));
        return nullptr;
    }

    // Determine the required output buffer size
    int maxOutputLength = bufferSize + blockLength;
    unsigned char* outputBuffer = (unsigned char *)malloc(maxOutputLength);
    int outputLength = 0;

    // Perform the encryption
    if(EVP_EncryptUpdate(ctx, outputBuffer, &outputLength, buffer, bufferSize)!=1){
        DEBUG_PRINT(("Error in EVP_EncryptUpdate()!"));
        return nullptr;
    }

    // Finalize the encryption
    int finalOutputLength = 0;
    EVP_EncryptFinal_ex(ctx, outputBuffer + outputLength, &finalOutputLength);
    outputLength += finalOutputLength;
    ciphertextlen=outputLength;
    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    return outputBuffer;
}

// Decrypt the buffer with AES-128 in CBC mode, return the plaintext and the plaintext length
unsigned char * AESdecrypt(const unsigned char* ciphertext, size_t ciphertextSize, const unsigned char* key, const unsigned char* iv,int& plaintextlen) {
    //const int blockLength = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        DEBUG_PRINT(("Error in EVP_CIPHER_CTX_new()!"));
        return nullptr;
    }

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
        DEBUG_PRINT(("Error in EVP_DecryptInit_ex()!"));
        return nullptr;
    }

    // Determine the required output buffer size
    int maxOutputLength = ciphertextSize;
    unsigned char* outputBuffer = (unsigned char *)malloc(maxOutputLength);
    int outputLength = 0;

    // Perform the decryption
    if(EVP_DecryptUpdate(ctx, outputBuffer, &outputLength, ciphertext, ciphertextSize)!=1){
        DEBUG_PRINT(("Error in EVP_DecryptUpdate()!"));
        return nullptr;
    }

    // Finalize the decryption
    int finalOutputLength = 0;
    EVP_DecryptFinal_ex(ctx, outputBuffer + outputLength, &finalOutputLength);
    outputLength += finalOutputLength;
    plaintextlen=outputLength;
    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    return outputBuffer;
}

// Use RSA to encrypt a message plaintext of length plaintextlen with the public key publicKey
unsigned char * RSAEncrypt(EVP_PKEY* publicKey,unsigned char * plaintext, size_t plaintextlen) {
    if(!plaintext || ! publicKey){
        DEBUG_PRINT(("Error, missing public key or message"));
        return nullptr;
    }
    RSA* rsaPublicKey = NULL;
    rsaPublicKey = EVP_PKEY_get1_RSA(publicKey);

    int encryptedSize = RSA_size(rsaPublicKey);
    // Allocate memory for the ciphertext
    unsigned char* ciphertext = (unsigned char *)malloc(encryptedSize);
    if(!ciphertext){
        DEBUG_PRINT(("Failed malloc!"));
        RSA_free(rsaPublicKey);
        return nullptr;
    }
    // Encrypt the plaintext
    if(RSA_public_encrypt(plaintextlen,plaintext,ciphertext,rsaPublicKey,RSA_PKCS1_OAEP_PADDING)==-1){
        DEBUG_PRINT(("Error in RSA_public_encrypt()"));
        free(ciphertext);
        RSA_free(rsaPublicKey);
        return nullptr;
    }
    RSA_free(rsaPublicKey);
    return ciphertext;
}

// Use RSA to decrypt a message ciphertext with the private key privateKey, return also the length of the plaintext
unsigned char * RSAdecrypt(EVP_PKEY* privateKey, unsigned char * ciphertext,int& plaintextlen) {
    if(!ciphertext || ! privateKey){
        DEBUG_PRINT(("Error, missing private key or ciphertext"));
        return nullptr;
    }
    RSA* rsaPrivateKey = NULL;
    rsaPrivateKey = EVP_PKEY_get1_RSA(privateKey);
    int decryptedSize = RSA_size(rsaPrivateKey);
    // Allocate memory for the plaintext
    unsigned char* plaintext = (unsigned char *)malloc(decryptedSize);
    if(!plaintext){
        DEBUG_PRINT(("Failed malloc!"));
        RSA_free(rsaPrivateKey);
        return nullptr;
    }
    int plaintextSize=RSA_private_decrypt(decryptedSize,ciphertext,plaintext,rsaPrivateKey,RSA_PKCS1_OAEP_PADDING);
    if(plaintextSize==-1){
        DEBUG_PRINT(("Error in RSA_private_decrypt()"));
        free(ciphertext);
        RSA_free(rsaPrivateKey);
        return nullptr;
    }
    plaintextlen=plaintextSize;
    RSA_free(rsaPrivateKey);
    return plaintext;
}

// Generate a random AES key for AES 128 cbc
unsigned char * generateAESKey(){
    int key_len= EVP_CIPHER_key_length(EVP_aes_128_cbc());
    unsigned char * key = (unsigned char *)malloc(key_len);
    int ret = RAND_bytes(key, key_len);
    if (ret != 1 || !key){
        DEBUG_PRINT(("Failed mallor or RAND_bytes!"));
        free(key);
        return nullptr;
    }
    return key;
}

// Generate a random IV used for AES 128
unsigned char * generate_IV(){
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    DEBUG_PRINT(("Iv len %d",iv_len));
    unsigned char *iv = (unsigned char *)malloc(iv_len);
    int ret = RAND_bytes(iv, iv_len);
    if (ret != 1 || !iv){
        DEBUG_PRINT(("Failed mallor or RAND_bytes!"));
        free(iv);
        return nullptr;
    }
    return iv;
}

// Free a buffer of length len, set the memory to 0 before freeing
void securefree(unsigned char * buffer,int len){
    memset(buffer,0,len);
    free(buffer);
    buffer = nullptr;
}

// Generate the digital envelope of a message "content" of length content_size
// return also the length of the envelope, a command "command" is concat-ed at the beginning of the final buffer
unsigned char * createDigitalEnvelope(EVP_PKEY * publick,std::string command, unsigned char* content, size_t content_size, int sender,int& ciphertextlen){
    if(!publick){
        DEBUG_PRINT(("Could not load public key"));
        return nullptr;
    }
    // Generate the AES key and IV
    unsigned char * simkey=generateAESKey();
    unsigned char * iv=generate_IV();
    int keylen=EVP_CIPHER_key_length(EVP_aes_128_cbc());
    int ivlen=EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    if(!simkey || ! iv){
        return nullptr;
    }
    int ciphlen=0;

    //Generate the ciphertext with AES 128 cbc
    unsigned char * ciphtxt=AESencrypt(content, content_size,simkey,iv,ciphlen);
    if(!ciphtxt){
        securefree(iv,ivlen);
        securefree(simkey,keylen);
        return nullptr;
    }

    // Concat IV and AES key to be encrypted with RSA
    unsigned char * ivAndKey = (unsigned char *)malloc(keylen+ivlen);
    if(!ivAndKey){
        DEBUG_PRINT(("Failed malloc!"));
        securefree(iv,ivlen);
        securefree(simkey,keylen);
        return nullptr;
    }

    memcpy(ivAndKey,iv,ivlen);
    memcpy(ivAndKey+ivlen,simkey,keylen);

    // Encrypt IV and AES key
    unsigned char * keyEnv=RSAEncrypt(publick,ivAndKey,ivlen+keylen);

    securefree(iv,ivlen);
    securefree(simkey,keylen);
    securefree(ivAndKey,keylen+ivlen);
    if(!keyEnv){
        return nullptr;
    }
    // Generate the final message CMD + IV&AESkey with RSA + ciphertext with AES 128
    int cmdlen=command.size()+1;
    int bufferlen=cmdlen+EVP_PKEY_size(publick)+ciphlen;
    unsigned char * toSend = (unsigned char *)malloc(bufferlen);
    if(!toSend){
        DEBUG_PRINT(("Failed malloc!"));
        securefree(keyEnv,EVP_PKEY_size(publick));
        return nullptr;
    }

    // Free memory and return the message
    DEBUG_PRINT(("Command len createDigitalEnvelope %lu %lu ",sizeof(command), command.size()+1));
    memcpy(toSend,(unsigned char *)command.c_str(),command.size()+1);
    memcpy(toSend+cmdlen,keyEnv,EVP_PKEY_size(publick));
    memcpy(toSend+cmdlen+EVP_PKEY_size(publick),ciphtxt,ciphlen);
    securefree(ciphtxt,ciphlen);
    securefree(keyEnv,EVP_PKEY_size(publick));
    ciphertextlen=bufferlen;
    return toSend;
}

// Return the content of the digital envelope contained in buffer of length len
// also return the length of the resulting plaintext 
unsigned char* decryptDigitalEnvelope(EVP_PKEY * privk, unsigned char * buffer,int len, int &plainTextLen){
    if(!privk){
        DEBUG_PRINT(("Could not load private key"));
        return nullptr;
    }
    DEBUG_PRINT(("Key size %d",EVP_PKEY_size(privk)));

    //generate the buffer for containing the RSA and AES part
    unsigned char * envelope = (unsigned char *) malloc(EVP_PKEY_size(privk));
    unsigned char * ciptxt = (unsigned char *) malloc(len-EVP_PKEY_size(privk));
    if(!envelope || !ciptxt){
        DEBUG_PRINT(("Failed malloc"));
        return nullptr;
    }
    memcpy(envelope,buffer,EVP_PKEY_size(privk));
    memcpy(ciptxt,buffer+EVP_PKEY_size(privk),len-EVP_PKEY_size(privk));

    // Decrypt the RSA part
    int keylen=0;
    unsigned char * simkeyAndIv=RSAdecrypt(privk,envelope,keylen);
    if(!simkeyAndIv){
        securefree(envelope,EVP_PKEY_size(privk));
        securefree(ciptxt,len-EVP_PKEY_size(privk));
        return nullptr;
    }

    // Get the AES key and IV
    unsigned char * key = (unsigned char *) malloc(EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    unsigned char * iv = (unsigned char *) malloc(EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
    if(!key || !iv){
        securefree(simkeyAndIv,keylen);
        DEBUG_PRINT(("Failed malloc"));
        return nullptr;
    }
    memcpy(iv,simkeyAndIv,EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
    memcpy(key,simkeyAndIv+EVP_CIPHER_iv_length(EVP_aes_128_cbc()),EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
    securefree(simkeyAndIv,keylen);

    // Decrypt the ciphertext with the key and IV previously obtained
    int lenclt=0;
    unsigned char * cltxt=AESdecrypt(ciptxt,len-EVP_PKEY_size(privk),key,iv,lenclt);   
    plainTextLen = lenclt;

    // Free remaining memory and return the cleartext
    securefree(key,EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    securefree(iv,EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
    securefree(envelope,EVP_PKEY_size(privk));
    securefree(ciptxt,len-EVP_PKEY_size(privk));

    if(!cltxt){
        return nullptr;
    }
    return cltxt;
}

// Generate the DH key
EVP_PKEY *generateDHKey(){

    EVP_PKEY *DH_params = NULL;
    EVP_PKEY *DH_pub_key = NULL;

    
    DH_params = EVP_PKEY_new();
    if(!DH_params){
        printf("Error in generating DH params\n");
        return NULL;
    }
    DH* default_DH = DH_get_2048_224();
    int ret = EVP_PKEY_set1_DH(DH_params,default_DH);
    if(ret != 1){
        printf("Error in setting the dh params\n");
        EVP_PKEY_free(DH_params);
        return NULL;
    }

    EVP_PKEY_CTX* ctx_DH = EVP_PKEY_CTX_new(DH_params, nullptr);
    if (!ctx_DH){
        printf("Error in setting the public key algorithm context\n");
        EVP_PKEY_free(DH_params);
        EVP_PKEY_CTX_free(ctx_DH);
        return NULL;
    }

    EVP_PKEY_keygen_init(ctx_DH);
    ret = EVP_PKEY_keygen(ctx_DH, &DH_pub_key);
    if (ret != 1){
        printf("Error in generating the key\n");
        EVP_PKEY_free(DH_params);
        EVP_PKEY_CTX_free(ctx_DH);
        return NULL;
    }
    
    DH_free(default_DH);
    EVP_PKEY_CTX_free(ctx_DH);
    EVP_PKEY_free(DH_params);
    printEVPKey(DH_pub_key);
    return DH_pub_key;
}

// Given two DH public key, generate the shared secret, nonces are use to introduce freshness
unsigned char * derivateDHSharedSecret(EVP_PKEY *my_key, EVP_PKEY *other_key, unsigned char* nonce_1, unsigned char* nonce_2){

    EVP_PKEY_CTX *ctx_key = EVP_PKEY_CTX_new(my_key, nullptr);
    if (!ctx_key){
        fprintf(stderr, "Error in allocating the context\n");
        return NULL;
    }

    unsigned char *shared_secret = nullptr;
    size_t secret_length = 0;

    int ret = EVP_PKEY_derive_init(ctx_key);
    if(ret != 1){
        fprintf(stderr, "Error in initializing context for DH secret derivation\n");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    ret = EVP_PKEY_derive_set_peer(ctx_key, other_key);
    if(ret != 1){
        fprintf(stderr, "Error in setting the peer\'s public key for Diffie-Hellman secret derivation\n");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }
    
    ret = EVP_PKEY_derive(ctx_key, nullptr, &secret_length);
    if(ret != 1){
        fprintf(stderr, "Error in deriving the secret length\n");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    shared_secret = (unsigned char *)malloc(secret_length);
    
    if(!shared_secret){
        fprintf(stderr, "Failed malloc\n");
        EVP_PKEY_CTX_free(ctx_key);
        return NULL;
    }

    ret = EVP_PKEY_derive(ctx_key, shared_secret, &secret_length);

    EVP_PKEY_CTX_free(ctx_key);
    if (ret != 1){
        fprintf(stderr, "Error in deriving the shared secret\n");
        securefree(shared_secret,secret_length);
        return NULL;
    }
    DEBUG_PRINT(("Shared secret in base64\n %s\n",Base64Encode(shared_secret, secret_length).c_str()));

    // Concat the derived share secret and the nonces
    unsigned char * fresh_shared_secret = (unsigned char *)malloc(secret_length + 2 * NONCELEN);
    memcpy(fresh_shared_secret, shared_secret, secret_length);
    memcpy(fresh_shared_secret+secret_length, nonce_1, NONCELEN);
    memcpy(fresh_shared_secret+secret_length+NONCELEN, nonce_2, NONCELEN);
    securefree(shared_secret, secret_length);

    // hash the share secret and nonces
    unsigned char *secretHashed = getHash(fresh_shared_secret,secret_length + 2 * NONCELEN,nullptr,EVP_sha384());
    if(!secretHashed){
        securefree(fresh_shared_secret,secret_length + 2 * NONCELEN);
        return nullptr;
    }
    
    securefree(fresh_shared_secret,secret_length + 2 * NONCELEN);
    return secretHashed;
}

// Given a public key then prints it
void printEVPKey(EVP_PKEY* pkey) {
    if (pkey == nullptr) {
        std::cout << "EVP_PKEY is nullptr" << std::endl;
        return;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        std::cout << "Failed to create BIO" << std::endl;
        return;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        std::cout << "Failed to write EVP_PKEY to BIO" << std::endl;
        BIO_free_all(bio);
        return;
    }

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    DEBUG_PRINT(("EVP_PKEY contents:\n %s",bufferPtr->data));
    
    BIO_free_all(bio);
}

// Given a hash message of length hash_len, sign it with the private key
unsigned char *signMsg(EVP_PKEY *privkey, const unsigned char *hash, const size_t hash_len){
    if(!privkey){
        fprintf(stderr, "Error private key is not existent\n");
        return NULL;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();    
    if(!ctx){
        fprintf(stderr, "Error in allocating digest\n");
        return NULL;
    }
    int ret = EVP_SignInit(ctx,EVP_sha256());
    if(ret != 1){
        fprintf(stderr, "Error in initializing the digest\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    ret = EVP_SignUpdate(ctx, hash, hash_len);
    if (ret != 1){
        fprintf(stderr, "Error in updating the digest\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    unsigned int signature_len = EVP_PKEY_size(privkey);
    DEBUG_PRINT(("Signature len: %i\n", signature_len));

    unsigned char * signature = (unsigned char *)malloc(signature_len);
    if(!signature){
        fprintf(stderr, "Failed malloc\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    ret = EVP_SignFinal(ctx, signature, &signature_len, privkey);
    DEBUG_PRINT(("%i\n", signature_len));
    if (ret != 1){
        fprintf(stderr, "Error in signing the digest\n");
        EVP_MD_CTX_free(ctx);
        free(signature);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);

    DEBUG_PRINT(("SIGNATURE\n %s\n", Base64Encode(signature, signature_len).c_str()));
    return signature;
}

// Given a received signature of length signature_len, confront it with a given hash of length hash_len
int verify_signature(EVP_PKEY *pubkey, const unsigned char *signature,
                    const size_t signature_len, const unsigned char *hash,
                    const size_t hash_len){
    
    if(!pubkey){
        fprintf(stderr, "Error public key is not existent\n");
        return -1;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();    
    if(!ctx){
        fprintf(stderr, "Error in allocating digest\n");
        return -1;
    }

    int ret = EVP_VerifyInit(ctx, EVP_sha256());
    if(ret != 1){
        fprintf(stderr, "Error in initializing the digest\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_VerifyUpdate(ctx, hash, hash_len);
    if (ret != 1){
        fprintf(stderr, "Error in updating the digest\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }


    ret = EVP_VerifyFinal(ctx, signature, signature_len, pubkey);
    if (ret == 0){
        printf("Signature not valid\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    else if(ret ==-1){
        fprintf(stderr, "Error in verifing the signature\n");
        EVP_MD_CTX_free(ctx);
        return -1; 
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

// Given an unsigned char * of length keyLength, converts it to EVP_PKEY 
EVP_PKEY* convertToEVP_PKEY(const unsigned char* keyData, size_t keyLength) {
    // Load private key data into a BIO
    BIO* bio = BIO_new_mem_buf(keyData, keyLength);

    // Read the private key from the BIO
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    printEVPKey(key);
    // Clean up the BIO
    BIO_free(bio);

    return key;
}

// Given an EVP_PKEY, converts it to unsigned char * return also the length of the unsigned char* buffer
unsigned char *convertToUnsignedChar(EVP_PKEY *pkey, int *length) {
    unsigned char *buffer = nullptr;
    BIO *bio = BIO_new(BIO_s_mem());

    if (bio != nullptr) {
        if (PEM_write_bio_PUBKEY(bio, pkey) == 1) {
            *length = BIO_pending(bio);
            buffer = new unsigned char[*length];
            BIO_read(bio, buffer, *length);
        }

        BIO_free(bio);
    }

    return buffer;
}

// Given a buffer of length size, prints it to Hex format
void printBufferHex(const unsigned char* buffer, size_t size) {
    std::cout << "Hex:" << std::endl;
    
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(buffer[i]) << " ";
        
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    
    std::cout << std::dec << std::endl;
    std::cout<<"Size: "<<size<<std::endl;
}

// Generate the nonces
unsigned char * createNonce(){
    unsigned char * nonce = (unsigned char*)malloc(NONCELEN);
    if(!RAND_bytes(nonce, NONCELEN)){
        free(nonce);
        printf("RAND_bytes failure\n");
        return nullptr;
    }
    return nonce;
}

// Given a message msg, encrypts it with AES 128 cbc using sharedSecret as encryption key and HMACKey as HMAC key
// the other parameters are used to help manage memory in the above calls, also return length of the plaintext and ciphertext
unsigned char * createCiphertext(std::string msg, int id, unsigned char* sharedSecret,
                                unsigned char** IV, unsigned char** to_hashed,
                                unsigned char** HMAC,unsigned char * HMACKey, unsigned char** to_enc, int* length, int* enc_len){
    
    int to_enc_len = msg.length() + 1;

    *IV = generate_IV();
    if(!*IV){
        fprintf(stderr, "error in generating the IV\n");
        return nullptr;
    }

    *to_enc = (unsigned char*)malloc(to_enc_len);
    if(!*to_enc){
        fprintf(stderr, "error in generating the buffer for encryption\n");
        return nullptr;
    }
    memcpy(*to_enc, msg.c_str(), msg.length()+1);

    int AES_len = 0;
    unsigned char* cipherText = AESencrypt(*to_enc, to_enc_len, sharedSecret, *IV, AES_len);
    if(!cipherText){
        fprintf(stderr, "error in generating the cipherText\n");
        return nullptr;
    }
    
    int to_hashed_len = IVLEN + AES_len + 1;
    *to_hashed = (unsigned char*)malloc(to_hashed_len);
    if(!*to_hashed){
        fprintf(stderr, "error in generating the buffer of the MAC\n");
        return nullptr;
    }
    *to_hashed[0] = (unsigned char)id;
    memcpy(*to_hashed+1, *IV, IVLEN);
    memcpy(*to_hashed+IVLEN+1, cipherText, AES_len);
    unsigned int digestLen=0;
    *HMAC = getHMAC(*to_hashed,to_hashed_len,HMACKey,digestLen);

    if(!*HMAC){
        fprintf(stderr, "error in generating the MAC\n");
        return nullptr;
    }
    
    unsigned char* concat_msg = (unsigned char*)malloc(1+IVLEN+SHA256LEN+AES_len);
    concat_msg[0]=(unsigned char)id;
    memcpy(concat_msg+1, *IV, IVLEN);
    memcpy(concat_msg+IVLEN+1, *HMAC, SHA256LEN);
    memcpy(concat_msg+SHA256LEN+IVLEN+1, cipherText, AES_len);

    securefree(cipherText, AES_len);
    
    *length = 1+IVLEN+SHA256LEN+AES_len;
    *enc_len = AES_len;
    DEBUG_PRINT(("sended %d ct bytes %d\n", *length, AES_len));
    return concat_msg;

}

// Decrypt a cipherText contained in buffer of length cipherSize, use session_key and HMACKey as decrypt key for
// AES 128 and HMAC key
std::string decryptCipherText(unsigned char *buffer,int cipherSize,unsigned char * session_key,unsigned char * HMACKey) {
    unsigned char * IV = (unsigned char *)malloc(IVLEN);
    memcpy(IV,buffer+1,IVLEN);
    int decrypted_size=0;
    unsigned char * decrypted = AESdecrypt(buffer+IVLEN+SHA256LEN+1,cipherSize,session_key,IV,decrypted_size);
    if(!decrypted){
        securefree(IV,IVLEN);
        return "";
    }
    DEBUG_PRINT(("decrypted len %d",decrypted_size));
    unsigned char * hash_received = (unsigned char *)malloc(SHA256LEN);
    memcpy(hash_received,buffer+1+IVLEN,SHA256LEN);

    unsigned char * to_hashed = (unsigned char *)malloc(IVLEN+cipherSize+1);
    to_hashed[0]=buffer[0];
    memcpy(to_hashed+1,IV,IVLEN);
    memcpy(to_hashed+IVLEN+1,buffer+1+IVLEN+SHA256LEN,cipherSize);
    unsigned int lenMAC=0;
    unsigned char * calculatedHash = getHMAC(to_hashed,IVLEN+cipherSize+1,HMACKey,lenMAC);
    securefree(IV,IVLEN);
    if(!verifyHash(calculatedHash,hash_received,EVP_sha256())){
        DEBUG_PRINT(("Error, calculated hash != computed hash"));
        securefree(hash_received,SHA256LEN);
        securefree(to_hashed,IVLEN+decrypted_size-SHA256LEN);
        securefree(calculatedHash,SHA256LEN);
        return "";
    }
    securefree(hash_received,SHA256LEN);
    securefree(to_hashed,IVLEN+decrypted_size+1);
    securefree(calculatedHash,SHA256LEN);
    std::string operation = buildStringFromUnsignedChar(decrypted,decrypted_size);
    securefree(decrypted,decrypted_size);
    return operation;
}

// Generate the HMAC with the key "key"
unsigned char * getHMAC(unsigned char *msg, const int msg_len,unsigned char *key,unsigned int &digestlen){
    unsigned char * digest = (unsigned char *)malloc(SHA256LEN);
    if(!digest){
        return nullptr;
    }
    return HMAC(EVP_sha256(),key,SHA256LEN, msg, msg_len,digest, &digestlen);
}

// Encrypt a plaintext with the pubKey (use digital envelope) and write it to targetPath
bool encryptFile(EVP_PKEY* pubKey, string clear_buff, string targetPath){
    if(!pubKey){
        cerr<<"Error in getting the public key for file enc\n";
        return false;
    }

    int ciphlen=0;
    unsigned char * cptxt=createDigitalEnvelope(pubKey,("ENC"),(unsigned char *)clear_buff.c_str(), clear_buff.length()+1, 0, ciphlen);
    if(!cptxt){
        cerr<<"Error in generating the encrtyption for the file\n";
        return false;
    }
    DEBUG_PRINT(("CT in base64 %s", Base64Encode(cptxt, ciphlen).c_str()));
    /*unsigned char * hash = getHash(cptxt, ciphlen, nullptr, EVP_sha256());
    if(!hash){
        cerr<<"Error in allocating the hash buffer\n";
        return "";
    }
    unsigned char * concat_msg = (unsigned char*)malloc(SHA256LEN+ciphlen);
    if(!concat_msg){
        cerr<<"Error in allocating the hash buffer\n";
        securefree(hash, SHA256LEN);
        return "";
    }
    memcpy(concat_msg, hash, SHA256LEN);
    memcpy(concat_msg+SHA256LEN, cptxt, ciphlen);
    securefree(hash, SHA256LEN);
    securefree(cptxt, ciphlen);
    writeBinaryFile(targetPath, concat_msg, SHA256LEN + ciphlen);
    securefree(concat_msg, ciphlen+SHA256LEN);*/

    writeBinaryFile(targetPath, cptxt, ciphlen);
    securefree(cptxt, ciphlen);
    return true;

}

// Decrypt a file at cipherFilePath with the use of the private key (use digital envelope)
string decryptFile(EVP_PKEY* privKey, string cipherFilePath){
    if(!privKey){
        cerr<<"Error in getting the private key for file enc\n";
        return "";
    }
    int file_len = 0;
    unsigned char * file_buf = readBinaryFile(cipherFilePath, &file_len);
    if(!file_buf){
        cerr<<"Couldn't open the file\n";
        return "";
    }

    /*unsigned char * hash = (unsigned char*)malloc(SHA256LEN);
    if(!hash){
        cerr<<"Error in allocating the hash buffer\n";
        return "";
    }*/
    //unsigned char * cptxt = (unsigned char*)malloc(file_len-SHA256LEN);
    unsigned char * cptxt = (unsigned char*)malloc(file_len);
    if(!cptxt){
        cerr<<"Error in allocating the cptxt buffer\n";
        return "";
    }
    //memcpy(hash, file_buf, SHA256LEN);
    //memcpy(cptxt, file_buf+SHA256LEN, file_len-SHA256LEN);
    memcpy(cptxt, file_buf, file_len);
    securefree(file_buf, file_len);

    /*unsigned char * computedHash =  getHash(cptxt, file_len-SHA256LEN, nullptr, EVP_sha256());

    if(!verifyHash(computedHash, hash, EVP_sha256())){
        securefree(computedHash,SHA256LEN);
        securefree(hash,SHA256LEN);
        cerr<<"Hash not corresponding, file corrupted\n";
        return "";
    }
    securefree(computedHash,SHA256LEN); 
    securefree(hash,SHA256LEN);*/    
    int ptlen=0;
    //unsigned char * clear_buf = decryptDigitalEnvelope(privKey, cptxt+COMMAND_SIZE, file_len-COMMAND_SIZE-SHA256LEN, ptlen);
    unsigned char * clear_buf = decryptDigitalEnvelope(privKey, cptxt+COMMAND_SIZE, file_len-COMMAND_SIZE, ptlen);
    //securefree(cptxt,file_len-SHA256LEN);
    securefree(cptxt,file_len);
    string response =  buildStringFromUnsignedChar(clear_buf,ptlen);
    securefree(clear_buf, ptlen);
    return response;

}