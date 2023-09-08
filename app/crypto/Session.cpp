#include "Session.h"
#include "../util/Logger.h"
#include "util.h"
#include <string>
#include <iostream>
#include <memory>



int Session::sendHandshakeMsg(std::string sent, unsigned char **nonce,
                          unsigned char **dh_uchar, EVP_PKEY **dh_pub, int& dh_pub_len)
{

    // Generate the DH key
    *dh_pub = generateDHKey();
    *dh_uchar = convertToUnsignedChar(*dh_pub, &dh_pub_len);
    if (dh_pub_len < 1)
    {
        Logger::error("Error in converting DH params");
        return -1;
    }
    Logger::info("Dh_pub_len is " + std::to_string(dh_pub_len));
    // Generate the nonce
    *nonce = createNonce();
    if (!*nonce)
    {
        Logger::error("Error generating the nonces");
        return -1;
    }
    Logger::info("nonce created: " + Base64Encode((const unsigned char*)*nonce, NONCELEN));

    // Generate the msg to send: Command/DH/NONCE/username
    std::string cmd = "HELLO";
    int msg_len = sent.size() + cmd.size() + DHPARLEN + NONCELEN + 2; //TODO: check if needed, also DHPARLEN != dh_pub_len
    unsigned char *msg = (unsigned char *)malloc(msg_len);
    if (!msg)
    {
        Logger::error("Error in allocating memory for the message");
        return -1;
    }
    memcpy(msg, (unsigned char *)cmd.c_str(), cmd.size());
    memcpy(msg + CMDLEN, *dh_uchar, dh_pub_len);
    memcpy(msg + CMDLEN + DHPARLEN, *nonce, NONCELEN);
    //memcpy(msg + CMDLEN + NONCELEN + dh_pub_len, (unsigned char *)sent.c_str(), sent.size() + 0);
    memcpy(msg + CMDLEN + DHPARLEN + NONCELEN, (unsigned char *)sent.c_str(), sent.size() + 0);

    // Send the message and return the socked descriptor
    // int sd = sendmsg(msg, msg_len);
    m_socketClient->sendData((const char *)msg, msg_len);
    securefree(msg, msg_len);
    return 0;
}




int Session::receiveServerHandshakeAnswer(unsigned char **nonce_server,
                                      unsigned char **dh_params_server, unsigned char **sharedSecret,
                                      EVP_PKEY **dh_pub, unsigned char *dh_client, unsigned char *nonce_client, int dh_uchar_len)
{

    // receive the login answer
    char *buffer = (char *)malloc(BUFFER_SIZE);
    int buffer_len;
    // int ret = read(sd, buffer, BUFFER_SIZE);
    m_socketClient->receiveData(buffer, buffer_len);

    // if the bytes read are few it means there is and ERR answer
    if (buffer_len < 8)
    {
        Logger::error("Error in login procedure");
        return -1;
    }

    // Generate the IV
    unsigned char *IV = (unsigned char *)malloc(IVLEN);
    memcpy(IV, buffer, IVLEN);
    Logger::debug("IV " + Base64Encode(IV, IVLEN));

    // Get the dh parameters from the server
    unsigned char *plainText_DH = (unsigned char *)malloc(DHPARLEN);
    memcpy(plainText_DH, buffer + IVLEN, DHPARLEN);
    Logger::debug("DHServer " + Base64Encode(plainText_DH, DHPARLEN));
    *dh_params_server = plainText_DH;

    // Get the nonce from the server
    unsigned char *plainText_Nonce = (unsigned char *)malloc(NONCELEN);
    memcpy(plainText_Nonce, buffer + IVLEN + DHPARLEN, NONCELEN);
    Logger::debug("Nonceserver " + Base64Encode(plainText_Nonce, NONCELEN));
    *nonce_server = plainText_Nonce;

    // Get the ciphertext from the received message
    unsigned char *cptxt = (unsigned char *)malloc(buffer_len - IVLEN - DHPARLEN - NONCELEN);
    memcpy(cptxt, buffer + IVLEN + DHPARLEN + NONCELEN, buffer_len - IVLEN - DHPARLEN - NONCELEN);
    securefree((unsigned char *)buffer, BUFFER_SIZE);

    // Convert the dh parameters from unsigned char* to EVP_PKEY and derive the shared secret
    EVP_PKEY *dh_server_pub = convertToEVP_PKEY(plainText_DH, DHPARLEN);
    *sharedSecret = derivateDHSharedSecret(*dh_pub, dh_server_pub, nonce_client, plainText_Nonce);
    EVP_PKEY_free(dh_server_pub);

    // Derive the session key and the HMAC key
    unsigned char *session_key = (unsigned char *)malloc(AES128LEN);
    unsigned char *HMACk = (unsigned char *)malloc(SHA256LEN);
    memcpy(session_key, *sharedSecret, AES128LEN);
    memcpy(HMACk, *sharedSecret + AES128LEN, SHA256LEN);
    Logger::success("session key " + Base64Encode(session_key, AES128LEN));
    Logger::success("HMAC key " + Base64Encode(HMACk, SHA256LEN));

    // Get the signed hash message
    int plaintext_len = 0;
    unsigned char *signed_hash = AESdecrypt(cptxt, buffer_len - IVLEN - DHPARLEN - NONCELEN, session_key, IV, plaintext_len);
    securefree(cptxt, buffer_len - IVLEN - DHPARLEN - NONCELEN);

    // Generate the buffer to hash
    unsigned char *toHash = (unsigned char *)malloc(2 * DHPARLEN + 2 * NONCELEN + IVLEN);
    memset(toHash, 0, 2*DHPARLEN + 2*NONCELEN + IVLEN);
    memcpy(toHash, plainText_DH, DHPARLEN);
    memcpy(toHash + DHPARLEN, plainText_Nonce, NONCELEN);
    memcpy(toHash + DHPARLEN + NONCELEN, dh_client, dh_uchar_len);
    memcpy(toHash + DHPARLEN + NONCELEN + DHPARLEN, nonce_client, NONCELEN);
    memcpy(toHash + DHPARLEN + NONCELEN + DHPARLEN + NONCELEN, IV, IVLEN);

    // Free IV since it's no longer necessary
    securefree(IV, IVLEN);

    // Hash the buffer and verity the signature
    Logger::debug("toHash: " + Base64Encode(toHash, 2*DHPARLEN + 2*NONCELEN + IVLEN));
    unsigned char *hashed = getHash(toHash, 2 * DHPARLEN + 2 * NONCELEN + IVLEN, nullptr, EVP_sha256());
    securefree(toHash, 2 * NONCELEN + 2 * DHPARLEN + IVLEN);
    if (verify_signature(m_publicKeyServer, signed_hash, plaintext_len, hashed, SHA256LEN) <= 0)
    {
        securefree(signed_hash, plaintext_len);
        securefree(hashed, SHA256LEN);
        Logger::error("Failed in verifying signature");
    }
    m_sessionKey = session_key;
    m_HMACKey = HMACk;
    // Free remaining memory and return 0
    securefree(signed_hash, plaintext_len);
    securefree(hashed, SHA256LEN);
    return 0;
}




int Session::sendHashCheck(std::string password, EVP_PKEY *privkey, unsigned char *client_dh,
                  unsigned char *nonce_client, unsigned char *server_dh,
                  unsigned char *nonce_server, int dh_uchar_len)
{

    // Create the text to be signed
    unsigned char *IV = generate_IV();
    unsigned char *to_sign = (unsigned char *)malloc(2 * DHPARLEN + 2 * NONCELEN + IVLEN + password.size() + 0);
    if (to_sign == nullptr)
    {
        securefree(IV, IVLEN);
        Logger::error("Error in malloc of to_sign");
        return -1;
    }
    memset(to_sign, 0, 2*DHPARLEN + 2*NONCELEN + IVLEN + password.size() + 0);
    memcpy(to_sign, client_dh, dh_uchar_len);
    memcpy(to_sign + DHPARLEN, nonce_client, NONCELEN);
    memcpy(to_sign + DHPARLEN + NONCELEN, server_dh, DHPARLEN);
    memcpy(to_sign + 2 * DHPARLEN + NONCELEN, nonce_server, NONCELEN);
    memcpy(to_sign + 2 * DHPARLEN + 2 * NONCELEN, IV, IVLEN);
    memcpy(to_sign + 2 * DHPARLEN + 2 * NONCELEN + IVLEN, (unsigned char *)password.c_str(), password.size() + 0);
    Logger::debug("to_sign: " + Base64Encode(to_sign, 2*DHPARLEN + 2* NONCELEN + IVLEN + password.size() + 0));

    // Create the hash for the text
    unsigned char *hash = getHash(to_sign, 2 * DHPARLEN + 2 * NONCELEN + IVLEN + password.size() + 0, nullptr, EVP_sha256());
    securefree(to_sign, 2 * DHPARLEN + 2 * NONCELEN + IVLEN + password.size() + 0);
    if (hash == nullptr)
    {
        securefree(IV, IVLEN);
        Logger::error("Error in generation of hash");
        return -1;
    }
    Logger::debug("hash: " + Base64Encode(hash, SHA256LEN));
    unsigned char *signature = signMsg(privkey, hash, SHA256LEN);
    securefree(hash, SHA256LEN);
    if (signature == nullptr)
    {
        securefree(IV, IVLEN);
        Logger::error("Error in generation of signature");
        return -1;
    }
    // Create the cptxt
    unsigned char *to_cptxt = (unsigned char *)malloc(SIGNLEN + password.size() + 0);
    if (to_cptxt == nullptr)
    {
        securefree(IV, IVLEN);
        securefree(signature, SIGNLEN);
        Logger::error("Error in malloc of to_cptxt");
        return -1;
    }

    Logger::debug("signature: " + Base64Encode(signature, SIGNLEN));
    memcpy(to_cptxt, signature, SIGNLEN);
    memcpy(to_cptxt + SIGNLEN, (unsigned char *)password.c_str(), password.size() + 0);
    securefree(signature, SIGNLEN);


    // Encrypt the plaintext
    int len = 0;
    unsigned char *cptxt = AESencrypt(to_cptxt, SIGNLEN + password.size() + 0, m_sessionKey, IV, len);
    securefree(to_cptxt, SIGNLEN + password.size() + 0);
    if (cptxt == nullptr)
    {
        securefree(IV, IVLEN);
        Logger::error("Error in generation of cptxt");
        return -1;
    }

    // Generate the message to be send, send it and free remaining memory
    unsigned char *msg = (unsigned char *)malloc(IVLEN + len);
    if (msg == nullptr)
    {
        securefree(IV, IVLEN);
        securefree(cptxt, len);
        Logger::error("Error in malloc of msg");
        return -1;
    }
    memcpy(msg, IV, IVLEN);
    memcpy(msg + IVLEN, cptxt, len);
    securefree(IV, IVLEN);
    securefree(cptxt, len);
    //send(sd, msg, IVLEN + len, 0);
    m_socketClient->sendData((const char*)msg, IVLEN + len);
    securefree(msg, IVLEN + len);
    return 1;
}


Session::Session(SocketClient *socketClient)
{
    m_socketClient = socketClient;
    m_publicKeyServer = readPublicKey("./keys/server/rsa_pubkey.pem");
    m_isExpired = true;
    Logger::warning("Session expired, please login again...");

    std::string username;
    std::string password;
    std::string result;

    while (m_isExpired)
    {
        std::cout << "(insert username) > ";
        std::cin >> username;
        std::cout << "(insert password) > ";
        std::cin >> password;

        std::string filepath = "./keys/" + username + "/rsa_privkey.pem";
        std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> privkey(readPrivateKey(filepath, password), [](EVP_PKEY *evp_pkey)
                                                                { EVP_PKEY_free(evp_pkey); });
        if (!privkey.get())
        {
            Logger::error("incorrect credentials. Please try again");
            continue;
        }

        // Nonce nonce(NONCELEN);
        unsigned char *nonce = nullptr;
        unsigned char *dh_uchar = nullptr;
        int dh_uchar_len = 0;
        EVP_PKEY *dh_pub = nullptr;

        Logger::info("sending handshake msg");
        int ret = sendHandshakeMsg(username, &nonce, &dh_uchar, &dh_pub, dh_uchar_len);
        if (ret != 0)
        {
            continue;
        }
        unsigned char *nonce_server = nullptr;
        unsigned char *dh_params_server = nullptr;
        unsigned char *sharedSecret = nullptr;
        Logger::info("receiving server handshake answer");
        ret = receiveServerHandshakeAnswer(&nonce_server, &dh_params_server, &sharedSecret,
                                       &dh_pub, dh_uchar, nonce, dh_uchar_len);

        if (ret != 0)
        {
            securefree(dh_uchar, DHPARLEN);
            securefree(nonce, NONCELEN);
            EVP_PKEY_free(dh_pub);
            // send(sd, "ERR", COMMAND_SIZE, 0);
            // close(sd);
            continue;
        }
        if (sharedSecret != nullptr)
            securefree(sharedSecret, AES128LEN + SHA256LEN);

        // Prepare variable for memory management in hashcheck response
        Logger::info("sending hash check");
        ret = sendHashCheck(password, privkey.get(), dh_uchar, nonce, dh_params_server, nonce_server, dh_uchar_len);

        // Free remaining memory
        securefree(dh_uchar, dh_uchar_len);
        securefree(nonce, NONCELEN);
        securefree(dh_params_server, DHPARLEN);
        securefree(nonce_server, NONCELEN);
        if (ret < 0)
        {
            printf("error in the hash-check phase\n");
            // send(sd, "ERR", COMMAND_SIZE, 0);
            continue;
        }

        // Check the final answer
        /*
        if (checkTCPInput(sd) == 1)
        {
            logged_in = true;
            // DEBUG_PRINT(("Id number: %d\n", getId()));
        }
        else
        {
            cout << "Error username or password incorrect\n";
            securefree(this->sessionKey, AES128LEN);
            securefree(this->HMACKey, SHA256LEN);
        }

        */
        EVP_PKEY_free(dh_pub);
        result = m_socketClient->receive();
        m_isExpired = (result != "OK");
        if (m_isExpired)
        {
            Logger::error("invalid credentials. Please try again");
        }
    }
    Logger::success("Login successful. Welcome back " + username);
}

Session::~Session()
{
}

bool Session::isExpired()
{
    return m_isExpired;
}

void Session::getBalance()
{
    Logger::debug("getting balance");
}

void Session::getHistory()
{
    Logger::debug("getting history");
}

void Session::transfer(std::string other, uint amount)
{
    Logger::debug("transferring to " + other + " amount: " + std::to_string(amount));
}
