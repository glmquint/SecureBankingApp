#include <stdlib.h>
#include <string>
#include <stdexcept>
#include <sstream>
#include "SBAServer.h"
#include <iostream>
#include <iomanip> // For setw and setfill
#include <string>
#include <functional>

void printHex(const std::string &str)
{
    for (const char &c : str)
    {
        // Convert each character to its hexadecimal representation
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << ' ';
    }
    std::cout << std::dec << std::endl; // Restore the output formatting to decimal
}

// This function handles authentication and login of clients
void SBAServer::handshakeServer(int sd, unsigned char *buffer, int len)
{
    if (!m_privateKey)
    {
        Logger::error("unable to read server's private key");
        return;
    }
    unsigned char *recv_cmd = (unsigned char *)malloc(CMDLEN);
    unsigned char *nonceClient = (unsigned char *)malloc(NONCELEN);
    unsigned char *dh_params_cl = (unsigned char *)malloc(DHPARLEN);
    unsigned char *username = (unsigned char *)malloc(len - NONCELEN - DHPARLEN - CMDLEN);

    memcpy(recv_cmd, buffer, CMDLEN); 
    memcpy(dh_params_cl, buffer + CMDLEN, DHPARLEN);
    memcpy(nonceClient, buffer + CMDLEN + DHPARLEN, NONCELEN);
    memcpy(username, buffer + CMDLEN + DHPARLEN + NONCELEN, len - NONCELEN - DHPARLEN - CMDLEN);

    {
        Nonce* nc = new Nonce(nonceClient);
        if (m_pastNonces.contains(*nc))
        {
            Logger::error("replay attack detected");
            return;
        }
        m_pastNonces.insert(*nc);
    }

    if ("HELLO" != std::string((const char *)recv_cmd, CMDLEN))
    {
        free(recv_cmd);
        Logger::error("not a valid message");
        return;
    }
    free(recv_cmd);

    std::string user = (reinterpret_cast<char *>(username));
    free(username);
    Logger::debug("User is " + user);

    // First check: control the existance of the user in the system
    if (!m_database->verifyClientExist(user))
    {
        Logger::error("user does not exists in database");
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        EVP_PKEY_free(m_privateKey);
        return;
    }

    // Receives the client parameter and generate the shared secret
    EVP_PKEY *dh_pub_server = generateDHKey();
    if (!dh_pub_server)
    {
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        EVP_PKEY_free(m_privateKey);
        free(username);
        Logger::error("Failed to generate server DH parameter");
        return;
    }
    EVP_PKEY *client_dh_param = convertToEVP_PKEY(dh_params_cl, DHPARLEN);
    if (!client_dh_param)
    {
        EVP_PKEY_free(dh_pub_server);
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        EVP_PKEY_free(m_privateKey);
        free(username);
        Logger::error("Failed to generate client DH parameter");
        return;
    }
    unsigned char *nonce_server = createNonce();
    unsigned char *computed_shared_secret = derivateDHSharedSecret(dh_pub_server, client_dh_param, nonceClient, nonce_server);
    if (!computed_shared_secret)
    {
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        free(username);
        securefree(nonce_server, NONCELEN);
        EVP_PKEY_free(client_dh_param);
        EVP_PKEY_free(m_privateKey);
        return;
    }
    EVP_PKEY_free(client_dh_param);

    // At this point we have both the session key and the MAC key
    unsigned char *sessionKey = (unsigned char *)malloc(AES128LEN);
    unsigned char *HMACKey = (unsigned char *)malloc(SHA256LEN);

    memcpy(sessionKey, computed_shared_secret, AES128LEN);
    memcpy(HMACKey, computed_shared_secret + AES128LEN, SHA256LEN);
    Logger::debug("Session key: " + Base64Encode(sessionKey, AES128LEN));
    Logger::debug("MAC key: " + Base64Encode(HMACKey, SHA256LEN));
    securefree(computed_shared_secret, AES128LEN + SHA256LEN);

    // Now we need to respond to client with 1)server parameter, 2)nonce of the server 3)encrypted signature of client and server parameters
    int dh_pub_len = 0;
    unsigned char *dh_uchar_server = convertToUnsignedChar(dh_pub_server, &dh_pub_len);
    Logger::debug("dh_pub_len: " + std::to_string(dh_pub_len));
    if (!dh_uchar_server)
    {
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        free(username);
        securefree(sessionKey, AES128LEN);
        securefree(HMACKey, SHA256LEN);
        EVP_PKEY_free(dh_pub_server);
        EVP_PKEY_free(m_privateKey);
        return;
    }
    EVP_PKEY_free(dh_pub_server);

    unsigned char *plainText = (unsigned char *)malloc(DHPARLEN + NONCELEN); // plaintext contains DH parameter and nonce of ther server
    memcpy(plainText, dh_uchar_server, DHPARLEN);
    memcpy(plainText + DHPARLEN, nonce_server, NONCELEN);
    securefree(dh_uchar_server, dh_pub_len);
    securefree(nonce_server, NONCELEN);
    Logger::debug("plaintext: " + std::string((const char *)plainText, DHPARLEN + NONCELEN));

    unsigned char *IV = generate_IV(); // it is used for encryption of the signature
    if (!IV)
    {
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        free(username);
        securefree(plainText, DHPARLEN + NONCELEN);
        securefree(sessionKey, AES128LEN);
        securefree(HMACKey, SHA256LEN);
        EVP_PKEY_free(m_privateKey);
        return;
    }
    Logger::debug("IV: " + Base64Encode(IV, IVLEN));

    // We need to calculate the hash to sign
    unsigned char *to_sign = (unsigned char *)malloc(2 * DHPARLEN + 2 * NONCELEN + IVLEN);
    memset(to_sign, 0, 2 * DHPARLEN + 2 * NONCELEN + IVLEN);
    memcpy(to_sign, plainText, DHPARLEN + NONCELEN); // DH and nonce server
    memcpy(to_sign + DHPARLEN + NONCELEN, dh_params_cl, DHPARLEN);
    memcpy(to_sign + 2 * DHPARLEN + NONCELEN, nonceClient, NONCELEN);
    memcpy(to_sign + 2 * DHPARLEN + 2 * NONCELEN, IV, IVLEN); // check for integrity of IV

    Logger::debug("to sign: " + Base64Encode(to_sign, 2 * DHPARLEN + 2 * NONCELEN + IVLEN));

    unsigned char *signedHash = getHash(to_sign, 2 * DHPARLEN + 2 * NONCELEN + IVLEN, nullptr, EVP_sha256());
    if (!signedHash)
    {
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        securefree(sessionKey, AES128LEN);
        securefree(HMACKey, SHA256LEN);
        EVP_PKEY_free(m_privateKey);
        securefree(to_sign, 2 * DHPARLEN + 2 * NONCELEN + IVLEN);
        return;
    }
    securefree(to_sign, 2 * DHPARLEN + 2 * NONCELEN + IVLEN);

    Logger::debug("signedHash: " + Base64Encode(signedHash, EVP_MD_size(EVP_sha256())));

    // We need to calculate the hash to digitally sign it
    unsigned char *signature = signMsg(m_privateKey, signedHash, SHA256LEN);
    if (!signature)
    {
        Logger::error("Failed to sign message");
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        EVP_PKEY_free(m_privateKey);
        securefree(sessionKey, AES128LEN);
        securefree(HMACKey, SHA256LEN);
        return;
    }
    securefree(signedHash, SHA256LEN);

    // We encrypt the signature
    int cptxt_len = 0;
    unsigned char *cptxt = AESencrypt(signature, SIGNLEN, sessionKey, IV, cptxt_len);
    if (!cptxt)
    {
        Logger::error("Failed to encrypt");
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        securefree(sessionKey, AES128LEN);
        securefree(HMACKey, SHA256LEN);
        EVP_PKEY_free(m_privateKey);
        securefree(signature, SIGNLEN);
        return;
    }
    securefree(signature, SIGNLEN);

    Logger::debug("cptxt: " + Base64Encode(cptxt, cptxt_len));

    // toSend will contain: IV | DH server | nonce Server | E(session_key,digital_signature(H(params)))
    unsigned char *to_send = (unsigned char *)malloc(DHPARLEN + NONCELEN + cptxt_len + IVLEN);
    memcpy(to_send, IV, IVLEN);
    memcpy(to_send + IVLEN, plainText, DHPARLEN + NONCELEN);
    memcpy(to_send + IVLEN + DHPARLEN + NONCELEN, cptxt, cptxt_len);
    securefree(cptxt, cptxt_len);

    m_socketServer->sendData(sd, (const char *)to_send, DHPARLEN + NONCELEN + cptxt_len + IVLEN); // send the second message to client

    securefree(IV, IVLEN);
    securefree(to_send, DHPARLEN + NONCELEN + cptxt_len + IVLEN);

    User *newuser = new User;
    newuser->m_username = user;
    newuser->m_sharedSecret = sessionKey;
    newuser->m_hmacSecret = HMACKey;
    newuser->m_isAuthenticated = false;
    connected_users[sd] = newuser;

    unsigned char tmpBuffer[BUFFER_SIZE]; // tmp buffer for receiving client requests
    int byterec = recv(sd, tmpBuffer, BUFFER_SIZE, 0);
    Logger::info("Byte received " + std::to_string(byterec));
    Logger::debug("received encoded: " + Base64Encode(buffer, byterec));
    if (byterec <= 4)
    {
        EVP_PKEY_free(m_privateKey);
        securefree(sessionKey, AES128LEN);
        securefree(HMACKey, SHA256LEN);
        securefree(plainText, DHPARLEN + NONCELEN);
        return;
    }
    IV = (unsigned char *)malloc(IVLEN);

    memcpy(IV, tmpBuffer, IVLEN);
    int plain_len = 0;
    unsigned char *decrypted = AESdecrypt(tmpBuffer + IVLEN, byterec - IVLEN, sessionKey, IV, plain_len);
    if (!decrypted)
    {
        Logger::error("Failed to decrypt ciphertext");
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        securefree(sessionKey, AES128LEN);
        securefree(plainText, DHPARLEN + NONCELEN);
        securefree(IV, IVLEN);
        EVP_PKEY_free(m_privateKey);
        securefree(HMACKey, SHA256LEN);
        return;
    }

    // check if password is correct
    unsigned char *password = (unsigned char *)malloc(plain_len - SIGNLEN);
    memcpy(password, decrypted + SIGNLEN, plain_len - SIGNLEN);
    std::string password_str(reinterpret_cast<char *>(password), plain_len - SIGNLEN);

    // now verify client the client response
    unsigned char *toHash = (unsigned char *)malloc(2 * NONCELEN + 2 * DHPARLEN + IVLEN + plain_len - SIGNLEN);
    memcpy(toHash, dh_params_cl, DHPARLEN);
    memcpy(toHash + DHPARLEN, nonceClient, NONCELEN);
    memcpy(toHash + DHPARLEN + NONCELEN, plainText, DHPARLEN + NONCELEN);
    memcpy(toHash + DHPARLEN + NONCELEN + DHPARLEN + NONCELEN, IV, IVLEN);
    memcpy(toHash + DHPARLEN + NONCELEN + DHPARLEN + NONCELEN + IVLEN, password, plain_len - SIGNLEN);
    Logger::debug("toHash : " + Base64Encode(toHash, 2 * NONCELEN + 2 * DHPARLEN + IVLEN + plain_len - SIGNLEN));

    securefree(password, plain_len - SIGNLEN);
    securefree(dh_params_cl, DHPARLEN);
    securefree(nonceClient, NONCELEN);
    securefree(plainText, DHPARLEN + NONCELEN);
    securefree(IV, IVLEN);

    unsigned char *hashed = getHash(toHash, 2 * DHPARLEN + 2 * NONCELEN + IVLEN + plain_len - SIGNLEN, nullptr, EVP_sha256());
    if (!hashed)
    {
        Logger::error("Failed to compute hash");
        securefree(toHash, 2 * DHPARLEN + 2 * NONCELEN + IVLEN + plain_len - SIGNLEN);
        securefree(sessionKey, AES128LEN);
        securefree(HMACKey, SHA256LEN);
        securefree(decrypted, plain_len);
        return;
    }
    Logger::debug("hashed: " + Base64Encode(hashed, 2 * DHPARLEN + 2 * NONCELEN + IVLEN + plain_len - SIGNLEN));

    // check if the signature is valid and contains same information
    EVP_PKEY *userPublicKey = readPublicKey("./keys/" + user + "/rsa_pubkey.pem");
    if (verify_signature(userPublicKey, decrypted, SIGNLEN, hashed, SHA256LEN) <= 0)
    {
        Logger::error("Failed to verify the signature");
        EVP_PKEY_free(userPublicKey);
        securefree(toHash, 2 * DHPARLEN + 2 * NONCELEN + IVLEN + plain_len - SIGNLEN);
        securefree(decrypted, plain_len);
        securefree(sessionKey, AES128LEN);
        securefree(HMACKey, SHA256LEN);
        return;
    }

    if (!m_database->verifyCredentials(user, password_str))
    {
        Logger::error("Failed to verify the password of the user");
        securefree(dh_params_cl, DHPARLEN);
        securefree(nonceClient, NONCELEN);
        securefree(sessionKey, AES128LEN);
        securefree(HMACKey, SHA256LEN);
        securefree(plainText, DHPARLEN + NONCELEN);
        securefree(password, plain_len - SIGNLEN);
        securefree(IV, IVLEN);
        EVP_PKEY_free(m_privateKey);
        securefree(decrypted, plain_len);
        return;
    }
    securefree(toHash, 2 * DHPARLEN + 2 * NONCELEN + IVLEN + plain_len - SIGNLEN);
    EVP_PKEY_free(userPublicKey);
    securefree(hashed, SHA256LEN);
    securefree(decrypted, plain_len);
    memset(tmpBuffer, 0, BUFFER_SIZE);

    connected_users[sd]->m_isAuthenticated = true;
    Logger::success("client is authenticated");

    // at this point client is authenticated
    unsigned char *ct;
    unsigned char *iv = nullptr;
    unsigned char *to_hashed = nullptr;
    unsigned char *hmac = nullptr;
    unsigned char *to_enc = nullptr;
    int clear_len = 0;
    int enc_len = 0;
    ct = createCiphertext("OK", connected_users[sd]->m_sharedSecret, &iv, &to_hashed, &hmac, connected_users[sd]->m_hmacSecret, &to_enc, &clear_len, &enc_len);
    Logger::debug("ct: " + Base64Encode(ct, (size_t)clear_len));
    m_socketServer->sendData(sd, (const char *)ct, (size_t)clear_len);
    free(ct);
    free(iv);
    free(to_hashed);
    free(hmac);
    free(to_enc);
}

void SBAServer::callback(int sd, char *buf, int len)
{
    Logger::info("callback: " + Base64Encode((unsigned char *)buf, len));
    if (connected_users.find(sd) != connected_users.end())
    {
        Logger::info("handle known user");
        std::string operation;
        operation = decryptCipherText((unsigned char *)buf, len, connected_users[sd]->m_sharedSecret, connected_users[sd]->m_hmacSecret);
        Logger::success("got operation: " + operation);
        std::string answer;
        answer = performOperation(sd, operation); // switch execution over operation, sd may be useful for answers
        Logger::info("answering with: " + answer);
        unsigned char *ct;
        unsigned char *iv = nullptr;
        unsigned char *to_hashed = nullptr;
        unsigned char *hmac = nullptr;
        unsigned char *to_enc = nullptr;
        int len = 0;
        int enc_len = 0;
        ct = createCiphertext(answer, connected_users[sd]->m_sharedSecret, &iv, &to_hashed, &hmac, connected_users[sd]->m_hmacSecret, &to_enc, &len, &enc_len);
        Logger::debug("ct: " + Base64Encode(ct, (size_t)len));
        m_socketServer->sendData(sd, (const char *)ct, (size_t)len);
    }
    else
    {
        Logger::info("handle unkown user");
        handshakeServer(sd, (unsigned char *)buf, len);
    }
}

bool SBAServer::verifyCredentials(std::string username, std::string password)
{
    return m_database->verifyCredentials(username, password);
}

bool SBAServer::addCredentials(std::string username, std::string password)
{
    return m_database->addCredentials(username, password);
}

void SBAServer::resetDB()
{
    m_database->resetDB();
}

std::string SBAServer::performOperation(int sd, std::string req)
{
    std::istringstream iss(req);
    std::string op;
    if (!(iss >> op)){
        Logger::error("empty request");
        return "empty request";
    }
    if (op == BAL_CMD)
        return std::to_string(m_database->getBalance(connected_users[sd]->m_username));
    else if (op == HISTORY_CMD)
        return m_database->getTransfers(connected_users[sd]->m_username, T_TRANSFERS);
    else if (op == TRANSF_CMD){
        std::string user;
        int amount;
        if (!(iss >> user)){
            Logger::error("empry user");
            return "empty user";
        }
        if (!(iss >> amount)){
            Logger::error("empty amount");
            return "empty amount";
        }
        if (amount <= 0){
            return "amount negative";
        }
        return m_database->transfer(connected_users[sd]->m_username, user, amount) ? "OK" : "KO";
    }
    return std::string("unrecognized command " + op + " on server");
}

SBAServer::SBAServer(SocketServer *socketServer, DatabaseDAO *database) : m_pastNonces(1024)
{
    if (socketServer == nullptr && database == nullptr)
    {
        throw std::runtime_error("null injection");
    }
    m_socketServer = socketServer;
    m_privateKey = readPrivateKey("./keys/server/rsa_privkey.pem", "server");
    if (!m_privateKey)
    {
        Logger::error("unable to read server's private key");
        throw std::runtime_error("can't read the private key");
    }
    m_database = database;
    m_socketServer->start(this);
    EVP_PKEY_free(m_privateKey);
}
