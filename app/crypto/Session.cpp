#include "Session.h"
#include "../util/Logger.h"
#include <string>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define CMD_LEN 5
#define LOGIN_CMD "LOGIN"

// Given a path return the private key, access is permitted with the use of the password
EVP_PKEY* readPrivateKey(std::string filepath, std::string password) {
    EVP_PKEY* prvkey=nullptr;
    FILE* file = fopen(filepath.c_str(), "r");
    if(!file) { 
        Logger::error("Private key not found!");
        return prvkey;
    }
    prvkey= PEM_read_PrivateKey(file, NULL, NULL, const_cast<char*>(password.c_str()));
    if(!prvkey) { 
        Logger::error("PEM_read_PrivateKey failed!");
        fclose(file);
        return prvkey;
    }
    fclose(file);
    return prvkey;
}

Session::Session(SocketClient *socketClient) : memoryArena(1024*1024)
{
    m_socketClient = socketClient;
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
        EVP_PKEY* privkey = readPrivateKey(filepath, password);
        if(!privkey){
            Logger::error("incorrect credentials. Please try again");
            continue;
        }

        int msg_len = CMD_LEN + username.length() + password.length();
        std::string concat_str = LOGIN_CMD+username+password;
        std::unique_ptr<unsigned char[]> msg (new unsigned char[msg_len]);
        for (int i = 0; i < msg_len; ++i){
            msg[i] = static_cast<unsigned char>(concat_str[i]);
        }
        m_socketClient->sendData(msg.get(), msg_len);
        result = m_socketClient->receive();
        m_isExpired = (result != "OK");
        if (m_isExpired){
            Logger::error("invalid credentials. Please try again");
        }
        EVP_PKEY_free(privkey);
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
