#ifndef SBASERVER_H
#define SBASERVER_H
#include "Logger.h"
#include "../crypto/util.h"
#include "../network/SocketServer.h"
#include "../util/DatabaseDAO.h"
#include "../util/RingSet.h"
#include <unordered_map>

struct User
{
    std::string m_username;
    unsigned char *m_sharedSecret;
    unsigned char *m_hmacSecret;
    bool m_isAuthenticated;
};

class SocketServer;

class SBAServer
{
private:
    int m_serverPort;
    SocketServer *m_socketServer;
    EVP_PKEY *m_privateKey;
    DatabaseDAO *m_database;
    void handshakeServer(int sd, unsigned char *buffer, int len);
    RingSet m_pastNonces;

public:
    SBAServer(SocketServer *SocketServer, DatabaseDAO *database);
    void callback(int sd, char *buf, int len);
    bool verifyCredentials(std::string username, std::string password);
    bool addCredentials(std::string username, std::string password);
    void resetDB();
    std::string performOperation(int sd, std::string op);
    std::unordered_map<int, User *> connected_users;
};
#endif