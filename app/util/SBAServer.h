#ifndef SBASERVER_H
#define SBASERVER_H
#include "Logger.h"
#include "../network/SocketServer.h"
#include "../util/DatabaseDAO.h"
#include "../crypto/util.h"
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

class SBAServer {
    private:
        int m_serverPort;
        SocketServer* m_socketServer;
        EVP_PKEY* m_privateKey;
        DatabaseDAO* m_database;
        void handshakeServer(int sd, unsigned char * buffer, int len);
        void sendEncrypted(int sd, std::string cleartext);
        
    public:
        SBAServer(SocketServer* SocketServer, DatabaseDAO* database);
        void callback(int sd, char* buf, int len);
        bool verifyClientExist(std::string username);
        bool verifyCredentials(std::string username, std::string password);
        bool addCredentials(std::string username, std::string password);
        void resetDB();
        std::unordered_map<int, User*> connected_users;

};
#endif