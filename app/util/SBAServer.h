#ifndef SBASERVER_H
#define SBASERVER_H
#include "../network/SocketServer.h"

class SBAServer {
    private:
        int m_serverPort;
        SocketServer* m_socketServer;
    public:
        SBAServer(SocketServer* SocketServer);
};
#endif