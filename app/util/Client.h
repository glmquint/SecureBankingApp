#ifndef CLIENT_H
#define CLIENT_H
#include "../network/SocketClient.h"
#include <string>

class Client {
    private:
        std::string m_serverIp;
        int m_serverPort;
        SocketClient m_socketClient;
    public:
        Client(int argc, char**argv);
        void loop();
};
#endif