#ifndef SOCKETCLIENT_H
#define SOCKETCLIENT_H
#include <string>

class SocketClient {
public:
    SocketClient();
    SocketClient(const std::string &serverIp, int port);
    void send(const std::string& message);
    std::string receive();
    void close();

private:
    std::string m_serverIp;
    int m_port;
    int m_socket_fd;
};
#endif