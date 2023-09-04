#ifndef SOCKETCLIENT_H
#define SOCKETCLIENT_H
#include <string>

class SocketClient {
public:
    SocketClient(const std::string &serverIp, int port);
    void sendData(unsigned char *data, int len);
    void send(const std::string &message);
    std::string receive();
    void close();
    ~SocketClient();

private:
    std::string m_serverIp;
    int m_port;
    int m_socket_fd;
};
#endif