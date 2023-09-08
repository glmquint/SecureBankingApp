#ifndef SOCKETSERVER_H
#define SOCKETSERVER_H
#include <sys/socket.h>
#include <string>
#include "../util/SBAServer.h"

class SBAServer;

class SocketServer {
public:
    SocketServer(int port);
    //void start(void (*callback)(SocketServer& socketServer, int sd, char* buffer, int buffer_len));
    void start(SBAServer* sbaServer);
    void sendData(int sd, const char* data, int len);
    void stop();
    ~SocketServer();
private:
    int m_port;
    int m_socket_fd;
    bool m_running;
    fd_set m_read_fds;
    int m_max_fd;
};

#endif