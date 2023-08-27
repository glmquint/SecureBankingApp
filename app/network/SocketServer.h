#ifndef SOCKETSERVER_H
#define SOCKETSERVER_H
#include <sys/socket.h>
class SocketServer {
public:
    SocketServer(int port);
    void start();
    void stop();
private:
    int m_port;
    int m_socket_fd;
    bool m_running;
    fd_set m_read_fds;
    int m_max_fd;
};

#endif