#ifndef SOCKETSERVER_H
#define SOCKETSERVER_H
#include <sys/socket.h>
#include <string>
class SocketServer {
public:
    SocketServer(int port);
    void start(void (*callback)(SocketServer& socketServer, char*, int));
    void send(const std::string& message);
    void stop();
    ~SocketServer();
private:
    int m_port;
    int m_socket_fd;
    bool m_running;
    fd_set m_read_fds;
    int m_max_fd;
    int m_handling_fd;
};

#endif