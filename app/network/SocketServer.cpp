#include "SocketServer.h"
#include "../util/Logger.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

SocketServer::SocketServer(int port) : m_port(port), m_running(false) {
    m_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket_fd < 0) {
        throw std::runtime_error("Failed to create socket");
    }
    int optval = 1;
    setsockopt(m_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = INADDR_ANY;
    if (bind(m_socket_fd, (sockaddr *)&server_address, sizeof(server_address)) < 0) {
        throw std::runtime_error("Failed to bind socket to port");
    }

    if (listen(m_socket_fd, 5) < 0) {
        throw std::runtime_error("Failed to listen on socket");
    }

    FD_ZERO(&m_read_fds);
    FD_SET(m_socket_fd, &m_read_fds);
    m_max_fd = m_socket_fd;
}

void SocketServer::start() {
    m_running = true;
    while (m_running) {
        fd_set read_fds = m_read_fds;
        int num_ready_fds = select(m_max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (num_ready_fds < 0) {
            throw std::runtime_error("select() failed");
        }
        for (int fd = 0; fd <= m_max_fd; fd++) {
            if (FD_ISSET(fd, &read_fds)) {
                if (fd == m_socket_fd) {
                    // new client connection
                    sockaddr_in client_address;
                    socklen_t client_address_len = sizeof(client_address);
                    int client_socket_fd = accept(m_socket_fd, (sockaddr *)&client_address, &client_address_len);
                    if (client_socket_fd < 0) {
                        Logger::error("Failed to accept client connection");
                    } else {
                        FD_SET(client_socket_fd, &m_read_fds);
                        m_max_fd = std::max(m_max_fd, client_socket_fd);
                        Logger::success("New client connected");

                    }
                } else {
                    // existing client data
                    char buffer[1024];
                    int num_bytes = recv(fd, buffer, sizeof(buffer), 0);
                    if (num_bytes <= 0) {
                        Logger::warning("Client disconnected");
                        close(fd);
                        FD_CLR(fd, &m_read_fds);
                    } else {
                        Logger::info("Received " + std::to_string(num_bytes) + " bytes from client" );
                        std::string str(buffer, num_bytes);
                        Logger::info(str);
                    }
                }
            }
        }
    }
}

void SocketServer::stop() {
    m_running = false;
}
/*
int main() {
try {
    SocketServer server(12345);
    std::cout << "Server started. Listening on port 12345..." << std::endl;

    server.start();

    std::cout << "Server shutting down." << std::endl;
} catch (const std::runtime_error& e) {
    std::cerr << "Error: " << e.what() << std::endl;
}

return 0;
}
*/