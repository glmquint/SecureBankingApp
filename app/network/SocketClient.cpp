#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "SocketClient.h"
#include "../util/Logger.h"

SocketClient::SocketClient(){
    // default constructor that fails
}

SocketClient::SocketClient(const std::string& serverIp, int port) : m_serverIp(serverIp), m_port(port), m_socket_fd(-1) {
    m_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket_fd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if (inet_pton(AF_INET, serverIp.c_str(), &server_address.sin_addr) <= 0) {
        Logger::error("address: " + serverIp + "\tport: " + std::to_string(port));
        throw std::runtime_error("Invalid address/Address not supported");
    }

    if (connect(m_socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        Logger::error("address: " + serverIp + "\tport: " + std::to_string(port));
        throw std::runtime_error("Connection failed");
    }
}

void SocketClient::send(const std::string& message) {
    int num_bytes = write(m_socket_fd, message.c_str(), message.size());
    if (num_bytes < 0) {
        throw std::runtime_error("Failed to send data");
    }
}

std::string SocketClient::receive() {
    char buffer[1024];
    int num_bytes = read(m_socket_fd, buffer, sizeof(buffer));
    if (num_bytes < 0) {
        throw std::runtime_error("Failed to receive data");
    }
    return std::string(buffer, num_bytes);
}

void SocketClient::close() {
    if (m_socket_fd != -1) {
        ::close(m_socket_fd);
        m_socket_fd = -1;
    }
}

/*
int main() {
    SocketClient client("127.0.0.1", 12345);

    try {
        std::string message = "Hello, server!";
        client.send(message);

        std::string receivedData = client.receive();
        std::cout << "Received: " << receivedData << std::endl;

        client.close();
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
*/