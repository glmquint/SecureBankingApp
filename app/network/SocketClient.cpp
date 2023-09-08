#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "SocketClient.h"
#include "../util/Logger.h"
#include "../crypto/util.h"


SocketClient::SocketClient(const std::string &serverIp, int port) : m_serverIp(serverIp), m_port(port), m_socket_fd(-1)
{
    m_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket_fd < 0)
    {
        throw std::runtime_error("Failed to create socket");
    }

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if (inet_pton(AF_INET, serverIp.c_str(), &server_address.sin_addr) <= 0)
    {
        Logger::debug("address: " + serverIp + "\tport: " + std::to_string(port));
        throw std::runtime_error("Invalid address/Address not supported");
    }

    if (connect(m_socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        Logger::debug("address: " + serverIp + "\tport: " + std::to_string(port));
        throw std::runtime_error("Connection failed");
    }
    Logger::success("Successfully connected to " + serverIp + " on port " + std::to_string(port));
}

void SocketClient::sendData(const char* data, int len){
    int num_sent = 0;
    do
    {
        num_sent += ::send(m_socket_fd, data, len, 0);
    } while (num_sent < len);
    Logger::success("client sended " + std::to_string(len) + " bytes: "+ Base64Encode((const unsigned char*)data, len));
    //Logger::debug("decoded: "+std::string(data, len));
}

void SocketClient::send(const std::string &message)
{
    int num_bytes = write(m_socket_fd, message.c_str(), message.size());
    if (num_bytes < 0)
    {
        throw std::runtime_error("Failed to send data");
    }
}

std::string SocketClient::receive()
{
    char* buffer = new char[BUFFER_SIZE];
    int num_bytes = 0;
    receiveData(buffer, num_bytes);
    return std::string(buffer, num_bytes);
}

void SocketClient::receiveData(char *buffer, int& len)
{
    //buffer = new char[BUFFER_SIZE];
    len = recv(m_socket_fd, buffer, BUFFER_SIZE, 0);
    if (len < 0)
    {
        throw std::runtime_error("Failed to receive data");
    }
    Logger::debug("Received encoded: " + Base64Encode((const unsigned char*) buffer, len));
    Logger::info("Received " + std::to_string(len) + " bytes from server" );
}

void SocketClient::close()
{
    if (m_socket_fd != -1)
    {
        ::close(m_socket_fd);
        m_socket_fd = -1;
    }
}

SocketClient::~SocketClient()
{
    LOG("destructor socket client");
    // close(); // TODO: understand why
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