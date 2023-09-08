#include "SocketServer.h"
#include "../util/Logger.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <csignal>
#include <cstdlib>
#include <functional>

volatile sig_atomic_t g_flag = 0;

void sigintHandler(int signal)
{
    // Set the flag to indicate Ctrl-C was pressed
    g_flag = 1;
    std::cout << "Ctrl-C received. Cleaning up and exiting..." << std::endl;
}

SocketServer::SocketServer(int port) : m_port(port), m_running(false)
{
    m_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket_fd < 0)
    {
        throw std::runtime_error("Failed to create socket");
    }
    int optval = 1;
    setsockopt(m_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = INADDR_ANY;
    if (bind(m_socket_fd, (sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        throw std::runtime_error("Failed to bind socket to port");
    }

    if (listen(m_socket_fd, 5) < 0)
    {
        throw std::runtime_error("Failed to listen on socket");
    }

    FD_ZERO(&m_read_fds);
    FD_SET(m_socket_fd, &m_read_fds);
    m_max_fd = m_socket_fd;
    Logger::success("Server started. Listening on port " + std::to_string(m_port) + "...");

    // Install the Ctrl-C signal handler
    if (signal(SIGINT, sigintHandler) == SIG_ERR)
    {
        throw std::runtime_error("Error installing signal handler.");
    }
}

void SocketServer::start(SBAServer *sbaServer)
{
    m_running = true;
    while (m_running && !g_flag)
    {
        fd_set read_fds = m_read_fds;
        FD_SET(STDIN_FILENO, &read_fds); // Add stdin to the set
        int num_ready_fds = select(m_max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (num_ready_fds < 0)
        {
            throw std::runtime_error("select() failed");
        }
        for (int fd = 0; fd <= m_max_fd; fd++)
        {
            if (FD_ISSET(fd, &read_fds))
            {
                Logger::info("fd: " + std::to_string(fd));
                if (fd == m_socket_fd)
                {
                    // new client connection
                    sockaddr_in client_address;
                    socklen_t client_address_len = sizeof(client_address);
                    int client_socket_fd = accept(m_socket_fd, (sockaddr *)&client_address, &client_address_len);
                    if (client_socket_fd < 0)
                    {
                        Logger::error("Failed to accept client connection");
                    }
                    else
                    {
                        FD_SET(client_socket_fd, &m_read_fds);
                        m_max_fd = std::max(m_max_fd, client_socket_fd);
                        Logger::success("New client connected");
                    }
                }
                else if (fd == STDIN_FILENO)
                {
                    // Handle input from stdin
                    std::string input;
                    // std::getline(std::cin, input);
                    std::cin >> input;
                    if (!input.empty())
                    {
                        Logger::info("Server command: " + input);
                        if (input == "quit")
                            stop();
                        else if (input == "adduser")
                        {
                            std::string username;
                            std::string password;
                            std::cout << "username > ";
                            std::cin >> username;
                            std::cout << "password > ";
                            std::cin >> password;
                            if (!sbaServer->addCredentials(username, password))
                            {
                                Logger::error("failed inserting user");
                            }
                            else
                            {
                                Logger::success("user inserted correctly");
                            }
                        }
                        else if (input == "resetdb")
                        {
                            sbaServer->resetDB();
                        }
                        else if (input == "verifyuser")
                        {

                            std::string username;
                            std::string password;
                            std::cout << "username > ";
                            std::cin >> username;
                            std::cout << "password > ";
                            std::cin >> password;
                            if (!sbaServer->verifyCredentials(username, password))
                            {
                                Logger::error("failed verify user");
                            }
                            else
                                Logger::success("user verified correctly");
                            {
                            }
                        }
                        else
                        {
                            Logger::print("Unrecognized command: " + input);
                            Logger::print("Use 'quit' to stop the server");
                        }
                    }
                }
                else
                {
                    char buffer[BUFFER_SIZE];
                    int num_bytes = recv(fd, buffer, BUFFER_SIZE, 0);
                    if (num_bytes <= 0)
                    {
                        Logger::warning("Client disconnected");
                        close(fd);
                        FD_CLR(fd, &m_read_fds);
                        sbaServer->connected_users.erase(fd);
                    }
                    else
                    {
                        Logger::info("Received " + std::to_string(num_bytes) + " bytes from client");

                        sbaServer->callback(fd, buffer, num_bytes);
                    }
                }
            }
        }
    }
}

void SocketServer::sendData(int sd, const char *data, int len)
{
    if (sd < 0)
    {
        throw std::runtime_error("Iinvalid fd");
    }
    int num_sent = 0;
    do
    {
        num_sent += send(sd, data, len, 0);
    } while (num_sent < len);
    Logger::success("sent " + std::to_string(len) + " bytes to client at sd: " + std::to_string(sd));
    Logger::success("encoded sent: " + Base64Encode((const unsigned char*)data, len));
}

void SocketServer::stop()
{
    m_running = false;
    Logger::success("Server shutting down...");
}

SocketServer::~SocketServer()
{
    // Close the socket file descriptor
    if (m_socket_fd >= 0)
    {
        close(m_socket_fd);
    }

    // Close any active handling file descriptor
    FD_ZERO(&m_read_fds);
    LOG("destructor socket server");
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