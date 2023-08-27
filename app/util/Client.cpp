#include <stdexcept>
#include <iostream>
#include "Logger.h"
#include "Client.h"

Client::Client(int argc, char **argv)
{
    if (argc < 3)
    {
        throw std::runtime_error("not enough arguments");
    }
    std::string m_serverIp(argv[1]);
    m_serverPort = atoi(argv[2]);
    m_socketClient = SocketClient(m_serverIp, m_serverPort);
}

void Client::loop()
{
    bool stopped = false;
    std::string cmd;
    while (!stopped)
    {
        std::cout << "> ";
        std::cin >> cmd;
        if (!std::cin)
        {
            // TODO: handle error
        }
        if (cmd == "quit")
        {
            break;
        }
        else if (cmd == "send")
        {
            getline(std::cin, cmd);
            m_socketClient.send(cmd);
        }

        Logger::info(cmd);
    }
}