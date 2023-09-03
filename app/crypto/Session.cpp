#include "Session.h"
#include "../util/Logger.h"
#include <string>
#include <iostream>

Session::Session(SocketClient *socketClient)
{
    m_socketClient = socketClient;
    m_isExpired = true;
    Logger::warning("Session expired, please login again...");

    std::string username;
    std::string password;
    std::string result;

    while (m_isExpired)
    {
        std::cout << "(insert username) > ";
        std::cin >> username;
        std::cout << "(insert password) > ";
        std::cin >> password;
        m_socketClient->send("LOG\n");
        m_socketClient->send(username.c_str());
        m_socketClient->send(password.c_str());
        result = m_socketClient->receive();
        m_isExpired = (result != "OK");
        if (m_isExpired){
            Logger::error("invalid credentials. Please try again");
        }
    }
    Logger::success("Login successful. Welcome back " + username);
}

Session::~Session()
{
}

bool Session::isExpired()
{
    return m_isExpired;
}
