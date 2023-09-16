#include <stdexcept>
#include <iostream>
#include "Logger.h"
#include "SBAClient.h"
#include "../network/SocketClient.h"
#include "../crypto/Session.h"
#include <csignal>
#include <cstdlib>

volatile sig_atomic_t g_flag = 0;

void sigintHandler(int signal_) {
    // Set the flag to indicate Ctrl-C was pressed
    g_flag = 1;
    std::cout << "Ctrl-C received" << std::endl;
    throw std::runtime_error("received Ctrl-C");
}

SBAClient::SBAClient(SocketClient* socketClient)
{
    if (socketClient == nullptr){
        throw std::runtime_error("null dependency");
    }
    m_socketClient = socketClient;
    m_session = new Session(m_socketClient);

    // Install the Ctrl-C signal handler
    if (signal(SIGINT, sigintHandler) == SIG_ERR) {
        throw std::runtime_error("Error installing signal handler.");
    }
}

Session *SBAClient::getSession()
{
    if(m_session == nullptr)
        return new Session(m_socketClient);
    if(m_session->isExpired()){
        delete m_session;
        m_session = new Session(m_socketClient);
    }
    return m_session;
}

void SBAClient::loop()
{
    std::string cmd;
    while (!g_flag)
    {
        std::cout << "> ";
        if (!(std::cin >> cmd))
        {
            Logger::error("handle cin error");
            break;
        }
        if (cmd == "quit")
        {
            break;
        }
        else if (cmd == "help")
        {
            Logger::print("Available commands:");
            Logger::print("help                          this help command");
            Logger::print("balance                       get balance");
            Logger::print("history                       get transaction history");
            Logger::print("transfer <username> <amount>  tranfer the <amount> to <username>");
        }
        else if (cmd == "balance")
        {
            m_session->getBalance();
            Logger::info("got balance command");
        }
        else if (cmd == "history")
        {
            Logger::info("got history command");
            m_session->getHistory();
        }
        else if (cmd == "transfer")
        {
            Logger::info("got transfer command");
            std::string other;
            uint amount;
            bool ok = false;
            while (!ok)
            {
                Logger::print("other > ");
                std::cin >> other;
                Logger::print("amount > ");
                std::cin >> amount;
                if (!std::cin.good())
                {
                    Logger::error("invalid amount, please enter a valid integer");
                    std::cin.clear();
                    continue;
                }
                Logger::info("other: " + other);
                Logger::info("amount: " + std::to_string(amount));
                Logger::print("is this correct? (q/y/N)");
                std::cin >> cmd;
                ok = (cmd == "y" || cmd == "q");
            }
            if (cmd == "y")
                m_session->transfer(other, amount);
        }

        else
        {
            Logger::warning("Unrecognized command: " + cmd);
            Logger::print("Use help for a list of available commands");
        }
    }
    Logger::info("Cleaning up and exiting...");
}