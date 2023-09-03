#include <stdlib.h>
#include <string>
#include <stdexcept>
#include "SBAServer.h"
#include "Logger.h"
#include "SBAServer.h"
#include "../network/SocketServer.h"

void callback(SocketServer& socketServer, std::string str){
    Logger::success("callback: " + str);
    socketServer.send(str);
}

SBAServer::SBAServer(SocketServer* socketServer)
{
    if (socketServer == nullptr){
        throw std::runtime_error("null injection");
    }
    m_socketServer = socketServer;
    m_socketServer->start(callback);
}

