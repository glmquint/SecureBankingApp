#include <stdlib.h>
#include <string>
#include <stdexcept>
#include "SBAServer.h"
#include "Logger.h"
#include "SBAServer.h"
#include "../network/SocketServer.h"

void callback(SocketServer& socketServer, char* buffer, int size){
    std::string str(buffer, size);
    Logger::success("callback: " + str);
    if (str == "ECHO"){
        socketServer.send(str);
    } else if (str == "LOGIN")
    {
        /* code */
    }
    
}

SBAServer::SBAServer(SocketServer* socketServer)
{
    if (socketServer == nullptr){
        throw std::runtime_error("null injection");
    }
    m_socketServer = socketServer;
    m_socketServer->start(callback);
}

