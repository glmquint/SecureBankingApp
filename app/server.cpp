#include "util/SBAServer.h"
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv){
    if (argc < 2)
        throw std::runtime_error("not enough arguments");
    try
    {
        int serverPort = atoi(argv[1]);
        SocketServer socketServer(serverPort);
        DatabaseDAO database("SBA.db");
        SBAServer server = SBAServer(&socketServer, &database);
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}