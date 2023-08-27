#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include "network/SocketServer.h"
#include "util/Logger.h"

using namespace std;

int main(int argc, char** argv){
    if (argc < 2)
        throw std::runtime_error("not enough arguments");
    try {
        int serverPort = atoi(argv[1]);
        SocketServer server(serverPort);
        Logger::success("Server started. Listening on port " + std::to_string(serverPort) + "...");

        server.start();

        std::cout << "Server shutting down." << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}