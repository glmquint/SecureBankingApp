#include <iostream>
#include <string>
#include "util/SBAClient.h"
#include "network/SocketClient.h"
#include "util/Logger.h"

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        throw std::runtime_error("not enough arguments");
    }
    try
    {
        const std::string serverIp(argv[1]);
        int serverPort = atoi(argv[2]);
        SocketClient socketClient = SocketClient(serverIp, serverPort);
        SBAClient client = SBAClient(&socketClient);
        client.loop();
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}