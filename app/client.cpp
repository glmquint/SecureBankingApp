#include <iostream>
#include <string>
#include "network/SocketClient.h"
#include "util/Client.h"
#include "util/Logger.h"

int main(int argc, char**argv){
    Client c = Client(argc, argv);
    c.loop();
    return 0;
}