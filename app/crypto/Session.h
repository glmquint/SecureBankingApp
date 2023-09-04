#ifndef SESSION_H
#define SESSION_H
#include "../network/SocketClient.h"
#include "../util/MemoryArena.h"

class Session
{
private:
    SocketClient* m_socketClient;
    bool m_isExpired;
    MemoryArena memoryArena;
public:
    Session();
    Session(SocketClient* socketClient);
    ~Session();
    bool isExpired();
    void getBalance();
    void getHistory();
    void transfer(std::string other, uint amount);
};




#endif