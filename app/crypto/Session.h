#ifndef SESSION_H
#define SESSION_H
#include "../network/SocketClient.h"

class Session
{
private:
    SocketClient* m_socketClient;
    bool m_isExpired;
public:
    Session();
    Session(SocketClient* socketClient);
    ~Session();
    bool isExpired();
};




#endif