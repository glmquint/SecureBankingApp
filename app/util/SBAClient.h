#ifndef SBACLIENT_H
#define SBACLIENT_H
#include "../network/SocketClient.h"
#include "../crypto/Session.h"
#include <string>

class SBAClient {
    private:
        SocketClient* m_socketClient;
        Session* m_session;
    public:
        SBAClient() = delete;
        SBAClient(SocketClient* socketClient);
        Session* getSession();
        void loop();
};
#endif