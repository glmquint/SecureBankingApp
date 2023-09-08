#ifndef SESSION_H
#define SESSION_H
#include "../network/SocketClient.h"
#include "util.h"

class Session
{
private:
    SocketClient* m_socketClient;
    EVP_PKEY* m_publicKeyServer;
    bool m_isExpired;
    unsigned char* m_sessionKey;
    unsigned char* m_HMACKey;
    int sendLoginMsg(std::string sent, unsigned char **nonce,
         unsigned char **dh_uchar, EVP_PKEY **dh_pub);
    int receiveServerLoginAnswer(unsigned char **nonce_server,
                             unsigned char **dh_params_server, unsigned char **sharedSecret,
                             EVP_PKEY **dh_pub, unsigned char *dh_client, unsigned char *nonce_client);
    int sendHashCheck(std::string password, EVP_PKEY *privkey, unsigned char *client_dh,
                  unsigned char *nonce_client, unsigned char *server_dh,
                  unsigned char *nonce_server);
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