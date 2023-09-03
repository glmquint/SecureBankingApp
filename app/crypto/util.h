#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/select.h>
#include <time.h>
#include <signal.h>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <openssl/bn.h>
#include <openssl/dh.h>

#define DEBUG_OFF

#ifdef DEBUG_ON
    #define DEBUG_PRINT(x) printf("[DEBUG]: "); printf x; printf("\n"); fflush(stdout);
#else
    #define DEBUG_PRINT(x) 
#endif

using namespace std;

unsigned char * readBinaryFile(string filename, int* len);
bool writeBinaryFile(std::string filename,unsigned char * buffer,int size);
std::string getPath(std::string username);
std::string Base64Encode(const unsigned char* data, size_t length);
unsigned char* Base64Decode(const std::string& encodedData, size_t& outLength);
std::string buildStringFromUnsignedChar(unsigned char * buffer, int dimension);
std::vector<std::string> getWords(std::string buffer);
std::vector<std::string> splitStringByNewline(const std::string& inputString);
std::string joinStringsByNewline(const std::vector<std::string>& inputVector);
std::vector<std::string> getLastElements(const std::vector<std::string>& inputVector, int t);