#include "util.h"
using namespace std;

// Write a file in binary mode
bool writeBinaryFile(string filename, unsigned char * buffer, int size){
    DEBUG_PRINT(("Filename: %s | buffer: %s | size: %d",filename.c_str(),buffer,size));
    FILE* binaryFile = fopen(filename.c_str(), "wb");
    if(!binaryFile) { 
        DEBUG_PRINT(("Can't open file %s",filename.c_str())); 
        return false;
    }
    int ret;
    ret = fwrite(buffer, 1, size, binaryFile);
    fclose(binaryFile);
    return ret==size;
}

// Read a file in binary mode
unsigned char * readBinaryFile(string filename, int* len){
    FILE* binaryFile = fopen(filename.c_str(), "rb");
    if(!binaryFile) { 
        DEBUG_PRINT(("Can't open file %s",filename.c_str()));
        return nullptr; 
    }
    fseek(binaryFile, 0, SEEK_END);
    long int clear_size = ftell(binaryFile);
    fseek(binaryFile, 0, SEEK_SET);

    // read the plaintext from file:
    unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
    if(!clear_buf) {
        DEBUG_PRINT(("malloc failed, dimension of the file %ld",clear_size));
        return nullptr; 
    }
    *len = fread(clear_buf, 1, clear_size, binaryFile);
    if(*len < clear_size){ 
        DEBUG_PRINT(("error in reading file, read: %d | size of the file: %ld",*len,clear_size));
        return nullptr; 
    }
    fclose(binaryFile);
    return clear_buf;
}

// Given a username return the path in the filesystem
string getPath(string username){
    string curpath=filesystem::current_path();
    string path = curpath+"/server/users/"+username;
    return path;
}

// Given a unsigned char * buffer of length "length",
// return the equivalent Base64 string used for debugging purposes
std::string Base64Encode(const unsigned char* data, size_t length) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* base64Bio = BIO_new(BIO_f_base64());
    BIO_push(base64Bio, bio);

    // Disable line breaks in the Base64 output
    BIO_set_flags(base64Bio, BIO_FLAGS_BASE64_NO_NL);

    // Write the data to the BIO
    BIO_write(base64Bio, data, length);
    BIO_flush(base64Bio);

    // Determine the size of the encoded data
    long bioSize = BIO_get_mem_data(bio, nullptr);

    // Create a string and read the encoded data from the BIO
    std::string encodedData(bioSize, '\0');
    BIO_read(bio, (void*)encodedData.data(), bioSize);

    // Cleanup
    BIO_free_all(base64Bio);

    return encodedData;
}

// Given a string in Bas64 format it decodes it, return a unsigned char * 
unsigned char* Base64Decode(const std::string& encodedData, size_t& outLength) {
    // Create a BIO object for reading from the encoded string
    BIO* bio = BIO_new_mem_buf(encodedData.c_str(), encodedData.length());
    BIO* base64Bio = BIO_new(BIO_f_base64());
    BIO_push(base64Bio, bio);

    // Disable line breaks in the Base64 input
    BIO_set_flags(base64Bio, BIO_FLAGS_BASE64_NO_NL);

    // Determine the size of the decoded data
    size_t maxDecodedLength = encodedData.length() / 4 * 3;  // Conservative estimate
    unsigned char* decodedData = new unsigned char[maxDecodedLength];

    // Perform the Base64 decoding
    outLength = BIO_read(base64Bio, decodedData, encodedData.length());

    // Cleanup
    BIO_free_all(base64Bio);

    return decodedData;
}

// Given a unsigned char* buffer o length dimension return it into string format
string buildStringFromUnsignedChar(unsigned char * buffer, int dimension){
    string result(reinterpret_cast<char*>(buffer),dimension);
    return result;
}

// Given a string return a vector of string containing the original string word by word
std::vector<std::string> getWords(std::string buffer){
    istringstream iss(buffer);
    vector<string> tokens;
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    DEBUG_PRINT(("Token size is %lu",tokens.size()));
    return tokens;
}

// Given a string, return a vector of string containing the original string line by line
std::vector<std::string> splitStringByNewline(const std::string& inputString) {
    std::vector<std::string> result;
    std::string temp;

    for (char c : inputString) {
        if (c == '\n') {
            result.push_back(temp);
            temp.clear();
        } else {
            temp += c;
        }
    }

    if (!temp.empty()) {
        result.push_back(temp);
    }

    return result;
}

// Given a vector of string, concat them back together adding a \n between them
std::string joinStringsByNewline(const std::vector<std::string>& inputVector) {
    std::string result;

    for (const std::string& str : inputVector) {
        result += str + '\n';
    }

    return result;
}

// Given an vector of string, return the last t entry of the vector
std::vector<std::string> getLastElements(const std::vector<std::string>& inputVector, int t) {
    int n = inputVector.size();
    int startIndex = (n > t) ? n - t -1 : 0;

    std::vector<std::string> result;
    for (int i = startIndex; i < n; ++i) {
        result.push_back(inputVector[i]);
    }

    return result;
}