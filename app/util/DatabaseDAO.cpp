#include <stdexcept>
#include "../crypto/util.h"
#include "DatabaseDAO.h"

DatabaseDAO::DatabaseDAO(const char *db_name)
{
    int result = sqlite3_open(db_name, &db);
    if (result != SQLITE_OK)
    {
        throw std::runtime_error("problem opening the database");
    }
}
char *DatabaseDAO::login(const char *username, const char *password)
{
    return nullptr;
}
bool DatabaseDAO::transfer(char *src, char *dst, uint amount)
{
    return false;
}
char *DatabaseDAO::getTransfers(char *user, int T)
{
    return nullptr;
}

void DatabaseDAO::resetDB()
{
    const char *createTableSQL = "DROP TABLE IF EXISTS Users;\
  CREATE TABLE IF NOT EXISTS Users (\
  username TEXT PRIMARY KEY,\
  password TEXT NOT NULL, \
  salt TEXT NOT NULL,\
  pubkey_path TEXT NOT NULL, \
  balance INT CHECK (balance >= 0)\
);";
    int result = sqlite3_exec(db, createTableSQL, nullptr, nullptr, nullptr);
    if (result != SQLITE_OK)
    {
        throw std::runtime_error("error while creating table Users");
    }

    createTableSQL = "DROP TABLE IF EXISTS Transfers;\
  CREATE TABLE IF NOT EXISTS Transfers (\
  user TEXT, \
  dt DATETIME, \
  info TEXT, \
  PRIMARY KEY (user, dt),\
  FOREIGN KEY (user) REFERENCES Users(username)\
);";
    result = sqlite3_exec(db, createTableSQL, nullptr, nullptr, nullptr);
    if (result != SQLITE_OK)
    {
        throw std::runtime_error("error while creating table Transfers");
    }
}
/*
void DatabaseDAO::createTable()
{
    const char* createTableSQL = "CREATE TABLE IF NOT EXISTS MyTable (ID INT, Name TEXT);";
    int result = sqlite3_exec(db, createTableSQL, nullptr, nullptr, nullptr);
    if (result != SQLITE_OK) {
        throw std::runtime_error("error while creating table");
    }
}
void DatabaseDAO::insertData(int id, const char* name){
    const char* insertSQL = "INSERT INTO MyTable (ID, Name) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
    if (result == SQLITE_OK) {
        //int id = 1;
        //const char* name = "John";
        sqlite3_bind_int(stmt, 1, id);
        sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
        result = sqlite3_step(stmt);
        if (result != SQLITE_DONE) {
            throw std::runtime_error("error while inserting data");
        }
        sqlite3_finalize(stmt);
    }
}
void DatabaseDAO::queryData(){
    const char* selectSQL = "SELECT ID, Name FROM MyTable;";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        // Process data
    }
    sqlite3_finalize(stmt);
}
*/
DatabaseDAO::~DatabaseDAO()
{
    sqlite3_close(db);
}

bool DatabaseDAO::verifyClientExist(std::string user)
{
    const char *selectSQL = "SELECT username FROM Users WHERE username = ?;";
    sqlite3_stmt *stmt;
    int result = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
    if (result == SQLITE_OK)
    {
        sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
        result = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return result == SQLITE_ROW;
    }
    return false;
}

bool DatabaseDAO::addCredentials(std::string username, std::string password)
{
    const char *selectSQL = "INSERT INTO Users (username, password, salt, pubkey_path, balance) VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int result = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
    if (result != SQLITE_OK)
    {
        return false;
    }
    std::string salt(Base64Encode((const unsigned char *)createNonce(), NONCELEN));
    Logger::debug("new salt: " + salt);
    std::string pubkey_path("./keys/" + username + "/rsa_pubkey.pem");
    Logger::debug("pubkeypath: " + pubkey_path);
    std::string hashpwd_str(
        Base64Encode(
            getHash(
                (unsigned char *)(password.c_str()),
                password.length(),
                (unsigned char *)salt.c_str(),
                EVP_sha256()),
            EVP_MD_size(EVP_sha256())));
    Logger::debug("new hashpwd: " + hashpwd_str);
    const char *hashpwd = (const char *)hashpwd_str.c_str();
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashpwd, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, salt.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, pubkey_path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, 1000);
    result = sqlite3_step(stmt);
    if (result != SQLITE_DONE)
    {
        Logger::error("error while inserting data");
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

bool DatabaseDAO::verifyCredentials(std::string username, std::string password)
{
    const char *selectSQL = "SELECT password, salt FROM Users WHERE username = ?;";
    sqlite3_stmt *stmt;
    int result = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
    if (result != SQLITE_OK)
    {
        return false;
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const unsigned char *saved_pwd = sqlite3_column_text(stmt, 0);
        std::string saved_pwd_str((char *)saved_pwd);
        const unsigned char *salt = sqlite3_column_text(stmt, 1);
        size_t outlen = 0; // not used
        result = !CRYPTO_memcmp(
            getHash(
                (unsigned char *)(password.c_str()),
                password.length(),
                (unsigned char *)salt,
                EVP_sha256()),
            Base64Decode(saved_pwd_str, outlen), EVP_MD_size(EVP_sha256()));
        // Process data
        Logger::info("result of crypto_memcmp is " + std::to_string(result));
        free((char *)saved_pwd); // TODO: hahah remember to free all
        free((char *)salt);
    }
    sqlite3_finalize(stmt);
    return result;
}
