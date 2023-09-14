#include <stdexcept>
#include "../crypto/util.h"
#include "DatabaseDAO.h"
#include <memory>

DatabaseDAO::DatabaseDAO(const char *db_name)
{
    int result = sqlite3_open(db_name, &db);
    if (result != SQLITE_OK)
    {
        throw std::runtime_error("problem opening the database");
    }
}
bool DatabaseDAO::transfer(std::string sender, std::string receiver, uint amount)
{
    if (amount <= 0 || !verifyClientExist(sender) || !verifyClientExist(receiver))
    {
        Logger::error("invalid transfer request");
        return false;
    }
    sqlite3_stmt *stmt = nullptr;

    std::string send_str = std::string("sent ") + std::to_string(amount) + std::string(" to ") + receiver;
    std::string send_enc;
    std::string recv_str = std::string("got ") + std::to_string(amount) + std::string(" from ") + sender;
    std::string recv_enc;

    {
        std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> sender_pubkey(readPublicKey("./keys/" + sender + "/rsa_pubkey.pem"), [](EVP_PKEY *pkey)
                                                                      { EVP_PKEY_free(pkey); });
        unsigned char *ciphertext_rawptr = nullptr;
        size_t len = 0;
        bool res = RSAEncrypt(sender_pubkey.get(), (unsigned char *)send_str.c_str(), send_str.length(), ciphertext_rawptr, len);
        std::unique_ptr<unsigned char> ciphertext(ciphertext_rawptr);
        if (!res)
        {
            Logger::error("error while RSA encrypting");
            return false;
        }
        send_enc = Base64Encode(ciphertext.get(), len);
    }
    Logger::info("send_enc: " + send_enc);

    {
        std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> receiver_pubkey(readPublicKey("./keys/" + receiver + "/rsa_pubkey.pem"), [](EVP_PKEY *pkey)
                                                                        { EVP_PKEY_free(pkey); });
        unsigned char *ciphertext_rawptr = nullptr;
        size_t len = 0;
        bool res = RSAEncrypt(receiver_pubkey.get(), (unsigned char *)recv_str.c_str(), recv_str.length(), ciphertext_rawptr, len);
        std::unique_ptr<unsigned char> ciphertext(ciphertext_rawptr);
        if (!res)
        {
            Logger::error("error while RSA encrypting");
            return false;
        }
        recv_enc = Base64Encode(ciphertext.get(), len);
    }
    Logger::info("recv_enc: " + recv_enc);

    // Begin the SQLite transaction
    if (sqlite3_exec(db, "BEGIN", 0, 0, 0) != SQLITE_OK)
    {
        Logger::error("Failed to begin transaction: " + std::string(sqlite3_errmsg(db)));
        sqlite3_finalize(stmt);
        return false;
    }

    // Prepare the sender's update and insert statement
    std::string senderUpdateSQL = "UPDATE Users SET balance = balance - ? WHERE username = ?;";
    std::string senderInsertSQL = "INSERT INTO Transfers (user, info, dt) VALUES (?, ?, DATETIME('now'));";

    // Prepare the receiver's update and insert statement
    std::string receiverUpdateSQL = "UPDATE Users SET balance = balance + ? WHERE username = ?;";
    std::string receiverInsertSQL = "INSERT INTO Transfers (user, info, dt) VALUES (?, ?, DATETIME('now'));";

    if (sqlite3_prepare_v2(db, senderUpdateSQL.c_str(), -1, &stmt, 0) != SQLITE_OK)
    {
        Logger::error("Failed to prepare sender update statement: " + std::string(sqlite3_errmsg(db)));
        goto rollback;
    }

    sqlite3_bind_int(stmt, 1, amount);
    sqlite3_bind_text(stmt, 2, sender.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        Logger::error("Failed to execute sender update statement: " + std::string(sqlite3_errmsg(db)));
        goto rollback;
    }

    sqlite3_reset(stmt);

    if (sqlite3_prepare_v2(db, senderInsertSQL.c_str(), -1, &stmt, 0) != SQLITE_OK)
    {
        Logger::error("Failed to prepare sender insert statement: " + std::string(sqlite3_errmsg(db)));
        goto rollback;
    }

    sqlite3_bind_text(stmt, 1, sender.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, send_enc.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        Logger::error("Failed to execute sender insert statement: " + std::string(sqlite3_errmsg(db)));
        goto rollback;
    }

    sqlite3_reset(stmt);

    if (sqlite3_prepare_v2(db, receiverUpdateSQL.c_str(), -1, &stmt, 0) != SQLITE_OK)
    {
        Logger::error("Failed to prepare receiver update statement: " + std::string(sqlite3_errmsg(db)));
        goto rollback;
    }

    sqlite3_bind_int(stmt, 1, amount);
    sqlite3_bind_text(stmt, 2, receiver.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        Logger::error("Failed to execute receiver update statement: " + std::string(sqlite3_errmsg(db)));
        goto rollback;
    }

    sqlite3_reset(stmt);

    if (sqlite3_prepare_v2(db, receiverInsertSQL.c_str(), -1, &stmt, 0) != SQLITE_OK)
    {
        Logger::error("Failed to prepare receiver insert statement: " + std::string(sqlite3_errmsg(db)));
        goto rollback;
    }

    sqlite3_bind_text(stmt, 1, receiver.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, recv_enc.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        Logger::error("Failed to execute receiver insert statement: " + std::string(sqlite3_errmsg(db)));
        goto rollback;
    }

    sqlite3_finalize(stmt);

    // Commit the transaction
    if (sqlite3_exec(db, "COMMIT", 0, 0, 0) != SQLITE_OK)
    {
        Logger::error("Failed to commit transaction: " + std::string(sqlite3_errmsg(db)));
        return false;
    }

    return true;

rollback:

    sqlite3_finalize(stmt);
    // Rollback the transaction
    if (sqlite3_exec(db, "ROLLBACK", 0, 0, 0) != SQLITE_OK)
    {
        Logger::error("Failed to rollback transaction: " + std::string(sqlite3_errmsg(db)));
    }
    return false;
}
std::string DatabaseDAO::getTransfers(std::string user, uint T)
{
    std::string result;
    sqlite3_stmt *stmt = nullptr;

    std::string query = "SELECT * FROM Transfers WHERE user = ? ORDER BY dt DESC LIMIT ?;";

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, 0) != SQLITE_OK)
    {
        Logger::error("Failed to prepare query: " + std::string(sqlite3_errmsg(db)));
        return result;
    }

    sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, T);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        // Assuming you have columns named 'user', 'info', and 'dt' in your Transfers table
        std::string user = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
        std::string dt = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
        std::string info = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2)));

        result += user + " | " + dt + " | " + info + "\n";
    }

    sqlite3_finalize(stmt);

    return result;
}

int DatabaseDAO::getBalance(std::string user)
{
    const char *selectSQL = "SELECT balance FROM Users WHERE username = ?;";
    int balance = -1;
    sqlite3_stmt *stmt;
    int result = sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
    if (result == SQLITE_OK)
    {
        sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
        result = sqlite3_step(stmt);
        if (result == SQLITE_ROW)
        {
            balance = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    Logger::success("got balance of " + user + ": " + std::to_string(balance));
    return balance;
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
    Logger::info("verifying credentials: " + username + " (" + std::to_string(username.length()) + " bytes)" + password + "(" + std::to_string(password.length()) + " bytes)");
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
        // free((char *)saved_pwd); // TODO: hahah remember to free all
        // free((char *)salt);
    }
    sqlite3_finalize(stmt);
    return result;
}
