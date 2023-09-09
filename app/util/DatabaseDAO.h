
#ifndef DATABASEDAO_H
#define DATABASEDAO_H

#include "sqlite3.h"

/*
* 
* CREATE TABLE IF NOT EXISTS Users (
*   username TEXT PRIMARY KEY,
*   password TEXT NOT NULL, 
*   salt TEXT NOT NULL,
*   pubkey_path TEXT NOT NULL, 
*   balance INT CHECK (balance >= 0)
* );  
*
* CREATE TABLE IF NOT EXISTS Transfers (
*   user TEXT, 
*   dt DATETIME, 
*   info TEXT, 
*   PRIMARY KEY (user, dt),
*   FOREIGN KEY (user) REFERENCES Users(username)
* );
*   'info' contains (other_username;amount)
*
*/

class DatabaseDAO {
    private:
        sqlite3* db;
    public:
        DatabaseDAO(const char* db_name);
        bool transfer(std::string  src, std::string  dst, uint amount);
        std::string getTransfers(std::string  user, uint T);
        int getBalance(std::string username);
        void resetDB();
        ~DatabaseDAO();
        bool verifyClientExist(std::string user);
        bool addCredentials(std::string username, std::string password);
        bool verifyCredentials(std::string username, std::string password);
};

#endif