#include "sqlite3.h"
#include <stdexcept>

class DatabaseDAO {
    private:
        sqlite3* db;
    public:
        DatabaseDAO(){
            int result = sqlite3_open("SBA.db", &db);
            if (result != SQLITE_OK){
                throw std::runtime_error("problem opening the database");
            }
        }
        void createTable(){
            const char* createTableSQL = "CREATE TABLE IF NOT EXISTS MyTable (ID INT, Name TEXT);";
            int result = sqlite3_exec(db, createTableSQL, nullptr, nullptr, nullptr);
            if (result != SQLITE_OK) {
                throw std::runtime_error("error while creating table");
            }
        }
        void insertData(int id, const char* name){
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
        void queryData(){
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
        ~DatabaseDAO(){
            sqlite3_close(db);
        }
};