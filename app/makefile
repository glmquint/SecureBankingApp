CXX = g++
CXXFLAGS = -g -Wall
CXXLFLAGS = -g -Wall -lssl -lcrypto -pthread -ldl -Iutil/sqlite3.h

all: client server

client: client.o util/SBAClient.o network/SocketClient.o util/Logger.o crypto/util.o crypto/Session.o
	$(CXX) $^ -o $@ $(CXXLFLAGS) 

server: server.o util/SBAServer.o network/SocketServer.o util/Logger.o util/sqlite3.o util/DatabaseDAO.o crypto/util.o util/RingSet.o
	$(CXX) $^ -o $@ $(CXXLFLAGS)

util/sqlite3.o: util/sqlite3.c
	gcc -Wall -c util/sqlite3.c -o util/sqlite3.o

%.o: %.c
	$(CXX) $(CXXFLAGS) -c $< -o $@ 

clean:
	rm -f client server
	find . -name "*.o" -type f ! -name "sqlite3.o" -delete