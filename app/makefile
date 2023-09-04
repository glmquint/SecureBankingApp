CXX = g++
CXXFLAGS = -g -Wall
CXXLFLAGS = -g -Wall -lssl -lcrypto -pthread -ldl -Isqlite3.h

all: client server

client: client.o util/SBAClient.o network/SocketClient.o util/Logger.o crypto/Session.o util/MemoryArena.o
	$(CXX) $^ -o $@ $(CXXLFLAGS) 

server: server.o util/SBAServer.o network/SocketServer.o util/Logger.o util/DatabaseDAO.o
	$(CXX) $^ -o $@ $(CXXLFLAGS)

%.o: %.c
	$(CXX) $(CXXFLAGS) -c $< -o $@ 

clean:
	rm -f client server
	find . -name "*.o" -type f -delete