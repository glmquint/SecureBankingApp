CXX = g++
CXXFLAGS = -g -Wall -Wextra

all: client server

client: client.o util/SBAClient.o network/SocketClient.o util/Logger.o crypto/Session.o
	$(CXX) $^ -o $@

server: server.o util/SBAServer.o network/SocketServer.o util/Logger.o
	$(CXX) $^ -o $@

%.o: %.c
	$(CXX) $(CXXFLAGS) -c $< -o $@ 

clean:
	rm client
	rm server
	find . -name "*.o" -type f -delete