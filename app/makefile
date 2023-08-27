all: client server

client: client.o util/Client.o network/SocketClient.o util/Logger.o
	g++ $^ -o $@

server: server.o network/SocketServer.o util/Logger.o
	g++ $^ -o $@

%.o: %.c
	g++ -c $< -o $@ 

clean:
	rm client
	rm server
	find . -name "*.o" -type f -delete