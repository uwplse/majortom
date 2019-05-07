default: client server

client: client.c
	gcc -Wall client.c -o client -ldl -pthread

server: server.c
	gcc -Wall server.c -o server -ldl -pthread

clean:
	rm -f client server

.PHONY: clean default
