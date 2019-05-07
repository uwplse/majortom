#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>

void *echo_server(void *arg) {
  int sock = *(int *)arg;
  while (1) {
    int len;
    recv(sock, &len, sizeof(unsigned int), 0);
    len = ntohl(len);
    char *buf = (char *)malloc(len * sizeof(char));
    recv(sock, buf, len, 0);
    len = htonl(len);
    send(sock, &len, sizeof(unsigned int), 0);
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("wrong argument number\n");
    return -1;
  }
  struct addrinfo serverhints, *serverres;
  int sockfd;

  memset(&serverhints, 0, sizeof serverhints);
  serverhints.ai_family = AF_INET;  // use IPv4 or IPv6, whichever
  serverhints.ai_socktype = SOCK_STREAM;
  serverhints.ai_flags = AI_PASSIVE;     // fill in my IP for me

  getaddrinfo(NULL, argv[1], &serverhints, &serverres);
  
  // make a socket:
  sockfd = socket(serverres->ai_family, serverres->ai_socktype, serverres->ai_protocol);
  int enable = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
  // bind it to the port we passed in to getaddrinfo():
  bind(sockfd, serverres->ai_addr, serverres->ai_addrlen);

  listen(sockfd, 5);
  while(1) {
    struct sockaddr addr;
    socklen_t addrlen = sizeof(addr);
    int sock = accept(sockfd, &addr, &addrlen);
    
    pthread_t tid;
    pthread_create(&tid, NULL, echo_server, &sock);
  }
}
