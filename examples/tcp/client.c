#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("wrong argument number\n");
    return -1;
  }
  struct addrinfo serverhints, *serverres;
  int sockfd;
  
  sleep(5);

  memset(&serverhints, 0, sizeof serverhints);
  serverhints.ai_family = AF_INET;  // use IPv4 or IPv6, whichever
  serverhints.ai_socktype = SOCK_STREAM;
  serverhints.ai_flags = AI_PASSIVE;     // fill in my IP for me

  getaddrinfo(NULL, argv[1], &serverhints, &serverres);
  
  // make a socket:
  sockfd = socket(serverres->ai_family, serverres->ai_socktype, serverres->ai_protocol);

  connect(sockfd, serverres->ai_addr, serverres->ai_addrlen);
  
  // bind it to the port we passed in to getaddrinfo():

  unsigned int i = 1;
  while(1) {
    unsigned int data = htonl(i);
    send(sockfd, &data, sizeof(unsigned int), 0);
    unsigned int j;
    for (j = 0; j < i; j++) {
      send(sockfd, "a", sizeof(char), 0);
    }
    unsigned int len;
    recv(sockfd, &len, sizeof(unsigned int), 0);
    len = ntohl(len);
    if (len != i) {
      exit(5);
    }
    i = (i + 1) % 10000;
  }
}
