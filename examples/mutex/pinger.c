#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>

#include "proteinpills.h"

int sockfd;
int pings_sent;
struct addrinfo themhints, *themres;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *background(void *arg) {
  int id = *(int*)arg;
  while(1) {
    annotate_timeout("Background timeout");
    int_field("tid", id);
    sleep(1);
    pthread_mutex_lock(&mutex);
    sendto(sockfd, "ping", 5, 0, themres->ai_addr, themres->ai_addrlen);
    pings_sent++;
    annotate_timeout("Timeout with mutex held");
    int_field("tid", id);
    sleep(1);
    pthread_mutex_unlock(&mutex);
  }
}

int main(int argc, char** argv) {
  if (argc != 3) {
    return -1;
  }
  struct addrinfo mehints, *meres;
  char buf[5];
  int pongs_received = 0;

  memset(&mehints, 0, sizeof mehints);
  mehints.ai_family = AF_INET;  // use IPv4 or IPv6, whichever
  mehints.ai_socktype = SOCK_DGRAM;
  mehints.ai_flags = AI_PASSIVE;     // fill in my IP for me

  getaddrinfo(NULL, argv[1], &mehints, &meres);



  memset(&themhints, 0, sizeof themhints);
  themhints.ai_family = AF_INET;
  themhints.ai_socktype = SOCK_DGRAM;
  themhints.ai_flags = AI_PASSIVE;

  getaddrinfo(NULL, argv[2], &themhints, &themres);
  
  // make a socket:
  sockfd = socket(meres->ai_family, meres->ai_socktype, meres->ai_protocol);

  // bind it to the port we passed in to getaddrinfo():
  bind(sockfd, meres->ai_addr, meres->ai_addrlen);

  struct sockaddr from;
  socklen_t fromsize = sizeof(from);

  pings_sent = 0;
  annotate_timeout("Start timeout");
  sleep(5);
  pthread_t tid;
  int id = 1;
  pthread_mutex_lock(&mutex);
  pthread_create(&tid, NULL, background, &id);
  id++;
  pthread_create(&tid, NULL, background, &id);
  annotate_timeout("Main thread timeout");
  sleep(5);
  pthread_mutex_unlock(&mutex);
  while(1) {
    sendto(sockfd, "ping", 5, 0, themres->ai_addr, themres->ai_addrlen);
    pings_sent++;
    recvfrom(sockfd, buf, 5, 0, &from, &fromsize);
    pongs_received++;
  }
}
