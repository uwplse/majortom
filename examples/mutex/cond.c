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
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

int bananas;

void state_function() {
  int_field("bananas", bananas);
}


void *consumer(void *arg) {
  int id = *(int*)arg;
    while(1) {
      annotate_timeout("Eat a banana");
      int_field("tid", id);
      sleep(1);
      pthread_mutex_lock(&mutex);
      while (!bananas) {
        pthread_cond_wait(&cond, &mutex);
      }
      bananas -= 1;
      annotate_timeout("Eating a banana");
      int_field("tid", id);
      sleep(1);
      pthread_mutex_unlock(&mutex);
  }
}

int main(int argc, char** argv) {
  if (argc != 1) {
    return -1;
  }
  register_state_function(state_function);
  bananas = 0;
  annotate_timeout("Start timeout");
  sleep(5);
  pthread_t tid;
  int id = 1;
  pthread_create(&tid, NULL, consumer, &id);
  id++;
  pthread_create(&tid, NULL, consumer, &id);
  id++;
  pthread_create(&tid, NULL, consumer, &id);
  id++;
  pthread_create(&tid, NULL, consumer, &id);
  id++;
  pthread_create(&tid, NULL, consumer, &id);
  id++;
  while(1) {
    annotate_timeout("Add bananas");
    sleep(1);
    pthread_mutex_lock(&mutex);
    bananas += 3;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&mutex);
  }
}
