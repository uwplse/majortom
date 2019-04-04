#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char** argv) {
  sleep(1);
  mkdir("directory", 0);
  sleep(1);
  return 0;
}
