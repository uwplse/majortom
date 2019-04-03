#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

int main(int argc, char** argv) {
  sleep(1);
  FILE *readfile = fopen("readfile", "r");
  char c = fgetc(readfile);
  if (c != 'A') {
    return -1;
  }
  sleep(1);
  FILE *existingwritefile = fopen("existingwritefile", "a");
  fprintf(existingwritefile, "\nMORE TEXT IN THE FILE");
  fflush(existingwritefile);
  sleep(1);
  FILE *writefile = fopen("writefile", "w");
  fprintf(writefile, "TEXT IN THE FILE");
  fflush(writefile);
  sleep(1);
  return 0;
}
