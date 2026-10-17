#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  struct stat s;
  memset(&s,0,sizeof(s));
  if(argc!=2 || stat(argv[1],&s)) return 1;
  return fwrite(&s,1,sizeof(s),stdout)==sizeof(s)?0:2;
}
