#include <unistd.h>
#include <stdio.h>
#include <errno.h>
int main(int argc,char **argv) {
  for(int i=1;i<argc;i++) {
    errno=0;int result=access(argv[i],F_OK);int error=errno;
    printf("%s\t%d\t%d\n",argv[i],result,error);
  }
  return 0;
}
