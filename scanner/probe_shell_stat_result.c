#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
int main(int argc, char **argv) {
  struct stat s;
  if (argc != 2) return 2;
  errno = 0;
  int result = stat(argv[1], &s), error = errno;
  printf("%s\t%d\t%d\n", argv[1], result, error);
  return 0;
}
