#include <unistd.h>
#include <stdio.h>
#include <errno.h>
int main(void) {
  int keys[] = {0x1e, 0x27, 0x28};
  for (unsigned i=0; i<sizeof(keys)/sizeof(keys[0]); ++i) {
    errno=0;
    long v=sysconf(keys[i]);
    printf("%d %ld %d\n", keys[i], v, errno);
  }
  return 0;
}
