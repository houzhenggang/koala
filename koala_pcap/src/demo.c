#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
  int ch;
  opterr = 0;

  char dev[1024], exp[1024];
  memset(dev, 0, 1024);
  memset(exp, 0, 1024);
  while ((ch = getopt(argc, argv, "i:")) != EOF) {
    switch (ch) {
      case 'i':
        printf("a:%s\n", optarg);
        trim(optarg, dev);
        break;
      default:
        printf("option:%s\n", optarg);
    }
  }
  printf("pos:%d\n", optind);

  int k = 0;
  for (k = optind; k < argc; k++) {
    strcat(exp, argv[k]);
    if (k < argc - 1) strcat(exp, " ");
  }
  printf("exp:%s\n", exp);
}
