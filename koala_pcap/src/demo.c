#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <phd_trim.h>

int main(int argc, char *argv[]) {
  if (argc > 1) {
    printf("argc:%d argv[1]:%s\n", argc, argv[1]);

    char *str = malloc(OPTION_BUF_LEN);
    trim("  dfdfdf   ", str);
    printf("str:[%s]\n", str);
    int i;
    for (i = 1; i < argc; i++) {
      if (argv[i][0] == '-' || argv[i][0]) {
        char *opt = malloc(OPTION_BUF_LEN);

        switch (tolower(argv[i][1])) {
          case 'd':
            trim(argv[++i], opt);
            printf("-d Option:%s\n", opt);
            break;
          case 'c':
            trim(argv[++i], opt);
            printf("-c Option:%s\n", opt);
            break;
          default:
            printf("Unkown option!\n");
        }
      }
    }
  }
  return 0;
}
