#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <pthread.h>
#include <yf_trim.h>

void pthread(void);

//测试
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
		//多线程
		pthread_t id;
		int j, ret;
		ret = pthread_create(&id, NULL, (void *) pthread, NULL);
		if (ret != 0) {
			printf("Create pthread error!");
			exit(1);
		}
		for (j = 0; j < 3; j++) {
			sleep(1);
			printf("This is main process.\n");
		}
		pthread_join(id, NULL);
	}
	return (0);
}

void pthread(void) {
	int i = 0;
	for (i = 0; i < 3; i++) {
		sleep(1);
		printf("This is a pthread.\n");
	}
}
