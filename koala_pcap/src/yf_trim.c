#include <stdio.h>
#include <string.h>
#include "yf_trim.h"

void trim(const char *str, char *buf) {
	strcpy(buf, str);
	char *tail, *head;
	for (tail = buf + strlen(buf) - 1; tail >= buf; tail--) {
		if (!IS_SPACE(*tail))
			break;
	}
	tail[1] = 0;
	for (head = buf; head <= tail; head++) {
		if (!IS_SPACE(*head))
			break;
	}
	if (head != buf)
		memcpy(buf, head, (tail - head + 2) * sizeof(char));
}

void p0x_u_char(int len, u_char *msg) {
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x ", msg[i]);
	}
}

void p0x_char(int len, char *msg) {
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x ", msg[i]);
	}
}
