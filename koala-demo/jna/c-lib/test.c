#include "test.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void j_say(const char* str,char** pstr) {
	printf("Hello World!\n[%s]",str);

	*pstr = (char*)malloc(sizeof(char) * 6);
    memset(*pstr,0,sizeof(char) * 6);
    strcpy(*pstr,"hello");
}
int j_add(int x,int y){
    return x+y;
}

