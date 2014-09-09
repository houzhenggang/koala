#include <string.h>
#include <memory.h>
#include <yf_trim.h>

void trim(const char *str,char *buffer) {
  strcpy(buffer,str);
  char *tail,*head;
  for(tail=buffer + strlen(buffer) - 1;tail>=buffer;tail--){
    if(!IS_SPACE(*tail)) break;
  }
  tail[1] = 0;
  for(head = buffer;head <= tail; head++){
      if(!IS_SPACE(*head)) break;
  }
  if(head != buffer) memcpy(buffer,head,(tail - head + 2) * sizeof(char));
}
