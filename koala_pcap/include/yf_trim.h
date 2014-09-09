#ifndef _YF_TRIM_H
#define _YF_TRIM_H

#define IS_SPACE(x) ((x)==' '||(x)=='\r'||(x)=='\n'||(x)=='f'||(x)=='\b'||(x)=='\t')
#define OPTION_BUF_LEN 1024

#ifndef _STRING_H
#define _STRING_H
#include <string.h>
#endif /* string.h */

#ifndef _MEMORY_H
#define _MEMORY_H
#include <memory.h>
#endif /* memory.h */

void trim(const char *str,char *buffer);

#endif
