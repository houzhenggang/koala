#ifndef _YF_TRIM_H
#define _YF_TRIM_H

#define IS_SPACE(x) ((x)==' '||(x)=='\r'||(x)=='\n'||(x)=='f'||(x)=='\b'||(x)=='\t')
#define OPTION_BUF_LEN 1024

void trim(const char *str, char *buffer);

#endif
