#ifndef _YF_TRIM_H
#define _YF_TRIM_H

#ifndef __u_char_defined
typedef unsigned char u_char;
#define __u_char_defined
#endif

#define IS_SPACE(x) ((x)==' '||(x)=='\r'||(x)=='\n'||(x)=='f'||(x)=='\b'||(x)=='\t')
#define OPTION_BUF_LEN 1024

void trim(const char *str, char *buffer);

void p0x_u_char(int len, u_char *msg);

void p0x_char(int len, char *msg);

#endif
