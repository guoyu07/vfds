#ifndef _COMMON_H_
#define _COMMON_H_
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>

#define ID __FILE__
#define FUNC __FUNCTION__
#define LN __LINE__

#ifdef __cplusplus
extern "C"
{
#endif
int get_ip_by_domain(char *serverip, char *domain);
void trim_in(char *s, char *d);
uint32_t r5hash(const char *p); 
int get_strtime(char *buf);
int get_strdate(char *buf);
#ifdef __cplusplus
}
#endif
#endif
