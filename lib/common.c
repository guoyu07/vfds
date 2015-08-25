#include "common.h"
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h> 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int get_ip_by_domain(char *serverip, char *domain)
{
	char **pptr;
	char                    str[128] = {0x0};
	struct hostent  *hptr;
	if ( (hptr = gethostbyname(domain)) == NULL) 
		return -1;

	switch (hptr->h_addrtype) {
		case AF_INET:
#ifdef  AF_INET6
		case AF_INET6:
#endif
			pptr = hptr->h_addr_list;
			for ( ; *pptr != NULL; pptr++)
			{
				inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str));
				strcpy(serverip, str);
				return 0;
			}
			break;

		default:
			return -1;
			break;
	}
	return -1;
}

void trim_in(char *s, char *d)
{
	/*skip head blank */

	while (s)
	{
		if (*s != ' ')
			break;
		s++;
	}

	int c = 0;
	while (*s)
	{
		if (*s == ' ')
		{
			c++;
			if (c == 1)
			{
				*d = *s;
				d++;
				s++;
				continue;
			}
			s++;
		}
		else
		{
			c = 0;
			*d = *s;
			d++;
			s++;
		}
	}
	return;
}

uint32_t r5hash(const char *p) 
{
	uint32_t h = 0;
	while(*p) {
		h = h * 11 + (*p<<4) + (*p>>4);
		p++;
	}
	return h;
}

int get_strtime(char *buf)
{
    struct tm tmm; 
	time_t now = time(NULL);
	localtime_r(&now, &tmm);  
	sprintf(buf, "%04d%02d%02d%02d%02d%02d", tmm.tm_year + 1900, tmm.tm_mon + 1, tmm.tm_mday, tmm.tm_hour, tmm.tm_min, tmm.tm_sec);
	return 0;
}

int get_strdate(char *buf)
{
    struct tm tmm; 
	time_t now = time(NULL);
	localtime_r(&now, &tmm);  
	sprintf(buf, "%04d%02d%02d", tmm.tm_year + 1900, tmm.tm_mon + 1, tmm.tm_mday);
	return 0;
}

