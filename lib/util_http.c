#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "util.h"

#define BUF_LEN 1024
#define MAX_STRING_LEN  2048

//xnet_select x defines
#define READ_STATUS     0
#define WRITE_STATUS    1
#define EXCPT_STATUS    2

static int timeout_sec = 10;
static int timeout_microsec = 0;

static void parse_src(char *src, char *domain, char *requestpath, int *port, int *ishttps)
{
	char *point_a;
	char *point_b;
	
	memset(domain, 0, sizeof(domain));
	memset(requestpath, 0, sizeof(requestpath));
	*port = 0;

	if(src == NULL)
		return;

	point_a = src;
	if(!strncmp(point_a, "http://", strlen("http://")))
	{
		*ishttps = 0;
		point_a = src + strlen("http://");
	}
	else if(!strncmp(point_a, "https://", strlen("https://")))
	{
		*ishttps = 1;
		point_a = src + strlen("https://");
	}

	point_b = strchr(point_a, '/');
	if(point_b != NULL)
	{
		memcpy(domain, point_a, strlen(point_a) - strlen(point_b));
		memcpy(requestpath, point_b, strlen(point_b));
	}
	else
	{
		memcpy(domain, point_a, strlen(point_a));
		sprintf(requestpath, "/");
	}
	
	if(point_b)
		domain[strlen(point_a) - strlen(point_b)] = 0;
	else
		domain[strlen(point_a)] = 0;

	point_a = strchr(domain, ':');
	if(point_a)
		*port = atoi(point_a + 1);
	else 
	{
		if(*ishttps == 1)
			*port = 443;
		else
			*port = 80;
	}
}

static int create_tcpsocket(const char *host, const unsigned short port, const unsigned short ishttps)
{
	int ret;
	char * transport = "tcp";
	struct hostent *phe; /* pointer to host information entry */
	struct protoent *ppe; /* pointer to protocol information entry */
	struct sockaddr_in sin; /* an Internet endpoint address */
	int s; /* socket descriptor and socket type */

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	if ((sin.sin_port = htons(port)) == 0)
		return -1;

	/* Map host name to IP address, allowing for dotted decimal */
	if( (phe = gethostbyname(host)) != NULL )
		memcpy(&sin.sin_addr, phe->h_addr, phe->h_length);
	else if( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE )
		return -1;

	/* Map transport protocol name to protocol number */
	if ( (ppe = getprotobyname(transport)) == 0)
		return -1;



	/* Allocate a common TCP socket */
	s = socket(PF_INET, SOCK_STREAM, ppe->p_proto);
	if (s < 0)
		return -1;

	if(ishttps != 1)
	{
		/* Connect the socket with timeout */
		fcntl(s, F_SETFL, O_NONBLOCK);
		if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		{
			if (errno == EINPROGRESS)
			{ //it is in the connect process 
				struct timeval tv; 
				fd_set writefds; 
				tv.tv_sec = timeout_sec; 
				tv.tv_usec = timeout_microsec; 

				FD_ZERO(&writefds); 
				FD_SET(s, &writefds); 

				if(select(s+1,NULL,&writefds,NULL,&tv)>0)
				{
					int len=sizeof(int); 
					//	下面的一句一定要，主要针对防火墙 
					getsockopt(s, SOL_SOCKET, SO_ERROR, &errno, &len); 
					if(errno != 0) 
						ret = 1;
					else
						ret = 0;
				}
				else
					ret = 2;//timeout or error happen 
			}
			else 
				ret = 1; 
		}
		else
		{
			ret = 1;
		}
	}
	else
	{
		/* create common tcp socket.seems non-block type is not supported by ssl. */
		ret = connect(s, (struct sockaddr *)&sin, sizeof(sin));
	}

	if(ret != 0){
		close(s);
		return -1;
	}
	return s;
}

static int xnet_select(int s, int sec, int usec, short x)
{
	int st = errno;
	struct timeval to;
	fd_set fs;
	to.tv_sec = sec;
	to.tv_usec = usec;
	FD_ZERO(&fs);
	FD_SET(s, &fs);
	switch(x){
		case READ_STATUS:
			st = select(s+1, &fs, 0, 0, &to);
			break;
		case WRITE_STATUS:
			st = select(s+1, 0, &fs, 0, &to);
			break;
		case EXCPT_STATUS:
			st = select(s+1, 0, 0, &fs, &to);
			break;
	}
	return(st);
}

int http_get(char **res, char *url)
{
	if(url == NULL)
	{
		*res = NULL;
		return -1;
	}

	int fd;
	char host[256] = {0x0};
	char requestpath[1024] = {0x0};
	int port = 0;
	int ishttps = 0;
	int reslength = 0;
	int ressize = 0;

	
	int n, ret;
	SSL *ssl;
	SSL_CTX *ctx;
	
	char buf[BUF_LEN];
	
	//parse url
	parse_src(url, host, requestpath, &port, &ishttps);
	
	//create socket
	fd = create_tcpsocket(host, port, ishttps);
	if(fd < 0)
		return -1;
	
	/* http request. */
	sprintf(buf, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n",requestpath, host);
	
	if(ishttps != 1)
	{
		if(xnet_select(fd, timeout_sec, timeout_microsec, WRITE_STATUS) > 0)
		{
			/* send off the message */
			write(fd, buf, strlen(buf));
		}
		else
		{
			return -1;
		}
		while (xnet_select(fd, timeout_sec, timeout_microsec, READ_STATUS) > 0)
		{
			if ((n = read(fd, buf, BUF_LEN-1)) > 0) 
			{
				buf[n] = '\0';
				if(reslength == 0)
				{
					reslength += n;
					ressize = BUF_LEN;
					*res = malloc(ressize);
					memset(*res, 0, ressize);
					char *tmp;
					if((tmp = strstr(buf, "\r\n\r\n")) != NULL)
					{
						strcat(*res, tmp + 4);
					}
					else
						strcat(*res, buf);
				}
				else 
				{
					reslength += n;
					ressize += BUF_LEN;
					*res = realloc(*res, ressize);
					strcat(*res, buf);				
				}	
			}
			else
			{
				break;
			}
		}
		//close the plain socket handler.
		close(fd);
	}
	else
	{
		SSL_load_error_strings();
		SSL_library_init();
		ctx = SSL_CTX_new(SSLv23_client_method());
		if ( ctx == NULL )
		{
			return -1;
		}

		ssl = SSL_new(ctx);
		if ( ssl == NULL ){
			return -1;
		}

		ret = SSL_set_fd(ssl, fd);
		if ( ret == 0 ){
			return -1;
		}

		/* PRNG */
		RAND_poll();
		while ( RAND_status() == 0 )
		{
			unsigned short rand_ret = rand() % 65536;
			RAND_seed(&rand_ret, sizeof(rand_ret));
		}
		
		/* SSL Connect */
		ret = SSL_connect(ssl);
		if( ret != 1 ){
			return -1;
		}

		//https socket write.
		SSL_write(ssl, buf, strlen(buf));
		while((n = SSL_read(ssl, buf, BUF_LEN-1)) > 0)
		{	
			buf[n] = '\0';
			if(reslength == 0)
			{
				reslength += n;
				ressize = BUF_LEN;
				*res = malloc(ressize);
				memset(*res, 0, ressize);
				char *tmp;
				if((tmp = strstr(buf, "\r\n\r\n")) != NULL)
				{
					strcat(*res, tmp + 4);
				}
				else
					strcat(*res, buf);
			}
			else 
			{
				reslength += n;
				ressize += BUF_LEN;
				*res = realloc(*res, ressize);
				strcat(*res, buf);				
			}	

		}
		
		if(n != 0)
		{
			return -1;
		}

		//close ssl tunnel.
		ret = SSL_shutdown(ssl);
		//if( ret != 1 ){
		//	usleep(10000);
		//	ret = SSL_shutdown(ssl);
		//	if(ret != 1)
		//	{
		//		close(fd);
		//		return -1;
		//	}
		//}

		//close the plain socket handler.
		close(fd);

		//clear ssl resource.
		SSL_free(ssl); 

		SSL_CTX_free(ctx);
		ERR_free_strings();
	}
	return 0;
}


