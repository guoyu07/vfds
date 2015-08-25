#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "common.h"
#include "global.h"
#include "so.h"
#include "log.h"
#include "myepoll.h"
#include "sig.h"
#include "util.h"
#include "protocol.h"

/*信令线程日志FD*/
int sig_log = -1;
/*服务器当前状态*/
extern uint8_t self_stat;
/*已连接master队列*/
static list_head_t activelist;
/*快速查找在线master*/
static list_head_t online_list[256];

extern int svc_initconn(int fd);

#define SENDBUFSIZE 2048000
char sendbuf[SENDBUFSIZE];

#include "sig_base.c"

/*信令线程初始化调用*/
int svc_init() 
{
	char *logname = myconfig_get_value("sig_logname");
	if (!logname) 
		logname = "./sig_log.log"; 
	char *cloglevel = myconfig_get_value("sig_loglevel");
	int loglevel = LOG_NORMAL;
	if (cloglevel)
		loglevel = getloglevel(cloglevel);
	int logsize = myconfig_get_intval("sig_logsize", 100);
	int logintval = myconfig_get_intval("sig_logtime", 3600);
	int lognum = myconfig_get_intval("sig_lognum", 10);
	sig_log = registerlog(logname, loglevel, logsize, logintval, lognum);
	if (sig_log < 0)
		return -1;
	LOG(sig_log, LOG_NORMAL, "svc_init init log ok!\n");

	INIT_LIST_HEAD(&activelist);
	int i = 0;
	for (i = 0; i < 256; i++)
	{
		INIT_LIST_HEAD(&online_list[i]);
	}
	self_stat = ON_LINE;
	return 0;
}

/*新连接初始化时调用*/
int svc_initconn(int fd) 
{
	uint32_t ip = getpeerip(fd);
	char ipstr[16] = {0x0};
	ip2str(ipstr, ip);
	log_peer *peer = NULL;
	if (find_ip_stat(ip, &peer) == 0)
	{          
		LOG(sig_log, LOG_ERROR, "fd %d ip %s dup connect!\n", fd, ipstr);                                                                                 
		return RET_CLOSE_DUP;    
	}

	struct conn *curcon = &acon[fd];
	if (curcon->user == NULL)
		curcon->user = malloc(1024);
	if (curcon->user == NULL)
	{
		LOG(sig_log, LOG_ERROR, "malloc err %m\n");
		return RET_CLOSE_MALLOC;
	}
	memset(curcon->user, 0, 1024);
	LOG(sig_log, LOG_NORMAL, "a new ip %s connect, fd[%d] init ok!\n", ipstr, fd);
	return 0;
}

static int get_result(char *url, char *buf, int len)
{
	memset(buf, 0, len);
	sprintf(buf, "request url:%s, ramdom digital:%d\n", url, rand());
	return strlen(buf);
}

static int handle_request(int cfd) 
{   
	char httpheader[1024] = {0x0};
	struct conn *c = &acon[cfd];
	char *url = (char*)c->user;
	LOG(sig_log, LOG_NORMAL, "[%u] url = %s\n", getpeerip(cfd), url);

	int n = get_result(url, sendbuf, SENDBUFSIZE);
	if (n <= 0)
	{   
		LOG(sig_log, LOG_ERROR, "err request %s\n", url);
		return RECV_CLOSE;
	}
	snprintf(httpheader, sizeof(httpheader), "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n", n);
	set_client_data(cfd, httpheader, strlen(httpheader));
	if (n > 0) 
		set_client_data(cfd, sendbuf, n);
	return RECV_SEND;
}   

static int check_request(int fd, char* data, int len) 
{
	if(len < 14)
		return 0;

	struct conn *c = &acon[fd];
	if(!strncmp(data, "GET /", 5)) {
		char* p;
		if((p = strstr(data + 5, "\r\n\r\n")) != NULL) {
			char* q;
			int len;
			if((q = strstr(data + 5, " HTTP/")) != NULL) {
				len = q - data - 5;
				if(len < 1023) {  
					strncpy(c->user, data + 5, len);
					((char*)c->user)[len] = '\0';
					return p - data + 4;
				}
			}
			return -2;  
		}
		else 
			return 0;
	}   
	else
		return -1;
}

static int check_req(int fd)
{       
	char *data; 
	size_t datalen;
	if (get_client_data(fd, &data, &datalen))
	{       
		LOG(sig_log, LOG_DEBUG, "fd[%d] no data!\n", fd);
		return RECV_ADD_EPOLLIN;  /*no suffic data, need to get data more */
	}               
	int clen = check_request(fd, data, datalen);
	if (clen < 0)   
	{           
		LOG(sig_log, LOG_DEBUG, "fd[%d] data error ,not http!\n", fd);
		return RECV_CLOSE;
	}   
	if (clen == 0)
	{       
		LOG(sig_log, LOG_DEBUG, "fd[%d] data not suffic!\n", fd);
		return RECV_ADD_EPOLLIN;
	}   
	int ret = handle_request(fd);
	consume_client_data(fd, clen);
	return ret;
}

/*连接有数据可读时调用*/
int svc_recv(int fd) 
{
	return check_req(fd);
}

/*连接可写数据时调用*/
int svc_send(int fd)
{
	return SEND_CLOSE;
}

/*信令线程定时任务*/
void svc_timeout()
{
}

/*连接关闭时调用，清除连接信息*/
void svc_finiconn(int fd)
{
	struct conn *curcon = &acon[fd];
	if (curcon->user == NULL)
		return;

	memset(curcon->user, 0, 1024);
	free(curcon->user);
	curcon->user = NULL;
	LOG(sig_log, LOG_NORMAL, "svn_finiconn,close fd [%d]!\n", fd); 
}
