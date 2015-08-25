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
		curcon->user = malloc(sizeof(log_peer));
	if (curcon->user == NULL)
	{
		LOG(sig_log, LOG_ERROR, "malloc err %m\n");
		return RET_CLOSE_MALLOC;
	}
	memset(curcon->user, 0, sizeof(log_peer));
	peer = (log_peer *)curcon->user;
	peer->hbtime = time(NULL);
	peer->sock_stat = CONNECTED;
	peer->fd = fd;
	peer->ip = ip;
	INIT_LIST_HEAD(&(peer->alist));
	INIT_LIST_HEAD(&(peer->hlist));
	list_move_tail(&(peer->alist), &activelist);
	list_add(&(peer->hlist), &online_list[ip&ALLMASK]);
	LOG(sig_log, LOG_NORMAL, "a new ip %s connect, fd[%d] init ok!\n", ipstr, fd);
	return 0;
}

/*处理接收数据*/
static int check_req(int fd)
{
	sig_head h;
	sig_body b;
	char *data;
	size_t datalen;
	if (get_client_data(fd, &data, &datalen))
	{
		LOG(sig_log, LOG_TRACE, "fd[%d] no data!\n", fd);
		return -1;  /*no suffic data, need to get data more */
	}
	int ret = parse_sig_msg(&h, &b, data, datalen);
	if (ret > 0)
	{
		LOG(sig_log, LOG_TRACE, "fd[%d] no suffic data!\n", fd);
		return -1;  /*no suffic data, need to get data more */
	}
	if (ret == E_PACKET_ERR_CLOSE)
	{
		LOG(sig_log, LOG_ERROR, "fd[%d] ERROR PACKET bodylen is [%d], must be close now!\n", fd, h.bodylen);
		return RECV_CLOSE;
	}
	int clen = h.bodylen + SIG_HEADSIZE;
	ret = do_req(fd, &h, &b);
	consume_client_data(fd, clen);
	return ret;
}

/*连接有数据可读时调用*/
int svc_recv(int fd) 
{
	struct conn *curcon = &acon[fd];
	log_peer *peer = (log_peer *) curcon->user;
	peer->hbtime = time(NULL);
	list_move_tail(&(peer->alist), &activelist);
	
	int ret = RECV_ADD_EPOLLIN;
	int subret = 0;
	while (1)
	{
		subret = check_req(fd);
		if (subret == -1)
			break;
		if (subret == RECV_CLOSE)
			return RECV_CLOSE;
		ret |= subret;
	}
	return ret;
}

/*连接可写数据时调用*/
int svc_send(int fd)
{
	struct conn *curcon = &acon[fd];
	log_peer *peer = (log_peer *) curcon->user;
	peer->hbtime = time(NULL);
	list_move_tail(&(peer->alist), &activelist);
	return SEND_ADD_EPOLLIN;
}

/*信令线程定时任务*/
void svc_timeout()
{
	time_t now = time(NULL);
	int to = g_config.timeout * 2;
	log_peer *peer = NULL;
	list_head_t *l;
	sig_head h;
	sig_body b;
	list_for_each_entry_safe_l(peer, l, &activelist, alist)
	{
		if (peer == NULL)
			continue; 
		if (now - peer->hbtime > g_config.timeout && now - peer->hbtime < to){
			h.bodylen = sizeof(self_stat);
			h.cmdid = AGENT_HB_REQ;
			h.status = A_HB_2_M;
			memcpy(b.body, &self_stat, sizeof(self_stat));		
			active_send(peer, &h, &b);
		}
		if (now - peer->hbtime < to)			
			break;
		
		char ipstr[16] = {0x0};
		ip2str(ipstr, peer->ip);
		LOG(sig_log, LOG_NORMAL, "ip %s connect timeout close %d [%lu:%lu]\n", ipstr, peer->fd, now, peer->hbtime);
		do_close(peer->fd);
	}
}

/*连接关闭时调用，清除连接信息*/
void svc_finiconn(int fd)
{
	struct conn *curcon = &acon[fd];
	if (curcon->user == NULL)
		return;

	log_peer *peer = (log_peer *) curcon->user;
	list_del_init(&(peer->alist));
	list_del_init(&(peer->hlist));
	
	char ipstr[16] = {0x0};
	ip2str(ipstr, peer->ip);
	
	memset(curcon->user, 0, sizeof(log_peer));
	free(curcon->user);
	curcon->user = NULL;
	LOG(sig_log, LOG_NORMAL, "svn_finiconn ip %s,close fd [%d]!\n", ipstr, fd); 
}
