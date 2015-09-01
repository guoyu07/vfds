#include "task.h"
#include "so.h"
#include "init.h"
#include "solib.h"
#include "myepoll.h"
#include "thread.h"
#include "myconfig.h"
#include "fdinfo.h"
#include "global.h"
#include "mybuff.h"
#include "log.h"
#include "util.h"
#include "watchdog.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

extern t_g_config g_config;  

static __thread struct epoll_event *pev;
static __thread int epfd;
static __thread int lfd;
static __thread int maxevent;
static __thread struct mylib solib;
static __thread char *iobuf;
static __thread SSL_CTX *ssl_ctx;
static __thread SSL *ssl;

static int handle_pre_ssl(int fd, int op_type);

#if __GNUC__ < 4
static inline void barrier(void) { __asm__ volatile("":::"memory"); }
#else
static inline void barrier(void) { __sync_synchronize (); }
#endif

static int sub_init_signalling(char *so)
{
	solib.handle = dlopen(so, RTLD_NOW);
	if (solib.handle == NULL)
	{
		LOG(glogfd, LOG_ERROR, "open %s err %s\n", so, dlerror());
		return -1;
	}
	solib.svc_init = (proc_init)dlsym(solib.handle, "svc_init");
	if (solib.svc_init)
		if (solib.svc_init() < 0)
		{
			LOG(glogfd, LOG_ERROR, "svc_init ERROR %m!\n");
			return -1;
		}
	solib.svc_initconn = (proc_method)dlsym(solib.handle, "svc_initconn");
	solib.svc_recv = (proc_method)dlsym(solib.handle, "svc_recv");
	solib.svc_send = (proc_method)dlsym(solib.handle, "svc_send");
	solib.svc_finiconn = (proc_fini)dlsym(solib.handle, "svc_finiconn");
	solib.svc_timeout = (proc_timeout)dlsym(solib.handle, "svc_timeout" );
	if (solib.svc_recv && solib.svc_send)
		return 0;
	LOG(glogfd, LOG_ERROR, "svc_send and svc_recv must be imp!\n");
	return -1;
}

void add_fd_2_efd(int fd)
{
	epoll_add(epfd, fd, EPOLLIN);
	fcntl(fd, F_SETFL, O_RDWR|O_NONBLOCK);

	struct conn *curconn = &acon[fd];
	curconn->fd = fd;
	curconn->send_len = 0;
	memset(curconn->peerip, 0, sizeof(curconn->peerip));
	mybuff_reinit(&(curconn->send_buff));
	mybuff_reinit(&(curconn->recv_buff));
	uint32_t ip = getpeerip(fd);
	ip2str(curconn->peerip, ip);
	LOG(glogfd, LOG_DEBUG, "fd [%d] [%s]set ok %d\n", fd, curconn->peerip, curconn->fd);
}

void modify_fd_event(int fd, int events)
{
	events = EPOLLIN|events;
	epoll_mod(epfd, fd, events);
	LOG(glogfd, LOG_DEBUG, "fd [%d] be modify!\n", fd);
}

int get_client_data(int fd, char **data, size_t *len)
{
	struct conn *curcon = &acon[fd];
	if(mybuff_getdata(&(curcon->recv_buff), data, len)) 
		return -1;
	return 0;
}

int consume_client_data(int fd, size_t len)
{
	struct conn *curcon = &acon[fd];
	mybuff_skipdata(&(curcon->recv_buff), len);
	return 0;
}

int set_client_data(int fd, char *buf, size_t len)
{
	struct conn *curcon = &acon[fd];
	mybuff_setdata(&(curcon->send_buff), buf, len);
	return 0;
}

int set_client_fd(int fd, int localfd, size_t offset, size_t len)
{
	struct conn *curcon = &acon[fd];
	mybuff_setfile(&(curcon->send_buff), localfd, offset, len);
	return 0;
}

static int ssl_accept_new(int fd)
{
	LOG(glogfd, LOG_TRACE, "fd [%d] begin ssl accept new\n", fd);
	struct conn *curcon = &acon[fd];
	int acc_ret = SSL_accept(curcon->ssl);
	if(acc_ret <= 0)
	{
		int ret = SSL_get_error(curcon->ssl, acc_ret);
		if(ret == SSL_ERROR_WANT_READ)
		{
			LOG(glogfd, LOG_DEBUG, "fd [%d] ssl accpet new want read\n", fd);
			curcon->ssl_want_read = SSL_ACCEPT;
			modify_fd_event(fd, EPOLLIN);
		}
		else if(ret == SSL_ERROR_WANT_WRITE)
		{
			LOG(glogfd, LOG_DEBUG, "fd [%d] ssl accept new want write\n", fd);
			curcon->ssl_want_write = SSL_ACCEPT;
			modify_fd_event(fd, EPOLLOUT);
		}
		else 
		{
			LOG(glogfd, LOG_ERROR, "fd [%d], ssl accept err [%m]\n", fd);
			do_close(fd);
		}
		return -1;
	}

	LOG(glogfd, LOG_DEBUG, "fd [%d] ssl accept new success\n", fd);
	if(curcon->ssl_want_read == SSL_ACCEPT)
		curcon->ssl_want_read = 0;
	if(curcon->ssl_want_write == SSL_ACCEPT)
		curcon->ssl_want_write = 0;
	modify_fd_event(fd, EPOLLIN);
	return 0;
}

static void accept_new()
{
	struct sockaddr_in addr;
	socklen_t len;
   	int fd = 0;

	while (1)
	{
	    fd = accept(lfd, (struct sockaddr *)&addr, (len = sizeof(addr), &len));
		if (fd < 0)
			break;
		if (fd >= maxfds)
		{
			LOG(glogfd, LOG_ERROR, "fd overflow ![%d] > [%d]\n", fd, maxfds);
			close(fd);
			continue;
		}
		if (solib.svc_initconn(fd))
		{
			LOG(glogfd, LOG_ERROR, "fd init err ![%d] %m\n", fd);
			close(fd);
			continue;
		}
		add_fd_2_efd(fd);

		//init connect ssl
		if(g_config.enable_ssl)
		{	
			struct conn *curcon = &acon[fd];
			curcon->ssl_want_read = 0;
			curcon->ssl_want_write = 0;
			curcon->ssl = SSL_new(ssl_ctx);
			if(curcon->ssl == NULL)
			{
				LOG(glogfd, LOG_ERROR, "fd [%d] creaet ssl err [%m]\n", fd);
				close(fd);
				continue;
			}
			SSL_set_fd(curcon->ssl, fd);
			LOG(glogfd, LOG_DEBUG, "fd [%d] creaet ssl and ssl bind fd\n", fd);

			ssl_accept_new(fd);
		}
	}
}

void do_close(int fd)
{
	if (fd >= 0 && fd < maxfds)
	{
		struct conn *curcon = &acon[fd];
		if (curcon->fd < 0)
		{
			LOG(glogfd, LOG_DEBUG, "fd %d already be closed %s\n", fd, FUNC);
			return;
		}

		LOG(glogfd, LOG_DEBUG, "%s:%s:%d close fd %d\n", ID, FUNC, LN, fd);
		struct conn *curconn = &(acon[fd]);
		if (solib.svc_finiconn)
			solib.svc_finiconn(fd);

		//clear ssl resource
		if (g_config.enable_ssl)
		{
			SSL_shutdown(curcon->ssl);
			SSL_free(curcon->ssl);
			curcon->ssl = NULL;
		}

		barrier();
		epoll_del(epfd, fd);
		curconn->fd = -1;
		close(fd);
	}
}

static int ssl_do_send(int fd)
{
	LOG(glogfd, LOG_TRACE, "fd [%d] begin ssl do send\n", fd);
	struct conn *curcon = &acon[fd];
	
	char* data;
	size_t len;
	if(!mybuff_getdata(&(curcon->send_buff), &data, &len))
	{
		int n = SSL_write(curcon->ssl, data, len);
		if(n <= 0)
		{
			int ret = SSL_get_error(curcon->ssl, n);
			if(ret == SSL_ERROR_WANT_READ)
			{
				LOG(glogfd, LOG_DEBUG, "fd [%d] ssl write want read\n", fd);
				curcon->ssl_want_read = SSL_WRITE;
				modify_fd_event(fd, EPOLLIN);
			}
			else if(ret == SSL_ERROR_WANT_WRITE)
			{
				LOG(glogfd, LOG_DEBUG, "fd [%d] ssl write want write\n", fd);
				modify_fd_event(fd, EPOLLOUT);
			}
			else 
			{
				LOG(glogfd, LOG_ERROR, "fd [%d], ssl write err [%m]\n", fd);
				do_close(fd);
			}
			return -1;
		}
		mybuff_skipdata(&(curcon->send_buff), n);
		curcon->send_len += n;
		return n;
	}
	return 0;
}

static void do_send(int fd, int ssl)
{
	LOG(glogfd, LOG_DEBUG, "%s:%s:%d\n", ID, FUNC, LN);
	int ret = SEND_ADD_EPOLLIN;
	int n = 0;
	struct conn *curcon = &acon[fd];
	if (curcon->fd < 0)
	{
		LOG(glogfd, LOG_DEBUG, "fd %d already be closed %s\n", fd, FUNC);
		return;
	}

	int localfd;
	off_t start;
	char* data;
	size_t len;

	//ssl send
	if(ssl && !mybuff_getdata(&(curcon->send_buff), &data, &len))
	{
		if(curcon->ssl_want_write > 0 && curcon->ssl_want_write != SSL_WRITE)
		{
			int hd_ret = handle_pre_ssl(fd, curcon->ssl_want_write);
			if(hd_ret == -1)
				return;
		}

		if(ssl_do_send(fd) == -1)
			return;
	}

	//common send
	if(!ssl && !mybuff_getdata(&(curcon->send_buff), &data, &len)) 
	{
		LOG(glogfd, LOG_DEBUG, "fd[%d] get len from data [%d]\n", fd, len);
		while (1)
		{
			n = send(fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL);
			if(n > 0) 
			{
				LOG(glogfd, LOG_DEBUG, "fd[%d] send len %d, datalen %d\n", fd, n, len);
				mybuff_skipdata(&(curcon->send_buff), n);
				if (n < len)
					ret = SEND_ADD_EPOLLOUT;
				curcon->send_len += n;
			}
			else if(errno == EINTR) 
				continue;
			else if(errno == EAGAIN) 
				ret = SEND_ADD_EPOLLOUT;
			else 
				ret = SEND_CLOSE;
			break;
		}
	}
	//only common send will send file, ssl send cant
	if(!ssl && ret == SEND_ADD_EPOLLIN && !mybuff_getfile(&(curcon->send_buff), &localfd, &start, &len))
	{
		LOG(glogfd, LOG_DEBUG, "fd[%d] get len from file [%d]\n", fd, len);
		size_t len1 = len > GSIZE ? GSIZE : len;
		while (1)
		{
			n = sendfile64(fd, localfd, &start, len1);
			if(n > 0) 
			{
				mybuff_skipfile(&(curcon->send_buff), n);
				LOG(glogfd, LOG_DEBUG, "%s:%s:%d fd[%d] send len %d, datalen %d\n", ID, FUNC, LN, fd, n, len1);
				if(n < len) 
					ret = SEND_ADD_EPOLLOUT;
				curcon->send_len += n;
			}
			else if(errno == EINTR) 
				continue;
			else if(errno == EAGAIN) 
				ret = SEND_ADD_EPOLLOUT;
			else 
			{
				LOG(glogfd, LOG_ERROR, "%s:%s:%d fd[%d] send err %d:%d:%m\n", ID, FUNC, LN, fd, n, len);
				ret = SEND_CLOSE;
			}
			break;
		}
	}

	switch (ret)
	{
		case SEND_CLOSE:
			do_close(fd);
			return;
		case SEND_ADD_EPOLLIN:
			modify_fd_event(fd, EPOLLIN);
			break;
		case SEND_ADD_EPOLLOUT:
			modify_fd_event(fd, EPOLLOUT);
			break;
		case SEND_ADD_EPOLLALL:
			modify_fd_event(fd, EPOLLOUT|EPOLLIN);
			break;
	}
	if (ret == SEND_ADD_EPOLLIN && solib.svc_send)
		if (solib.svc_send(fd) == SEND_CLOSE)
		{
			LOG(glogfd, LOG_ERROR, "%s:%s:%d send close\n", ID, FUNC, LN);
			do_close(fd);
		}
}

static int ssl_do_recv(int fd)
{
	LOG(glogfd, LOG_TRACE, "fd [%d] begin ssl do recv\n", fd);
	struct conn *curcon = &acon[fd];

	memset(iobuf, 0, init_buff_size);
	int n = SSL_read(curcon->ssl, iobuf, init_buff_size);
	if(n <= 0)
	{
		int ret = SSL_get_error(curcon->ssl, n);
		if(ret == SSL_ERROR_WANT_READ)
		{
			LOG(glogfd, LOG_DEBUG, "fd [%d] ssl read want read\n", fd);
			modify_fd_event(fd, EPOLLIN);
		}
		else if(ret == SSL_ERROR_WANT_WRITE)
		{
			LOG(glogfd, LOG_DEBUG, "fd [%d] ssl read err [%m]\n", fd);
			curcon->ssl_want_write = SSL_READ;
			modify_fd_event(fd, EPOLLOUT);
		}
		else 
		{
			LOG(glogfd, LOG_ERROR, "fd [%d], ssl accept err %m\n", fd);
			do_close(fd);
		}
		return -1;
	}

	LOG(glogfd, LOG_DEBUG, "fd[%d] ssl do recv len %d\n", fd, n);
	mybuff_setdata(&(curcon->recv_buff), iobuf, n);
	return n;
}

static void do_recv(int fd, int ssl)
{
	struct conn *curcon = &acon[fd];
	if (curcon->fd < 0)
	{
		LOG(glogfd, LOG_DEBUG, "fd %d already be closed %s\n", fd, FUNC);
		return;
	}

	int n = -1;
	while (1)
	{
		if(ssl)
		{
			if(curcon->ssl_want_read > 0 && curcon->ssl_want_read != SSL_READ)
			{
				int hd_ret = handle_pre_ssl(fd, curcon->ssl_want_read);
				if(hd_ret == -1)
					return;
			}

			int ret = ssl_do_recv(fd);
			if(ret == -1)
			{
				if(curcon->fd < 0)
					return;
				else
					break;
			}
		}
		else
		{
			n = recv(fd, iobuf, init_buff_size, MSG_DONTWAIT);
			if (n > 0)
			{
				LOG(glogfd, LOG_DEBUG, "fd[%d] recv len %d\n", fd, n);
				mybuff_setdata(&(curcon->recv_buff), iobuf, n);
				if (n == init_buff_size)
				{
					LOG(glogfd, LOG_TRACE, "fd[%d] need recv nextloop %d\n", fd, n);
					continue;
				}
				break;
			}
			if (n == 0)
			{
				LOG(glogfd, LOG_ERROR, "fd[%d] close %s:%d!\n", fd, ID, LN);
				return do_close(fd);
			}
			if (errno == EINTR)
			{
				LOG(glogfd, LOG_DEBUG, "fd[%d] need recv again!\n", fd);
				continue;
			}
			if (errno == EAGAIN)
			{
				LOG(glogfd, LOG_DEBUG, "fd[%d] need recv next!\n", fd);
				modify_fd_event(fd, EPOLLIN);
			}
		}
	}

	int ret = solib.svc_recv(fd);
	switch (ret)
	{
		case RECV_CLOSE:
			LOG(glogfd, LOG_ERROR, "fd[%d] close %s:%d!\n", fd, ID, LN);
			do_close(fd);
			break;
		case RECV_SEND:
			do_send(fd, ssl);
			break;
		case RECV_ADD_EPOLLIN:
			modify_fd_event(fd, EPOLLIN);
			break;
		case RECV_ADD_EPOLLOUT:
			modify_fd_event(fd, EPOLLOUT);
			break;
		case RECV_ADD_EPOLLALL:
			modify_fd_event(fd, EPOLLOUT|EPOLLIN);
			break;
	}
}

static void push_msg_to_recv(char *buf, uint32_t ip)
{
}

static void do_recv_udp(int fd)
{
	struct sockaddr_in client_addr;
	socklen_t cli_len=sizeof(client_addr);
	int rlen = recvfrom(fd, iobuf, sizeof(t_udp_p), 0, (struct sockaddr *)&client_addr, &cli_len);
	if (rlen < sizeof(t_udp_p))
	{
		LOG(glogfd, LOG_ERROR, "error udp msg %d\n", fd);
		return;
	}

	push_msg_to_recv(iobuf, client_addr.sin_addr.s_addr);
}

static void do_send_udp(int fd)
{
}

static void do_process(int fd, int events, t_thread_arg *argp)
{
	if(!(events & (EPOLLIN | EPOLLOUT))) 
	{
		LOG(glogfd, LOG_DEBUG, "error event %d, %d\n", events, fd);
		if (argp->protocol == SOCK_STREAM)
			do_close(fd);
		return;
	}
	if(events & EPOLLIN) 
	{
		LOG(glogfd, LOG_DEBUG, "read event %d, %d\n", events, fd);
		if (argp->protocol == SOCK_STREAM)
			do_recv(fd, argp->ssl);
		else
			do_recv_udp(fd);
	}
	if(events & EPOLLOUT) 
	{
		LOG(glogfd, LOG_DEBUG, "send event %d, %d\n", events, fd);
		if (argp->protocol == SOCK_STREAM)
			do_send(fd, argp->ssl);
		else
			do_send_udp(fd);
	}
}

static void set_socket_attr(int fd)
{
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &init_buff_size, sizeof(int));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &init_buff_size, sizeof(int));
}

static int init_ssl(int fd)
{
	//init ssl library
	SSL_library_init();
	//load all ssl algorithms	
	OpenSSL_add_all_algorithms();
	//load all error string
	SSL_load_error_strings();
	LOG(glogfd, LOG_DEBUG, "ssl library init, load algorithms, load error strings\n");

	//create ssl ctx
	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if(ssl_ctx == NULL)
	{
		LOG(glogfd, LOG_ERROR, "create ssl context err [%m]\n");
		return -1;
	}
	LOG(glogfd, LOG_DEBUG, "ssl ctx created\n");

	//set ssl ctx options
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	LOG(glogfd, LOG_DEBUG, "ssl ctx set options\n");


	//load public key
	if (SSL_CTX_use_certificate_file(ssl_ctx, g_config.ssl_pub_key, SSL_FILETYPE_PEM) <= 0) 
	{
		LOG(glogfd, LOG_ERROR, "set ssl public key file err [%m]\n");
		stop = 1;
		return -1;
	}
	LOG(glogfd, LOG_DEBUG, "ssl had load public key\n");

	//load private key
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, g_config.ssl_pri_key, SSL_FILETYPE_PEM) <= 0)
	{
		LOG(glogfd, LOG_ERROR, "set ssl private key file err [%m]\n");
		stop = 1;
		return -1; 
	}
	LOG(glogfd, LOG_DEBUG, "ssl had load private key\n");

	//check the private key 
	if (!SSL_CTX_check_private_key(ssl_ctx)) 
	{
		LOG(glogfd, LOG_ERROR, "ssl public key cherr [%m]\n");
		stop = 1;
		return -1;
	}
	LOG(glogfd, LOG_DEBUG, "ssl had check key\n");

	//create ssl
	ssl = SSL_new(ssl_ctx);	
	//link fd to ssl
	SSL_set_fd(ssl, fd);
	LOG(glogfd, LOG_DEBUG, "ssl created and bind fd\n");

	return 0;
}

static int handle_pre_ssl(int fd, int op_type)
{
	if(op_type == SSL_ACCEPT)
		return ssl_accept_new(fd);
	else if(op_type == SSL_READ)
		return ssl_do_recv(fd);
	else if(op_type == SSL_WRITE)
		return ssl_do_send(fd);
	return 0;
}

int log_signalling_thread(void *arg)
{
	t_thread_arg *argp = (t_thread_arg *)arg;
	if (sub_init_signalling(argp->name))
	{
		stop = 1;
		return -1;
	}
	if (argp->port > 0)
	{
		lfd = get_listen_sock(argp->port, argp->protocol);
		if (lfd < 0)
		{
			LOG(glogfd, LOG_ERROR, "get_listen_sock err %d\n", argp->port);
			stop = 1;
			return -1;
		}
		LOG(glogfd, LOG_DEBUG, "%s listen on %d\n", argp->name, argp->port);
	}
	maxevent = argp->maxevent;
    epfd = epoll_create(maxevent);
	if(epfd < 0) 
	{
		LOG(glogfd, LOG_ERROR, "epoll_create(%d): %m\n", maxevent);
		stop = 1;
		return -1;
	}
    pev = (struct epoll_event*)malloc(sizeof(struct epoll_event) * maxevent);
	if(pev == NULL) 
	{
		LOG(glogfd, LOG_ERROR, "allocate epoll_event(%d): %m\n", maxevent);
		stop = 1;
		return -1;
	}
	if (argp->port > 0)
	{
		if (argp->flag)
			set_socket_attr(lfd);
	}

	iobuf = malloc(init_buff_size);
	if (iobuf == NULL)
	{
		LOG(glogfd, LOG_ERROR, "allocate iobuf [%d] error %m\n", init_buff_size);
		stop = 1;
		return -1;
	}

	struct threadstat *thst = get_threadstat();
	int event = EPOLLIN;
	if (argp->port > 0)
		epoll_add(epfd, lfd, event);

	if(argp->ssl && argp->protocol == SOCK_STREAM)
	{
		if(init_ssl(lfd))
		{
			LOG(glogfd, LOG_ERROR, "init ssl err [%m]\n");
			return -1;
		}
	}

	int n = 0, i = 0;
	time_t last = time(NULL);
	time_t now = last;
	LOG(glogfd, LOG_DEBUG, "%s:%s:%d\n", ID, FUNC, LN);
	while (!stop)
	{
		n = epoll_wait(epfd, pev, maxevent, 1000);
		for(i = 0; i < n; i++) 
		{
			if (argp->protocol == SOCK_STREAM && argp->port > 0 && pev[i].data.fd == lfd)
				accept_new();
			else
				do_process(pev[i].data.fd, pev[i].events, argp);
		}
		thread_reached(thst);
		now = time(NULL);
		if (now > last + g_config.chktimeout)
		{
			last = now;
			if (solib.svc_timeout)
				solib.svc_timeout();
		}
	}
	return 0;
}


