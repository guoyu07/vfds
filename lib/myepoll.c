#include <stdlib.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include "myconfig.h"
#include "myepoll.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
void epoll_add(int epfd, int fd, int events) 
{
	struct epoll_event ev;
	ev.events = events | EPOLLERR | EPOLLET ;
	ev.data.fd = fd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);	
}

void epoll_mod(int epfd, int fd, int events) 
{
	struct epoll_event ev;
	ev.events = events | EPOLLERR | EPOLLET;
	ev.data.fd = fd;
	epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);	
}

void epoll_del(int epfd, int fd) 
{
	struct epoll_event ev;
	ev.data.fd = fd;
	epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);	
}

int get_listen_sock(int port, int protocol)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	int fd = socket(AF_INET, protocol, 0);
	if(fd < 0) {
		printf("socket(AF_INET, SOCK_STREAM, 0): %m\n");
		return -1;
	}

	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	struct linger linger = {0, 0};
	setsockopt(fd, SOL_SOCKET, SO_LINGER, (int *)&linger, sizeof(linger));

	if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("bind(%d): %m\n", port);
		return -1;
	}

	if (protocol == SOCK_STREAM)
	{
		if(listen(fd, myconfig_get_intval("listen_queue_backlog", 10000)) < 0) {
			printf("bind(%d): %m\n", port);
			return -1;
		}
	}

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	return fd;
}

int createsocket(char *ip, int port)
{
	int					sockfd;
	struct sockaddr_in	servaddr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		return -1;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);

	int rc = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if (rc)
	{
		close(sockfd);
		return -1;
	}
	return sockfd;
}
