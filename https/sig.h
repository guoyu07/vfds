#ifndef __LOG_SIG_SO_H
#define __LOG_SIG_SO_H
#include "list.h"
#include "global.h"
#include "init.h"
#include "common.h"
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <dirent.h>

#define ALLMASK 0xFF

enum SOCK_STAT {LOGOUT = 0, CONNECTED, LOGIN, HB_SEND, HB_RSP, IDLE, RECV_LAST, SEND_LAST};

typedef struct {
	list_head_t alist;
	list_head_t hlist;
	int fd;
	uint32_t hbtime;
	uint32_t ip;
	uint8_t sock_stat;   /* SOCK_STAT */
	uint8_t server_stat; /* SERVER_STAT*/
} log_peer;

int find_ip_stat(uint32_t ip, log_peer **dpeer);

#endif
