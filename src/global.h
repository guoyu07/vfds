#ifndef _GLOBAL_H_
#define _GLOBAL_H_
#include <fcntl.h>
#include <sys/poll.h>
#include "atomic.h"
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "list.h"
#include "log.h"
#include "myconfig.h"
#include "mybuff.h"

#define ID __FILE__
#define LN __LINE__
#define FUNC __FUNCTION__

//global conn
extern struct conn *acon;

//global log fd
extern int glogfd;

//connect object
struct conn {
	char peerip[16];    //for debug print
	int fd;      //recheck avoid coredump
	struct mybuff send_buff;	//send buffer for client
	struct mybuff recv_buff;	//recv buffer for client
	int send_len;            //send len between call svc_send
	void* user;				//user custom data
	SSL *ssl;	//ssl object
	int ssl_want_read;	//wait for read SSL_OPER 
	int ssl_want_write;	//wait for write SSL_OPER
};

#define RECV_CLOSE 0x01   //do_recv need to close socket
#define RECV_ADD_EPOLLIN 0x02  //do_recv need to add fd EPOLLIN
#define RECV_ADD_EPOLLOUT 0x04 //do_recv need to add fd EPOLLOUT
#define RECV_ADD_EPOLLALL 0x06  //do_recv need to add fd EPOLLOUT and EPOLLIN
#define RECV_SEND 0x08  //do_recv need to send at once 

#define SEND_CLOSE 0x10 //do_send need to close socket
#define SEND_ADD_EPOLLIN 0x20 //do_send need to add fd EPOLLIN
#define SEND_ADD_EPOLLOUT 0x40 //do_send need to add fd EPOLLOUT
#define SEND_ADD_EPOLLALL 0x80 //do_send need to add fd EPOLLOUT and EPOLLIN

#define RET_OK 300
#define RET_SUCCESS 301
#define RET_CLOSE_HB 302  //4 detect hb
#define RET_CLOSE_MALLOC 303  //4 malloc err
#define RET_CLOSE_DUP 304  //dup connect


enum MODE {CON_PASSIVE = 0, CON_ACTIVE};

enum SERVER_STAT {UNKOWN_STAT = 0, WAIT_SYNC, SYNCING, SYNCED, ON_LINE};

enum SSL_OPER {SSL_ACCEPT = 1, SSL_READ, SSL_WRITE};
#endif
