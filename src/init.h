#ifndef _INIT_H_ 
#define _INIT_H_

#include "so.h"
#include "global.h" 
#include "thread.h"
#include "log.h"

//global log fd
extern int glogfd;  

//mybuff init buff size
extern int init_buff_size;

//server self stat
uint8_t self_stat;

//global info struct
typedef struct {	
	uint16_t sig_port;	
	uint16_t data_port;	
	uint16_t timeout;  //timeout to close connect
	uint16_t chktimeout;	//timeout to invoke so timeout method
	uint8_t enable_ssl;	//enable ssl
	char ssl_pub_key[256];	//ssl public key file path
	char ssl_pri_key[256];	//ssl private key file path
} t_g_config;

extern t_g_config g_config;        

extern uint32_t localip[64];

int init_global();

extern int init_work_thread(t_thread_arg *name);
#endif
