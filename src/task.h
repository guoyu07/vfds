#ifndef _TASK_H_
#define _TASK_H_

#include "list.h"
#include "init.h"
#include <stdint.h>
#include <time.h>
#include <pthread.h>

/*��������*/
enum {TASK_HOME = 0, TASK_RECV, TASK_UNKNOWN};

/*ȡ����״̬*/
enum {GET_TASK_ERR = -1, GET_TASK_OK, GET_TASK_NOTHING};

/*��������ʱ�Ƿ��Ƴ�����*/
enum {TASK_DEL = 0, TASK_HOLD};


typedef struct {
	char fname[16]; //basename=time_t + usrid + songid
	char buf[512];
	uint32_t idx;
	uint32_t total;
} t_udp_p;



/*�������Ԫ��*/
typedef struct {
	list_head_t llist;
	list_head_t hlist;
	int status; //�������ڶ�������
	uint32_t ip;
	t_udp_p p;
}log_tasklist;

typedef void (*timeout_task)(log_tasklist *task);

int init_task_info();

int log_set_task(log_tasklist *task, int status);

int log_get_task(log_tasklist **task, int status);

int mv_task_to(log_tasklist *task, int status);

int add_task_to_alltask(log_tasklist *task);

int get_task_from_alltask(log_tasklist **task, uint16_t lid);

int scan_status_task(int status, timeout_task ob, int del); 
#endif

