#ifndef _TASK_H_
#define _TASK_H_

#include "list.h"
#include "init.h"
#include <stdint.h>
#include <time.h>
#include <pthread.h>

/*队列类型*/
enum {TASK_HOME = 0, TASK_RECV, TASK_UNKNOWN};

/*取任务状态*/
enum {GET_TASK_ERR = -1, GET_TASK_OK, GET_TASK_NOTHING};

/*遍历队列时是否移除任务*/
enum {TASK_DEL = 0, TASK_HOLD};


typedef struct {
	char fname[16]; //basename=time_t + usrid + songid
	char buf[512];
	uint32_t idx;
	uint32_t total;
} t_udp_p;



/*任务队列元素*/
typedef struct {
	list_head_t llist;
	list_head_t hlist;
	int status; //任务所在队列类型
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

