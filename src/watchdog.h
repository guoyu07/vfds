#ifndef _WATCHDOG_H_
#define _WATCHDOG_H_

#include "atomic.h"

struct threadstat {
	int tid;			//�߳�ID
	atomic_t tickcnt;	//tick��Ŀ
	int badcnt;			//�̱߳��ж�Ϊͣ��״̬�Ĵ���
};

extern int watchdog_pid;

static inline void thread_reached(struct threadstat *ts) {
	if(ts)
		atomic_inc(&ts->tickcnt);
}

extern struct threadstat *get_threadstat(void);
extern int start_watchdog(void);
#endif
