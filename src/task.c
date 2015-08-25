#include <stdlib.h>
#include "task.h"
#include "common.h"
#include "log.h"

extern int glogfd;

static list_head_t logtask[TASK_UNKNOWN];

static pthread_mutex_t mutex[TASK_UNKNOWN];

static int g_timelock_time = 3;

int init_task_info()
{
	int i = 0;
	for(i = 0; i < TASK_UNKNOWN; i++)
	{
		INIT_LIST_HEAD(&logtask[i]);
		if(pthread_mutex_init(&mutex[i], NULL))
		{
			LOG(glogfd, LOG_ERROR, "pthread_mutex_init err %m\n");
			return -1;
		}
	}

	log_tasklist *taskall = (log_tasklist *) malloc (sizeof(log_tasklist) * 2048);
	if(taskall == NULL)
	{
		LOG(glogfd, LOG_ERROR, "malloc log tasklist err [%m]\n");
		return -1;
	}

	memset(taskall, 0, sizeof(log_tasklist) * 2048);
	for(i = 0; i < 2048; i++)
	{
		INIT_LIST_HEAD(&taskall->llist);
		INIT_LIST_HEAD(&taskall->hlist);
		taskall->status = TASK_HOME;
		list_add(&(taskall->llist), &logtask[TASK_HOME]);
		taskall++;
	}

	g_timelock_time = myconfig_get_intval("timelock_time", 3);

	LOG(glogfd, LOG_DEBUG, "init_task_info ok!\n");
	return 0;

}

int log_set_task(log_tasklist *task, int status)
{
	if(status < 0 || status >= TASK_UNKNOWN)
	{
		LOG(glogfd, LOG_ERROR, "ERR %S:%d status range error %d\n", FUNC, LN, status);
		return -1;
	}
	
	int ret = -1;
	struct timespec to;
	to.tv_sec = time(NULL) + g_timelock_time;	
	to.tv_nsec = 0;
	ret = pthread_mutex_timedlock(&mutex[status], &to);
	if(ret != 0)
	{
		if(errno != EDEADLK)
		{
			LOG(glogfd, LOG_ERROR, "ERR %s:%d [%d] pthread_mutex_timelock error %m\n", FUNC, LN, status);
			return -1;
		}
	}
	
	list_del_init(&(task->llist));
	list_add_tail(&(task->llist), &logtask[status]);
	task->status = status;

	if (pthread_mutex_unlock(&mutex[status]))
		LOG(glogfd, LOG_ERROR, "ERR %s:%d pthread_mutex_unlock error %m\n", FUNC, LN);
	
	return ret;	
}

int log_get_task(log_tasklist **task, int status)
{
	int ret = GET_TASK_ERR;
	if(status < 0 || status >= TASK_UNKNOWN)
	{
		LOG(glogfd, LOG_ERROR, "ERR %S:%d status range error %d\n", FUNC, LN, status);
		return ret;
	}

	struct timespec to;
	to.tv_sec = time(NULL) + g_timelock_time;	
	to.tv_nsec = 0;
	ret = pthread_mutex_timedlock(&mutex[status], &to);
	if(ret != 0)
	{
		if(errno != EDEADLK)
		{
			LOG(glogfd, LOG_ERROR, "ERR %s:%d [%d] pthread_mutex_timelock error %m\n", FUNC, LN, status);
			return -1;
		}
	}

	ret = GET_TASK_NOTHING;
	log_tasklist *tmp = NULL;
	list_head_t *l;
	list_for_each_entry_safe_l(tmp, l, &logtask[status], llist)
	{
		ret = GET_TASK_OK;
		*task = tmp;
		(*task)->status = TASK_UNKNOWN;
		list_del_init(&(tmp->llist));
		break;
	}

	if(ret == GET_TASK_NOTHING && status == TASK_HOME)
	{
		LOG(glogfd, LOG_DEBUG, "get from home , need malloc!\n");
		*task = (log_tasklist *) malloc (sizeof(log_tasklist));
		if(task == NULL)
		{
			LOG(glogfd, LOG_ERROR, "ERR: %s:%d malloc %m\n", FUNC, LN);
		}	
		else
		{
			ret = GET_TASK_OK;
			INIT_LIST_HEAD(&((*task)->llist));
			INIT_LIST_HEAD(&((*task)->hlist));
			(*task)->status = TASK_UNKNOWN;
		}
	}
	
	if (pthread_mutex_unlock(&mutex[status]))
		LOG(glogfd, LOG_ERROR, "ERR %s:%d pthread_mutex_unlock error %m\n", FUNC, LN);

	return ret;
}

int mv_task_to(log_tasklist *task, int status)
{
	if(status < 0 || status >= TASK_UNKNOWN)
    {
        LOG(glogfd, LOG_ERROR, "ERR %S:%d status range error %d\n", FUNC, LN, status);
        return -1;
    }
	
	struct timespec to;
	to.tv_sec = time(NULL) + g_timelock_time;	
	to.tv_nsec = 0;
	int ret = pthread_mutex_timedlock(&mutex[task->status], &to);
    if(ret != 0)
    {
        if(errno != EDEADLK)
        {
            LOG(glogfd, LOG_ERROR, "ERR %s:%d [%d] pthread_mutex_timelock error %d\n", FUNC, LN, status, task->status);
            return -1;
        }
    }
	
	list_del_init(&(task->llist));

	if (pthread_mutex_unlock(&mutex[task->status]))
        LOG(glogfd, LOG_ERROR, "ERR %s:%d pthread_mutex_unlock error %m\n", FUNC, LN);
	
	return log_set_task(task, status);
}

int scan_status_task(int status, timeout_task ob, int del)
{
	if(status < 0 || status >= TASK_UNKNOWN)
	{
		LOG(glogfd, LOG_ERROR, "ERR %s:%d status range error %d\n", FUNC, LN, status);
		return -1;
	}
	
	int ret = -1;
	struct timespec to;
	to.tv_sec = time(NULL) + g_timelock_time;	
	to.tv_nsec = 0;
	ret = pthread_mutex_timedlock(&mutex[status], &to);
	if (ret != 0)
	{
		if (errno != EDEADLK)
		{
			LOG(glogfd, LOG_ERROR, "ERR %s:%d pthread_mutex_timedlock error %m\n", FUNC, LN);
			return -1;
		}
	}

	log_tasklist *tmp = NULL;
	list_head_t *l;
	list_for_each_entry_safe_l(tmp, l, &logtask[status], llist)	
	{
		if (del == TASK_DEL)
		{
			list_del_init(&(tmp->llist));
		}
		ob(tmp);
	}
	
	if (pthread_mutex_unlock(&mutex[status]))
		LOG(glogfd, LOG_ERROR, "ERR %s:%d pthread_mutex_unlock error %m\n", FUNC, LN);

	return ret;
}
