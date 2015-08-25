#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include "version.h"
#include "log.h"
#include "myconfig.h"
#include "daemon.h"
#include "watchdog.h"
#include "mybuff.h"
#include "fdinfo.h"
#include "thread.h"
#include "so.h"
#include "init.h"
#include "task.h"

//global log fd
int glogfd = -1;

//mybuff init buff size
int init_buff_size = 20480;

/*init global log*/
static int init_glog()
{
	char *logname = myconfig_get_value("log_main_logname");
	if (!logname)
		logname = "./main_log.log";
	char *cloglevel = myconfig_get_value("log_main_loglevel");
	int loglevel = LOG_NORMAL;
	if (cloglevel)
		loglevel = getloglevel(cloglevel);
	int logsize = myconfig_get_intval("log_main_logsize", 100); //max log size M
	int logintval = myconfig_get_intval("log_main_logtime", 3600); //rotate time 
	int lognum = myconfig_get_intval("log_main_lognum", 10); //max log num
	glogfd = registerlog(logname, loglevel, logsize, logintval, lognum);
	return glogfd;
}

/*gen pid file*/
static void gen_pidfile() {
	mode_t oldmask = umask(0);
	int fd = open("./watch-"_NS_".pid", O_CREAT | O_RDWR | O_TRUNC, 0644);
	if(fd > 0) {
		if(watchdog_pid != 0)	
			dprintf(fd, "%d\n", watchdog_pid);
		else 
			dprintf(fd, "%d\n", mainthread.pid);
		close(fd);
	}
	else {  
		printf("genpidfile fail, %m\n");
	}
	umask(oldmask);
}

/*parse args, use for show msg*/
static int parse_args(int argc, char* argv[]) {
	if(argc > 1) {
		if(!strncasecmp(argv[1], "-v", 2)) 
		{
			printf("Version:   %s\n", version_string);
			printf("Date   :   %s\n", compiling_date);	
			return 1;
		}
	}
	return 0;	
}

/*main thread loop, can use for time task*/
static void main_loop(struct threadstat *thst) {
	while(!stop) 
	{
		sleep(1);
		thread_reached(thst);
	}
}

#define ICALL(x)	if((err=x()) < 0) goto error
int main(int argc, char **argv) {	
	/*parse args*/
	if(parse_args(argc, argv))
		return 0;
		
	int err = 0;
	printf("Starting Server %s (%s)...%ld\n", version_string, compiling_date, nowtime());
	
	/*read config file*/
	if(myconfig_init(argc, argv) < 0) {
		printf("myconfig_init fail %m\n");
		goto error;
	}

	/*daemon run*/
	daemon_start(argc, argv);
	/*start watchdog*/
	ICALL(start_watchdog);
	/*init fdinfo*/
	ICALL(init_fdinfo);
	/*init_log thread*/
	ICALL(init_log);
	/*init global log*/
	ICALL(init_glog);
	/*init multi thread env*/
	ICALL(init_thread);
	/*init global env*/
	ICALL(init_global);
	/*init task queues*/
	ICALL(init_task_info);

	//register work thread
	t_thread_arg sig_arg;
	memset(&sig_arg, 0, sizeof(sig_arg));
	snprintf(sig_arg.name, sizeof(sig_arg.name), "./sig.so");
	sig_arg.port = 49812;	//if this port gt 0, thread will listen this port, use for server side	
	sig_arg.maxevent = myconfig_get_intval("log_sig_maxevent", 4096);
	sig_arg.protocol = SOCK_DGRAM;
	LOG(glogfd, LOG_NORMAL, "prepare start %s\n", sig_arg.name);
	if(init_work_thread(&sig_arg))
		goto error;	

	t_thread_arg data_arg;
	memset(&data_arg, 0, sizeof(data_arg));
	snprintf(data_arg.name, sizeof(data_arg.name), "./data.so");
	data_arg.port = 49812;	//if this port gt 0, thread will listen this port, use for server side	
	data_arg.maxevent = myconfig_get_intval("log_sig_maxevent", 4096);
	data_arg.protocol = SOCK_STREAM;
	LOG(glogfd, LOG_NORMAL, "prepare start %s\n", data_arg.name);
	if(init_work_thread(&data_arg))
		goto error;	

    /*set thread title*/
	thread_jumbo_title();
	
	/*start register thread*/
	if(start_threads() < 0)
		goto out;	
	
	gen_pidfile();		
	printf("Server Started\n");
	
	/*get main thread stat info*/
	struct threadstat *thst = get_threadstat();	
	/*main thread loop*/
	main_loop(thst);
out:
	printf("Stopping Server %s (%s)...\n", version_string, compiling_date);
	stop_threads();
	myconfig_cleanup();
	fini_fdinfo();
	printf("Server Stopped.\n");
	return restart;
error:
	if(err == -ENOMEM) 
		printf("\n\033[31m\033[1mNO ENOUGH MEMORY\033[0m\n");	
	printf("\033[31m\033[1mStart Fail.\033[0m\n");
	return -1;
}
