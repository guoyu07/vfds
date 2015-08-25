#ifndef _SO_H_
#define _SO_H_ 
#include <stdint.h>
#include <stdio.h>


#define GSIZE 1073741824    /*sendfile max send once*/

typedef struct {
	char flag; /*�Ƿ���Ҫ����sockbuff ����������·����Ĭ�����ã���������·���������ļ����� */
	char name[255];
	int port;
	int maxevent;
	int threadcount;
} t_thread_arg;

volatile extern int stop;		//1-������ֹͣ��0-������������

int log_signalling_thread(void *arg);

void add_fd_2_efd(int fd);

void do_close(int fd);

void modify_fd_event(int fd, int events);

int get_client_data(int fd, char **data, size_t *len);

int consume_client_data(int fd, size_t len);

int set_client_data(int fd, char *buf, size_t len);

int set_client_fd(int fd, int lfd, size_t offset, size_t len);

#endif
