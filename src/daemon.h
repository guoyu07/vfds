#ifndef _DAEMON_H_
#define _DAEMON_H_

volatile extern int stop;		//1-������ֹͣ��0-������������
volatile extern int restart;	//1-�������쳣�˳���Ҫ�Զ�������0-���Զ�����

extern int daemon_start(int, char **);
extern void daemon_stop();
extern void daemon_set_title(const char *title);
#endif
