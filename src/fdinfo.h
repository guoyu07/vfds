#ifndef _FDINFO_H_
#define _FDINFO_H_
#include "global.h"

extern struct conn *acon;
extern int maxfds; 
extern int init_fdinfo(void);		//��ʼ��ȫ��ʹ�õ�fd�����Դ
extern void fini_fdinfo(void);		//�ͷ�fdʹ�õ������Դ
#endif
