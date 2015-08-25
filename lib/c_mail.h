#ifndef __C_MAIL_H_
#define __C_MAIL_H_
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif
typedef struct {
	char *stmp_server;
	int port;
	int contenttype; //1��ͨ�ı� 2html�ı�
	char *username;
	char *passwd;
	char *sendName;
	char *sender;
	char *receiver;
	char *ccreceiver;
	char *bccreceiver;
	char *title;
	char *content;
} mail_info;

int sendmail(const mail_info *mailinfo, char *errmsg);
#ifdef __cplusplus
}
#endif
#endif
