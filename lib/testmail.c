#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "c_mail.h"

int main(int argc, char **argv)
{
	mail_info mailinfo;
	memset(&mailinfo, 0, sizeof(mail_info));

	mailinfo.stmp_server = "smtp.renren-inc.com";
	mailinfo.port = 25;
	mailinfo.contenttype = 1;
	mailinfo.username = "56.alert@renren-inc.com";
	mailinfo.passwd = "alert@56com";
	mailinfo.sendName = "TEST";
	mailinfo.sender = "56.alert@renren-inc.com";
	mailinfo.receiver = "dingqin.lv@renren-inc.com";
	mailinfo.title = "test title";
	mailinfo.content = "test content!<br/>test second line!";

	char errmsg[256] = {0x0};
	int res = sendmail(&mailinfo, errmsg);
	if(res != 0)
		printf("send mail err [%s]\n", errmsg);
	else
		printf("send mail ok!\n");
	
	return 0;
}
