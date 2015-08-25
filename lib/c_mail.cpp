#include <iostream>
#include "base64.h"
#include "CSmtp.h"
#include "c_mail.h"

void addreceiver(CSmtp *mail, char *receivers, int type)
{
	char tmp[4096] = {0x0};
	memset(tmp, 0, sizeof(tmp));	
	strncpy(tmp, receivers, sizeof(tmp));

	char split = ';';
	int len = strlen(tmp);
	char *cur = tmp;
	while(cur < tmp + len)
	{
		char *p = strchr(cur, split);
		if(p != NULL)
			*p++ = '\0';

		if(type == 0)
        	mail->AddRecipient(cur);
		else if(type == 1)
			mail->AddCCRecipient(cur);
		else if(type == 2)
			mail->AddBCCRecipient(cur);

		if(p != NULL)
			cur = p;
		else
			break;
	}
}

int sendmail(const mail_info *mailinfo, char *errmsg)
{	
    try
    {
        CSmtp mail;        
		if(mailinfo->stmp_server == NULL || mailinfo->port <= 0)
		{
			strcpy(errmsg, "stmp_server or port must config!");
			return -1;
		}
        mail.SetSMTPServer(mailinfo->stmp_server, mailinfo->port);
		
		if(mailinfo->username != NULL && mailinfo->passwd != NULL)
		{
			mail.SetLogin(mailinfo->username);
			mail.SetPassword(mailinfo->passwd);
		}
		
		if(mailinfo->sendName != NULL)
		{
			mail.SetSenderName(mailinfo->sendName);
		}
		
		if(mailinfo->sender == NULL)
		{
			strcpy(errmsg, "sender must config!");
			return -1;
		}
        mail.SetSenderMail(mailinfo->sender);
        
		if(mailinfo->receiver == NULL)
		{
			strcpy(errmsg, "receiver must config!");
			return -1;
		}
		addreceiver(&mail, mailinfo->receiver, 0);
        
		if(mailinfo->ccreceiver != NULL)
		{
			addreceiver(&mail, mailinfo->ccreceiver, 1);
		}
		if(mailinfo->bccreceiver != NULL)
		{
			addreceiver(&mail, mailinfo->bccreceiver, 2);
		}
		
        mail.SetXPriority(XPRIORITY_NORMAL);
        mail.SetXMailer("56 mailer");

		if(mailinfo->contenttype == 0)
			mail.SetHeadFlag(1);
		else
			mail.SetHeadFlag(mailinfo->contenttype);
		
		if(mailinfo->title == NULL || mailinfo->content == NULL)
		{
			strcpy(errmsg, "title and content must config!");
			return -1;
		}
		mail.SetSubject(mailinfo->title);
		std::string basemsg = base64_encode(reinterpret_cast<const unsigned char *>(mailinfo->content), strlen(mailinfo->content));
        mail.SetMsgBody(basemsg.c_str());
        mail.Send();
    }
    catch(ECSmtp e)
    {
		strcpy(errmsg, e.GetErrorText().c_str());
        return -1;
    }    
    return 0;

}
