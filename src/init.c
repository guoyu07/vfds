#include <stdio.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "init.h"

//global config 
t_g_config g_config;

//local ip
uint32_t localip[64];

static int init_local_ip()
{
	memset(localip, 0, sizeof(localip));	
	struct ifconf ifc;	
	struct ifreq *ifr = NULL;	
	int i;	
	int nifr = 0;

	i = socket(AF_INET, SOCK_STREAM, 0);	
	if(i < 0) 		
		return -1;
	ifc.ifc_len = 0;	
	ifc.ifc_req = NULL;
	if(ioctl(i, SIOCGIFCONF, &ifc) == 0) 
	{
		ifr = malloc(ifc.ifc_len > 128 ? ifc.ifc_len : 128);
		ifc.ifc_req = ifr;
		if(ioctl(i, SIOCGIFCONF, &ifc) == 0)
			nifr = ifc.ifc_len / sizeof(struct ifreq);
	}
	close(i);

	int index = 0;
	for (i = 0; i < nifr; i++)
	{
		if (!strncmp(ifr[i].ifr_name, "lo", 2))
			continue;
		uint32_t ip = ((struct sockaddr_in *)&ifr[i].ifr_addr)->sin_addr.s_addr;
		localip[index%64] = ip;
		index++;
	}
	return 0;
}

int init_work_thread(t_thread_arg *arg)                                                                                                           
{
	int iret = 0;      
	if((iret = register_thread(arg->name, log_signalling_thread, (void *)arg)) < 0) 
		return iret;                                                                 
	LOG(glogfd, LOG_DEBUG, "%s:%s:%d\n", ID, FUNC, LN);        
	return 0;
}    

int init_global()
{	
	self_stat = UNKOWN_STAT;	
	memset(&g_config, 0, sizeof(t_g_config));

	g_config.sig_port = myconfig_get_intval("sig_port", 49810);	
	g_config.data_port = myconfig_get_intval("data_port", 49820);	

	g_config.timeout = myconfig_get_intval("timeout", 30);	
	g_config.chktimeout = myconfig_get_intval("chktimeout", 5);

	g_config.enable_ssl = myconfig_get_intval("enable_ssl", 0);
	if(g_config.enable_ssl)
	{
		char *val = myconfig_get_value("ssl_pub_key");
		if(val)
		{
			snprintf(g_config.ssl_pub_key, sizeof(g_config.ssl_pub_key), "%s", val);
		}
		else
		{
			LOG(glogfd, LOG_ERROR, "enable ssl must config ssl_pub_key\n");
			return -1;
		}
		val = myconfig_get_value("ssl_pri_key");
		if(val)
		{
			snprintf(g_config.ssl_pri_key, sizeof(g_config.ssl_pri_key), "%s", val);
		}
		else
		{
			LOG(glogfd, LOG_ERROR, "enable ssl must config ssl_pri_key\n");
			return -1;
		}
	}

	init_buff_size = myconfig_get_intval("socket_buff", 65536);	
	if (init_buff_size < 20480)		
		init_buff_size = 20480;

	if (init_local_ip())
	{
		LOG(glogfd, LOG_ERROR, "init_local_ip error %m\n");
		return -1;
	}
	return 0;
}
