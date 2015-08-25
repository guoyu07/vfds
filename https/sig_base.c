/*已连接队列中查找IP信息*/
int find_ip_stat(uint32_t ip, log_peer **dpeer)
{	
	list_head_t *hashlist = &(online_list[ALLMASK&ip]);	
	log_peer *peer = NULL;	
	list_head_t *l;	
	list_for_each_entry_safe_l(peer, l, hashlist, hlist)	
	{		
		if (peer->ip == ip)		
		{			
			*dpeer = peer;			
			return 0;		
		}	
	}	
	return -1;
}

/*发起连接与心跳*/
int active_send(log_peer *peer, sig_head *h, sig_body *b)
{
	char buf[2048] = {0x0};
	size_t n = 0;
	peer->hbtime = time(NULL);
	n = create_sig_msg(h->cmdid, h->status, b, buf, h->bodylen);
	set_client_data(peer->fd, buf, n);
	modify_fd_event(peer->fd, EPOLLOUT);
	LOG(sig_log, LOG_DEBUG, "active send %d cmdid %x\n", peer->fd, h->cmdid);
	return 0;
}

