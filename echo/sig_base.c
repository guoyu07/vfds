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

/*处理信令*/
static int do_req(int fd, sig_head *h, sig_body *b)   
{
	struct conn *curcon = &acon[fd];
	log_peer *peer = (log_peer *)curcon->user;
	peer->hbtime = time(NULL);

	char buf[2048] = {0x0};
	size_t n = 0;
	
	sig_body ob;
	memset(&ob, 0, sizeof(sig_body));
	
	switch(h->cmdid)
	{
		case 0x01: 
			strncpy(ob.body, b->body, h->bodylen);
			n = create_sig_msg(0x02, 0x02, &ob, buf, strlen(ob.body));
			set_client_data(fd, buf, n);
			peer->sock_stat = SEND_LAST;
			LOG(sig_log, LOG_DEBUG, "fd[%d] recv,cmd:%x, status:%x, bodylen:%d, body:%s, send len:%d\n", fd, h->cmdid, h->status, h->bodylen, ob.body, n);
			return RECV_ADD_EPOLLOUT; 
			
		default: 
			LOG(sig_log, LOG_ERROR, "fd[%d] recv a bad cmd [%x] status [%x]!\n", fd, h->cmdid, h->status);
			return RECV_CLOSE;
	}
	return RECV_ADD_EPOLLIN;
}
