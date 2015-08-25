#include "protocol.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int parse_sig_msg(sig_head *h, sig_body *b, char *s, int slen)
{
	if (slen < SIG_HEADSIZE)
		return E_PRO_HEAD_LEN;
	memcpy(h, s, sizeof(sig_head));
	h->bodylen = ntohs(h->bodylen);
	if (h->bodylen >= MAX_SIG_BODY)
		return E_PACKET_ERR_CLOSE;
	if (slen < SIG_HEADSIZE + h->bodylen)
		return E_PRO_TOTAL_LEN;
	if (slen == SIG_HEADSIZE)
		return 0;
	memcpy(b->body, s + SIG_HEADSIZE, h->bodylen);
	return 0;
}

int create_sig_msg(uint8_t cmdid, uint8_t status, sig_body *b, char *o, uint16_t bodylen)
{
	sig_head nh;
	nh.bodylen = htons(bodylen);
	nh.cmdid = cmdid;
	nh.status = status;

	char *p = o;
	memcpy(p, &nh, sizeof(nh));
	p += sizeof(nh);
	if (bodylen == 0)
		return sizeof(nh);

	memcpy(p, b->body, bodylen);
	p += bodylen;

	return p - o;
}

