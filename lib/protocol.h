#ifndef _PROTOCOL_H_ 
#define _PROTOCOL_H_ 
#include <stdint.h>

#define SIG_HEADSIZE 4
#define MAX_SIG_BODY 4096
extern const char *str_cmd[];
enum {E_PACKET_ERR_CLOSE = -100, E_PRO_OK = 0, E_PRO_HEAD_LEN, E_PRO_TOTAL_LEN, E_DATA_LEN};

typedef struct {
	uint16_t bodylen;
	uint8_t cmdid;
	uint8_t status;
}sig_head;

typedef struct {
	char body[MAX_SIG_BODY];
}sig_body;


/*信号cmdid定义*/
#define AGENT_IN_REQ 0X01
#define MASTER_IN_RES 0x81

#define AGENT_HB_REQ 0X02
#define MASTER_HB_RES 0X82

#define AGENT_NT_RES 0X03
#define MASTER_NT_REQ 0X83

#define AGENT_CT_RES 0X04
#define MASTER_CT_REQ 0X84


/*信号状态定义*/
#define A_L_2_M 0X01
#define A_HB_2_M 0x02
#define A_NT_2_M 0x03
#define A_CT_2_M 0X04

#define M_L_2_A 0X01
#define M_HB_2_A 0X02
#define M_NT_2_A 0X03
#define M_CT_2_A 0X04

/*数据cmdid定义*/
#define AGENT_DL_REQ 0X01
#define MASTER_DL_RES 0X81

#define AGENT_LOG_POST 0x03

/*数据状态定义*/
#define A_DL_2_M 0x01
#define M_DL_2_A 0x02

#define A_LOG_2_M 0x03

#ifdef __cplusplus
extern "C"
{
#endif

	/* parse_sig_msg:解析信息消息
	 * h:解析出的消息头
	 * b:解析出的消息体
	 * s:消息源
	 * slen:消息源的长度
	 * ret = 0,ok, other err
	 */
	int parse_sig_msg(sig_head *h, sig_body *b, char *s, int slen);

	/*create_sig_msg：组装信令消息
	 * cmdid:命令字
	 * status:状态
	 * b:消息体
	 * o:组装后的消息
	 *ret > 0 outlen, <= 0 err
	 */
	int create_sig_msg(uint8_t cmdid, uint8_t status, sig_body *b, char *o, uint16_t bodylen);

#ifdef __cplusplus
}
#endif


#endif
