#ifndef _Z_TCP_H_H_
#define _Z_TCP_H_H_

#include <sys/types.h>

/***********************************************/

#define ZTCP_FIXED_TCPHEAD 20		//固定tcp头的长度20Byte
#define ZTCP_LEN_4		 4		//首部长度字段一位代表4个Byte

//传输层tcp头，各个变量的大小（size）
#define ZTCP_HEAD_SPORT 2
#define ZTCP_HEAD_DPORT 2
#define ZTCP_HEAD_SEQ   4
#define ZTCP_HEAD_ACK   4
#define ZTCP_HEAD_OFFX2 1
#define ZTCP_HEAD_FLAGS 1
#define ZTCP_HEAD_WIN   2
#define ZTCP_HEAD_SUM   2
#define ZTCP_HEAD_URP   2

/***********************************************/
/* TCP header */
typedef u_int tcp_seq;

typedef struct _ZTCPHEAD_ {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define ZTCP_GETLEN(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20 
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
	void *option;
}zTCPHead;


/***********************************************/


/****************************************************/
/********************* 接口函数  ********************/

zTCPHead * zTCP_init();
void zTCP_free(zTCPHead *paHead);

const u_char* zTCP_UnpackHead(zTCPHead * paTCPHead, const u_char *packet);
int zTCP_UnpackNextFloor(zTCPHead *paTCPHead, const u_char *packet);
void  zTCP_PrintHead(zTCPHead* paTCPHead);

/******************** 	功能函数  *******************/
int zTCP_Start(const u_char * packet);


#endif