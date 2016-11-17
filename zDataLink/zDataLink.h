#ifndef _Z_DATALINK_H_H_
#define _Z_DATALINK_H_H_

#include <stdio.h>
#include <sys/types.h>

/***********************************************/

//链路层头，各个变量的大小（size）
#define ZDATALINK_HEAD_ETHERADDR_LEN 6	//dhost占多少个字节（ZDATALINK_HEAD_ETHERADDR_LEN * ZDATALINK_HEAD_HOST_SIZE）
#define ZDATALINK_HEAD_HOST_SIZE     1	//每一个dhost结构占1Byte
#define ZDATALINK_HEAD_TYPE 		 2 	//头中的type字段占2Byte

//IP层协议的类型
#define ZDATALINK_IPV4_TYPE 0X0800
#define ZDATALINK_ARP_TYPE  0x0806
#define ZDATALINK_RARP_TYPE 0x8035
#define ZDATALINK_IPV6_TYPE 0X86dd

/***********************************************/

typedef struct _ZDataLinkT_ {
	u_int headLen;		//头部长度，单位Byte
}zDataLinkT;

typedef struct _ZLinkHeadT_ {
	u_char dhost[ZDATALINK_HEAD_ETHERADDR_LEN]; /* Destination host address */
	u_char shost[ZDATALINK_HEAD_ETHERADDR_LEN]; /* Source host address */
	u_short type; /* IP? ARP? RARP? etc */
}zLinkHeadT;

/****************************************************/
/********************* 接口函数  ********************/

zDataLinkT * zLink_Init();
void zLink_Free(zDataLinkT * paLink);

const u_char* zLink_UnpackHead(zDataLinkT * paLink , zLinkHeadT * paLinkHead, const u_char *packet);
int zLink_UnpackNextFloor(zDataLinkT * paLink , zLinkHeadT *paLinkHead, const u_char *packet);
void  zLink_PrintHead(zLinkHeadT *paLinkHead);


/******************** 	功能函数  *******************/
int zLink_Start(const u_char * packet);

#endif