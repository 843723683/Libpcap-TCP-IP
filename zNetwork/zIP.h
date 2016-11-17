#ifndef _Z_IP_H_H_
#define _Z_IP_H_H_

#include <sys/types.h>
#include <arpa/inet.h>//struct in_addr头文件

/***********************************************/

#define ZIP_GETLEN(ip)		(((ip)->ip_vhl) & 0x0f)
#define ZIP_GETV(ip)		(((ip)->ip_vhl) >> 4)

#define ZIP_FIXED_IPHEAD 20		//固定IP头的长度20Byte
#define ZIP_LEN_4		 4		//首部长度字段一位代表4个Byte

//网络层IP头，各个变量的大小（size）
#define ZIP_HEAD_VHL 1
#define ZIP_HEAD_TOS 1
#define ZIP_HEAD_LEN 2
#define ZIP_HEAD_ID  2
#define ZIP_HEAD_OFF 2
#define ZIP_HEAD_TTL 1
#define ZIP_HEAD_P   1
#define ZIP_HEAD_SUM 2
#define ZIP_HEAD_SIP 4
#define ZIP_HEAD_DIP 4


//传输层类型
#define ZIP_ICMP_TYPE 01
#define ZIP_IGMP_TYPE 02
#define ZIP_TCP_TYPE  06
#define ZIP_UDP_TYPE  17

/***********************************************/

/* IP header */
typedef struct _ZIPHead_ {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field  */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
	void *option;
}zIPHead;

/****************************************************/
/********************* 接口函数  ********************/

zIPHead * zIP_init();
void zIP_free(zIPHead *paHead);

const u_char* zIP_UnpackHead(zIPHead * paIPHead, const u_char *packet);
int zIP_UnpackNextFloor(zIPHead *paIPHead, const u_char *packet);
void  zIP_PrintHead(zIPHead* paIPHead);

/******************** 	功能函数  *******************/
int zIP_Start(const u_char * packet);


#endif