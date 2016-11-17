#include "zIP.h"
#include "../zTool/zTool.h"
#include "../zTransport/zTCP.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
*描述：获取zIPHead句柄
*参数：无
*返回值：NULL ：malloc失败；
*		 ！NULL：返回pcap句柄；
*/
zIPHead * zIP_init()
{
	zIPHead * pmyHead = NULL;
	pmyHead = malloc(sizeof(zIPHead));
	if(pmyHead == NULL)
	{
		return NULL;
	}
	memset(pmyHead, 0 , sizeof(zIPHead));

	return pmyHead;

}

/*
*描述：释放zIPHead句柄
*参数：paLink：DataLink句柄
*返回值：无
*/
void zIP_free(zIPHead *paHead)
{
	if(paHead)
	{
		if(paHead->option)
		{
			free(paHead->option);
		}
		free(paHead);
	}

}

/*
*描述：解析IP头，因为用zTool_PclFillField对容易出现段错误。
*参数：
*	zIPHead：存放解析出来的头信息
*	packet：源数据包
*返回值：
*		NULL：失败
*		！NULL：解析IP头后，后面剩余的数据包的头地址
*/
const u_char* zIP_UnpackHead(zIPHead * paHead, const u_char *packet)
{
	if(paHead == NULL || packet == NULL)
	{
		return NULL;
	}
	zIPHead *pmyHead = paHead;
	const u_char* pmyPack = packet;

	/* version << 4 | header length >> 2 */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->ip_vhl), ZIP_HEAD_VHL) == -1)
	{
		return NULL;
	}
	/* type of service */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->ip_tos), ZIP_HEAD_TOS) == -1)
	{
		return NULL; 
	}
	/* total length */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->ip_len), ZIP_HEAD_LEN) == -1)
	{
		return NULL;
	}
	/* identification */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->ip_id), ZIP_HEAD_ID) == -1)
	{
		return NULL;
	}
	/* fragment offset field  */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->ip_off), ZIP_HEAD_OFF) == -1)
	{
		return NULL;
	}
	/* time to live */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->ip_ttl), ZIP_HEAD_TTL) == -1)
	{
		return NULL;
	}
	/* protocol */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->ip_p), ZIP_HEAD_P) == -1)
	{
		return NULL;
	}
	/* checksum */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->ip_sum), ZIP_HEAD_SUM) == -1)
	{
		return NULL;
	}

	/* source address 小段存储*/
	char* ret = NULL;
	if( (ret = zTool_GetSpecifySize(&pmyPack, ZIP_HEAD_SIP)) == NULL)
	{
		return NULL;
	}
	memcpy( &(pmyHead->ip_src.s_addr), ret, ZIP_HEAD_SIP);
	free(ret);
	ret = NULL;

	/* dest address 小段存储*/
	if( (ret = zTool_GetSpecifySize(&pmyPack, ZIP_HEAD_DIP)) == NULL)
	{
		return NULL;
	}
	memcpy( &(pmyHead->ip_dst.s_addr), ret, ZIP_HEAD_DIP);
	free(ret);
	ret = NULL;

	uint headLen = ZIP_GETLEN(pmyHead) * ZIP_LEN_4;
	if(headLen > ZIP_FIXED_IPHEAD)
	{
		//有选项字段
		pmyHead->option = malloc( headLen - ZIP_FIXED_IPHEAD );
		if(pmyHead->option == NULL)
		{
			return NULL;
		}
		if(zTool_PclFillField( &pmyPack, pmyHead->option, headLen - ZIP_FIXED_IPHEAD) == -1)
		{
			return NULL;
		}
		printf("[%s:%d] : 选项字段 head = %d\n",__func__,__LINE__, headLen);	
	}
	else if(headLen == ZIP_FIXED_IPHEAD)
	{
		//没有选项字段
		pmyHead->option = NULL;
	}
	else
	{
		return NULL;
	}

	return pmyPack;
}

/*
*描述：根据zLinkHeadT中type信息，调用不同的网络层解包函数。
*参数：
*	paIPHead:IP头指针，头的信息
*	packet: 传输层及以上的数据包（包含传输层）
*返回值：
*		-1:失败
*		0：成功
*/
int zIP_UnpackNextFloor(zIPHead *paIPHead, const u_char *packet)
{
	int ret = 0;
	if(paIPHead == NULL || packet == NULL)
	{
		ret = -1;
		return ret;
	}
	zIPHead *pmyHead = paIPHead;
	const u_char* pmyPack = packet;

	switch(paIPHead->ip_p)
	{
		case ZIP_ICMP_TYPE:
		{
			printf("[%s:%d] : 传输层ICMP协议 type =  %02d\n",__func__,__LINE__, pmyHead->ip_p);	
		}
		break;
		case ZIP_IGMP_TYPE:
		{
			printf("[%s:%d] : 传输层IGMP协议 type =  %02d\n",__func__,__LINE__, pmyHead->ip_p);	
		}
		break;
		case ZIP_TCP_TYPE:
		{
			printf("[%s:%d] : 传输层TCP协议 type =  %02d\n",__func__,__LINE__, pmyHead->ip_p);	
			if(zTCP_Start(pmyPack) == -1)
			{
				printf("[%s:%d] :zTCP_Start Unpack failed\n",__func__,__LINE__);
			}
		}
		break;
		case ZIP_UDP_TYPE:
		{
			printf("[%s:%d] : 传输层UDP协议 type =  %02d\n",__func__,__LINE__, pmyHead->ip_p);	
		}
		break;
		default:
		{
			ret = -1;
			printf("[%s:%d] : 传输层没有这个类型的协议 type =  %02d!!!!!!!!!!\n",__func__,__LINE__, pmyHead->ip_p);
		}
	}

	return ret;
}

/*
*描述：打印IP头的信息，要先调用zLink_UnpackHead。
*参数：
*	paIPHead：存放解析出来的头信息
*返回值：无
*/
void  zIP_PrintHead(zIPHead *paIPHead)
{
	if(paIPHead == NULL)
	{
		return ;
	}
	zIPHead *pmyHead = paIPHead;

	printf("version + len: %02x\n", pmyHead->ip_vhl);
	printf("TOS: %02x\n", pmyHead->ip_tos);
	printf("len: %04x\n", pmyHead->ip_len);
	printf("id : %04x\n", pmyHead->ip_id);
	printf("off: %04x\n", pmyHead->ip_off);
	printf("TTL: %02x\n", pmyHead->ip_ttl);
	printf("PCL: %02x\n", pmyHead->ip_p);
	printf("Check: %04x\n", pmyHead->ip_sum);
	printf("sip: %s\n ",inet_ntoa(pmyHead->ip_src));
	printf("dip: %s\n ",inet_ntoa(pmyHead->ip_dst));

	return;
}



/******************** 	功能函数  *******************/

/*
*描述：实现解析IP层信息，并且调用传输层函数继续解析。
*参数：
*	packet: 源数据包
*返回值：
*	-1:失败
*	 0:成功
*/
int zIP_Start(const u_char * packet)
{
	int ret = -1;
	if(packet == NULL)
	{
		return 	ret;	
	}
	zIPHead *pmyHead = NULL;
	const u_char* newPack = NULL;

	if( (pmyHead = zIP_init()) != NULL)
	{
		if( (newPack = zIP_UnpackHead(pmyHead, packet)) != NULL)
		{	
			// zIP_PrintHead(pmyHead);
			if(zIP_UnpackNextFloor(pmyHead, newPack) == 0)
			{
				ret = 0;
			}
		}
		zIP_free(pmyHead);
	}

	return ret;
}