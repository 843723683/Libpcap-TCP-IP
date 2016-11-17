#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zTCP.h"
#include "../zTool/zTool.h"


/*
*描述：获取zTCPHead句柄
*参数：无
*返回值：NULL ：malloc失败；
*		 ！NULL：返回pcap句柄；
*/
zTCPHead * zTCP_init()
{
	zTCPHead * pmyHead = NULL;
	pmyHead = malloc(sizeof(zTCPHead));
	if(pmyHead == NULL)
	{
		return NULL;
	}
	memset(pmyHead, 0 , sizeof(zTCPHead));

	return pmyHead;
}

/*
*描述：释放zTCPHead句柄
*参数：paHead：zTCPHead句柄
*返回值：无
*/
void zTCP_free(zTCPHead *paHead)
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
*描述：解析TCP头，因为用zTool_PclFillField对容易出现段错误。
*参数：
*	zTCPHead：存放解析出来的头信息
*	packet：源数据包
*返回值：
*		NULL：失败
*		！NULL：解析TCP头后，后面剩余的数据包的头地址
*/
const u_char* zTCP_UnpackHead(zTCPHead * paHead, const u_char *packet)
{
	if(paHead == NULL || packet == NULL)
	{
		return NULL;
	}
	zTCPHead *pmyHead = paHead;
	const u_char* pmyPack = packet;

	/* source port */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->th_sport), ZTCP_HEAD_SPORT) == -1)
	{
		return NULL;
	}

	/* destination port */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->th_dport), ZTCP_HEAD_DPORT) == -1)
	{
		return NULL;
	}

	/* sequence number */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->th_seq), ZTCP_HEAD_SEQ) == -1)
	{
		return NULL;
	}

	/* acknowledgement number */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->th_ack), ZTCP_HEAD_ACK) == -1)
	{
		return NULL;
	}

	/* data offset, rsvd */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->th_offx2), ZTCP_HEAD_OFFX2) == -1)
	{
		return NULL;
	}

	if(zTool_PclFillField(&pmyPack, &(pmyHead->th_flags), ZTCP_HEAD_FLAGS) == -1)
	{
		return NULL;
	}

	/* window */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->th_win), ZTCP_HEAD_WIN) == -1)
	{
		return NULL;
	}

	/* checksum */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->th_sum), ZTCP_HEAD_SUM) == -1)
	{
		return NULL;
	}

	/* urgent pointer */
	if(zTool_PclFillField(&pmyPack, &(pmyHead->th_urp), ZTCP_HEAD_URP) == -1)
	{
		return NULL;
	}

	uint headLen = ZTCP_GETLEN(pmyHead) * ZTCP_LEN_4;
	if(headLen > ZTCP_FIXED_TCPHEAD)
	{
		//有选项字段
		pmyHead->option = malloc( headLen - ZTCP_FIXED_TCPHEAD );
		if(pmyHead->option == NULL)
		{
			return NULL;
		}
		if(zTool_PclFillField( &pmyPack, pmyHead->option, headLen - ZTCP_FIXED_TCPHEAD) == -1)
		{
			return NULL;
		}
		printf("[%s:%d] : (tcp)选项字段 head = %d\n",__func__,__LINE__, headLen);	
	}
	else if(headLen == ZTCP_FIXED_TCPHEAD)
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
int zTCP_UnpackNextFloor(zTCPHead *paTCPHead, const u_char *packet)
{

	return 0;
}
/*
*描述：打印TCP头的信息，要先调用zLink_UnpackHead。
*参数：
*	paTCPHead：存放解析出来的头信息
*返回值：无
*/
void  zTCP_PrintHead(zTCPHead* paTCPHead)
{
	if(paTCPHead == NULL)
	{
		return ;
	}
	zTCPHead *pmyHead = paTCPHead;

	printf("sport: %04d\n", pmyHead->th_sport);
	printf("dport: %04d\n", pmyHead->th_dport);
	printf("seq  : %08x\n", pmyHead->th_seq);
	printf("ack  : %08x\n", pmyHead->th_ack);
	printf("offx2: %02x\n", pmyHead->th_offx2);
	printf("flags: %02x\n", pmyHead->th_flags);
	printf("win  : %04x\n", pmyHead->th_win);
	printf("Check: %04x\n", pmyHead->th_sum);
	printf("urp  : %04x\n", pmyHead->th_urp);

}



/******************** 	功能函数  *******************/
/*
*描述：实现解析tcp层信息，并且调用应用层函数继续解析。
*参数：
*	packet: 源数据包（包含传输层）
*返回值：
*	-1:失败
*	 0:成功
*/
int zTCP_Start(const u_char * packet)
{
	int ret = -1;
	if(packet == NULL)
	{
		return 	ret;	
	}
	zTCPHead *pmyHead = NULL;
	const u_char* newPack = NULL;

	if( (pmyHead = zTCP_init()) != NULL)
	{
		if( (newPack = zTCP_UnpackHead(pmyHead, packet)) != NULL)
		{	
		//	zTCP_PrintHead(pmyHead);
			if(zTCP_UnpackNextFloor(pmyHead, newPack) == 0)
			{
				ret = 0;
			}
		}
		zTCP_free(pmyHead);
	}

	return ret;
}
