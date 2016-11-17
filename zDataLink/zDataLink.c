#include "zDataLink.h"
#include "../zTool/zTool.h"
#include "../zNetwork/zIP.h"
#include <stdlib.h>
#include <string.h>

/****************************************************/
/********************* 接口函数  ********************/
/****************************************************/


/*
*描述：获取DataLink句柄
*参数：无
*返回值：NULL ：malloc失败；
*		 ！NULL：返回pcap句柄；
*/
zDataLinkT * zLink_Init()
{
	zDataLinkT * pmyLink = NULL;
	pmyLink = malloc(sizeof(zDataLinkT));
	if(pmyLink == NULL)
	{
		return NULL;
	}
	memset(pmyLink, 0, sizeof(zDataLinkT));

	pmyLink->headLen = 12;

	return pmyLink;
}

/*
*描述：释放DataLink句柄
*参数：paLink：DataLink句柄
*返回值：无
*/
void zLink_Free(zDataLinkT * paLink)
{
	zDataLinkT * pmyLink = paLink;
	if(pmyLink == NULL)
	{
		return ;
	}

	free(pmyLink);
	return ;
}

/*
*描述：解析DataLink头，因为zTool_GetSpecifySize不检查是否越界，
		所以对数据包完整性要求高。不然容易出现段错误。
*参数：
	paLink：DataLink句柄
	paLinkHead: 存放解析出来的头信息
	packet：源数据包
*返回值：解析DataLink头后，后面剩余的数据包的头地址
*/
const u_char* zLink_UnpackHead(zDataLinkT * paLink , zLinkHeadT * paLinkHead, const u_char* packet)
{
	if(paLink == NULL || paLinkHead == NULL || packet == NULL)
	{
		return NULL;
	}
//	zDataLinkT * pmyLink = paLink;
	zLinkHeadT * pmyHead = paLinkHead;
	const u_char * pmyPack = packet;
	char * ret = NULL;

	int i = 0;
	for(i = 0; i < ZDATALINK_HEAD_ETHERADDR_LEN; ++i)
	{
		ret = zTool_GetSpecifySize(&pmyPack, ZDATALINK_HEAD_HOST_SIZE);
		if(ret)
		{
			memcpy( &(pmyHead->dhost[i]), ret, ZDATALINK_HEAD_HOST_SIZE);
			free(ret);
			ret = NULL;
		}
		else
		{
			return NULL;
		}
	}

	for(i = 0; i < ZDATALINK_HEAD_ETHERADDR_LEN; ++i)
	{
		ret = zTool_GetSpecifySize(&pmyPack, ZDATALINK_HEAD_HOST_SIZE);
		if(ret)
		{
			memcpy( &(pmyHead->shost[i]), ret, ZDATALINK_HEAD_HOST_SIZE);
			free(ret);
			ret = NULL;
		}
		else
		{
			return NULL;
		}
	}

	if(zTool_PclFillField(&pmyPack, &(pmyHead->type), ZDATALINK_HEAD_TYPE) == -1)
	{
		return NULL;
	}

	return pmyPack;
}

/*
*描述：根据zLinkHeadT中type信息，调用不同的网络层解包函数。
*参数：
*	paLink:DataLink句柄
*	paLinkHead: 存放解析出来的头信息
*	packet: 网络层及以上的数据包（包含网络层）
*返回值：
*		-1:失败
*		0：成功
*/
int zLink_UnpackNextFloor(zDataLinkT * paLink , zLinkHeadT *paLinkHead, const u_char *packet)
{
	int ret = 0;
	if(paLink == NULL || packet == NULL || paLinkHead == NULL)
	{
		ret = -1;
		return ret;
	}
	// zDataLinkT * pmyLink;
	zLinkHeadT *pmyHead = paLinkHead;
	const u_char *pmyPack = packet;

	switch(pmyHead->type)
	{
		case ZDATALINK_IPV4_TYPE:
		{
			printf("[%s:%d] : 网络层IPV4协议 type =  %04x\n",__func__,__LINE__, pmyHead->type);
			if(zIP_Start(pmyPack) == -1)
			{
				printf("[%s:%d] :zIP_Start Unpack failed\n",__func__,__LINE__);
			}
		}
		break;
		case ZDATALINK_ARP_TYPE:
		{
			printf("[%s:%d] : 网络层ARP协议 type =  %04x\n",__func__,__LINE__, pmyHead->type);
		}
		break;
		case ZDATALINK_RARP_TYPE:
		{
			printf("[%s:%d] : 网络层RARP协议 type =  %04x\n",__func__,__LINE__, pmyHead->type);
		}
		break;
		case ZDATALINK_IPV6_TYPE:
		{
			printf("[%s:%d] : 网络层IPV6协议 type =  %04x\n",__func__,__LINE__, pmyHead->type);
		}
		break;
		default:
		{
			ret = -1;
			printf("[%s:%d] : 网络层没有这个类型的协议 type =  %04x~~~~~~~~~~~~~~\n",__func__,__LINE__, pmyHead->type);
		}
	}
	return ret ;

}


/*
*描述：打印DataLink头的信息，要先调用zLink_UnpackHead。
*参数：
	paLinkHead: 存放解析出来的头信息
*返回值：无
*/
void zLink_PrintHead(zLinkHeadT *paLinkHead)
{
	if(paLinkHead == NULL)
	{
		return;
	}
	zLinkHeadT *myHead = paLinkHead;

	printf("dhost:%02x:%02x:%02x:%02x:%02x:%02x\n", myHead->dhost[0]
		, myHead->dhost[1], myHead->dhost[2], myHead->dhost[3]
		, myHead->dhost[4], myHead->dhost[5]);
	printf("shost:%02x:%02x:%02x:%02x:%02x:%02x\n", myHead->shost[0]
		, myHead->shost[1], myHead->shost[2], myHead->shost[3]
		, myHead->shost[4], myHead->shost[5]);
	printf("type :%04x\n",myHead->type);

}

/****************************************************/
/******************** 	功能函数  *******************/
/****************************************************/

/*
*描述：实现解析DataLink信息，并且调用网络层函数继续解析。
*参数：
*	packet: 源数据包
*返回值：
*	-1:失败
*	 0:成功
*/
int zLink_Start(const u_char * packet)
{
	int ret = -1;
	if(packet == NULL)
	{
		return ret;
	}

	zDataLinkT * pmyLink;
	zLinkHeadT   myHead;
	const u_char * newPack; //接受去除DataLink层之后的数据包
	memset(&myHead, 0, sizeof(zLinkHeadT));

	if( (pmyLink = zLink_Init()) != NULL)
	{
		if( (newPack = zLink_UnpackHead(pmyLink, &myHead, packet)) != NULL)
		{
			// zLink_PrintHead(&myHead);
			if(zLink_UnpackNextFloor(pmyLink , &myHead, newPack) == 0)
			{
				ret = 0;
			}
		}
		zLink_Free(pmyLink);
	}

	return ret;
}
