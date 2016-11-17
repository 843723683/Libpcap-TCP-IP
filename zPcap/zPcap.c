#include "zPcap.h"
#include "../zDataLink/zDataLink.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


/*********************************************************/

static int zPcap_lookUpNet(zPcapT * paZPcap);
static void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet); 

/*********************************************************/


/*
*描述：获取pcap句柄
*参数：无
*返回值：NULL ：malloc失败；
*		 ！NULL：返回pcap句柄；
*/
zPcapT *zPcap_init(char *devname)
{
	zPcapT *pmyPcap = malloc(sizeof(zPcapT));
	if(pmyPcap == NULL)
	{
		return NULL;
	}
	memset(pmyPcap, 0, sizeof(zPcapT));

	memcpy(pmyPcap->devname, devname, strlen(devname));
	pmyPcap->devname[strlen(devname)] = '\0';

	if(zPcap_lookUpNet(pmyPcap) == -1)
	{
		zPcap_free(pmyPcap);
		return NULL;
	}

	return pmyPcap;
}

/*
*描述：释放pcap句柄
*参数：无
*返回值：-1 ：pcap句柄为空；
*		 0 ：释放成功；
*/
int zPcap_free(zPcapT * paZPcap)
{
	zPcapT *pmyPcap = paZPcap;
	if( pmyPcap == NULL)
	{
		return -1;
	}

	if(pmyPcap->handle)
	{
		pcap_close(pmyPcap->handle);
	}
	free(pmyPcap);

	return 0;
}

/*
*描述：获取设备的mask net.
*参数：pcap句柄
*返回值：-1:出错
*		 0 :成功 
*/
static int zPcap_lookUpNet(zPcapT * paZPcap)
{
	zPcapT *pmyPcap = paZPcap;
	if( pmyPcap == NULL)
	{
		return -1;
	}

	if(pcap_lookupnet(pmyPcap->devname, &(pmyPcap->net), &(pmyPcap->mask), pmyPcap->errbuf ) == -1)
	{
		return -1;
	}

	return 0;
}

/*
*描述：打开网卡设备，获取会话句柄
*参数：paZPcap:pcap句柄; 
		snaplen:数据包最大长度 
		promisc：true:混杂模式; 
		to_ms:超时时间（毫秒），如果设置为0意味着没有超时等待这一说法。
*返回值：-1:出错
*		 0 :成功 
*/
int zPcap_openDev(zPcapT * paZPcap, int snaplen, int promisc, int to_ms)
{
	zPcapT *pmyPcap = paZPcap;
	if( pmyPcap == NULL || pmyPcap->devname == NULL)
	{
		return -1;
	}

	if( (paZPcap->handle = pcap_open_live(paZPcap->devname, snaplen, promisc, to_ms, paZPcap->errbuf )) == NULL)
	{
		printf("%d----------%s\n",__LINE__, paZPcap->errbuf);
		return -1;
	}

	return 0;
}

/*
*描述：设置过滤条件。必须事先调用zPcap_init，zPcap_openDev
*参数：paZPcap:pcap句柄
*		filterstr:过滤条件
*		optimize：是否优化。0是假的，1是真实的
*返回值：-1:出错
*		 0 :成功 
*/
int zPcap_setFilter(zPcapT * paZPcap,char *filterstr, int optimize)
{
	zPcapT *pmyPcap = paZPcap;
	if( pmyPcap == NULL || pmyPcap->handle == NULL)
	{
		return -1;
	}

	struct bpf_program fp;
	if (pcap_compile(pmyPcap->handle, &fp, filterstr, optimize, pmyPcap->net) == -1) 
	{
		return -1;
	}

	if (pcap_setfilter(pmyPcap->handle, &fp) == -1)
	{
		return -1;
	}

	pcap_freecode(&fp);
	return 0;
}



/*
*描述：设置过滤条件。必须事先调用zPcap_init，zPcap_openDev
*参数：paZPcap:pcap句柄
		cnt:循环次数，-1：无限抓包
		callback：抓包后执行回调函数
		user：传给回调函数参数
*返回值：-1:出错
*		 0 :成功 
*/
int zPcap_loopGetPacket(zPcapT * paZPcap, int cnt)
{
	zPcapT *pmyPcap = paZPcap;
	if( pmyPcap == NULL || pmyPcap->handle == NULL)
	{
		return -1;
	}

	pcap_loop(pmyPcap->handle, cnt, getPacket, NULL);

	return 0;

}

/*
*描述：zPcap_loopGetPacket中的回调函数，调用
*参数：arg:pcap_loop最后一个参数
		pkthdr:包信息
		packet：数据包
*返回值：-1:出错
*		 0 :成功 
*/
static void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr,
			const u_char * packet)  
{
	if(packet == NULL)
	{
		return;
	}

	if(zLink_Start(packet) == -1)
	{
		printf("[%s:%d] : zLink_Start failed ~~~~~~~~~~~~~~\n",__func__,__LINE__);
	}

	return ;
}


/**************************************************************************/

/**************************************************************************/


/*
*描述：获取所有的网卡名，存入paZPcap的alldevs字段中。必须调用zPcap_freeAllDev释放
*参数：pcap句柄
*返回值：-1:出错
*		 0 :成功
*/
zPcapAllDevT *zPcap_findAllDev()
{
	zPcapAllDevT *pmydev = NULL;
	pmydev = malloc(sizeof(zPcapAllDevT));
	if(pmydev == NULL)
	{
		return NULL;
	}

	//返回网卡列表，alldevs指向表头
	if( pcap_findalldevs(&(pmydev->alldevs), NULL) == -1)
	{
		zPcap_freeAllDev(pmydev);
		return NULL;
	}

	return pmydev;
}

/*
*描述：释放所有的网卡名。
*参数：pcap句柄
*返回值：-1:出错
*		 0 :成功
*/
int zPcap_freeAllDev(zPcapAllDevT * paZDev)
{
	zPcapAllDevT *pmydev = paZDev;
	if( pmydev == NULL)
	{
		return -1;
	}
	if( pmydev->alldevs)
	{
		pcap_freealldevs(pmydev->alldevs);		
	}

	free(pmydev);
	
	return 0;
}

/*
*描述：打印所有网卡的名字
*参数：pcap句柄
*返回值：-1:出错
*		 0 :成功 
*/
int zPcap_printAllDev(zPcapAllDevT * paZDev)
{
	zPcapAllDevT *pmydev = paZDev;
	if( pmydev == NULL || pmydev->alldevs == NULL)
	{
		return -1;
	}

	pcap_if_t *tPcap = NULL;
	int i = 0;
	for(tPcap = pmydev->alldevs; tPcap != NULL; 
					tPcap = tPcap->next)
	{

		printf("%d.%s", ++i,tPcap->name);	
		if(tPcap->description)
		{
			printf("(%s).\n",tPcap->description);
		}	
		else
		{
			printf("(No description available).\n");
		}
	}

	return 0;
}





















