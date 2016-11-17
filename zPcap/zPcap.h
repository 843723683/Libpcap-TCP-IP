#ifndef _Z_PCAP_H_H_
#define _Z_PCAP_H_H_
#include <pcap.h>

/***********************************************/


/***********************************************/
#define MY_PCAP_ERRBUF_SIZE 1024
#define MY_DEV_NAME 125

typedef struct _zPcap_T_{
	char devname[MY_DEV_NAME];
	pcap_t *handle;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	char errbuf[MY_PCAP_ERRBUF_SIZE];//错误提示
}zPcapT;

typedef struct _ZPcapAllDev_T_{
	pcap_if_t *alldevs; //所有网卡设备

}zPcapAllDevT;

/****************************************************/
/********************* 接口函数  ********************/

zPcapT *zPcap_init(char *devname);
int zPcap_free(zPcapT * paZPcap);
int zPcap_openDev(zPcapT * paZPcap, int snaplen, int promisc, int to_ms);
int zPcap_setFilter(zPcapT * paZPcap,char *filterstr, int optimize);
int zPcap_loopGetPacket(zPcapT * paZPcap, int cnt);

zPcapAllDevT *zPcap_findAllDev();
int zPcap_freeAllDev(zPcapAllDevT * paZDev);
int zPcap_printAllDev(zPcapAllDevT * paZDev);

/******************** 	功能函数  *******************/


#endif