#include <stdio.h>
#include "zPcap.h"

#define MY_DEVNAME "eno16777736"

#define MY_SNAPLEN 65535
#define MY_PROMISC 1
#define MY_DELAYTIME 1000

//#define MY_FILTER "tcp"
#define MY_FILTER " "
#define MY_OPTIMIZE 0

/************************************************************/


int main(void)
{
	zPcapT *pmyPcap = NULL;
	zPcapAllDevT *pmyDev = NULL;

	while(1)
	{
		if((pmyDev = zPcap_findAllDev()) == NULL)
		{
			printf("%d------zPcap_findAllDev falied--------\n",__LINE__);
		}

		// if(zPcap_printAllDev(pmyDev) == -1)
		// {
		// 	printf("%d------zPcap_findAllDev falied--------\n",__LINE__);
		// }
		zPcap_freeAllDev(pmyDev);


		if((pmyPcap = zPcap_init(MY_DEVNAME)) == NULL)
		{
			printf("%d------zPcap_init falied--------\n",__LINE__);
		}

		if(zPcap_openDev(pmyPcap, MY_SNAPLEN, MY_PROMISC, MY_DELAYTIME) == -1)
		{
			printf("%d------zPcap_openDev falied--------\n",__LINE__);	
		}

		if(zPcap_setFilter(pmyPcap, MY_FILTER, MY_OPTIMIZE) == -1)
		{
			printf("%d------zPcap_setFilter falied--------\n",__LINE__);	
		}

		zPcap_loopGetPacket(pmyPcap, -1);
		
		if( zPcap_free(pmyPcap) == -1)
		{
			printf("%d------zPcap_free falied--------\n",__LINE__);	
		}
	}
	return 0;
}