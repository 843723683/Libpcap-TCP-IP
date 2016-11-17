#include "zTool.h"
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

/***************************************************************/
#define Z_MAX_HEAD_FILED 125	//最大头字段125Byte



/***************************************************************/


/*
*描述：返回获取(malloc)字符串从paSoucre 开始len个字节。
*		并且paSource会向后移动len个字节。返回值使用之后需要free。
*		不检查是否会越界，容易出现段错误。
*参数：paSource：数据源
*		len：获取字节数
*返回值：NULL ：失败；
*		 ！NULL：从paSoucre开始len个字节的字符串；
*用法：
*	必须确保paSource + len是可访问的，不然出现段错误
*/
void * zTool_GetSpecifySize( const unsigned char **paSource, int len)
{
	if(paSource == NULL || *paSource == NULL)
	{
		return NULL;
	}
	const unsigned char **pmySrc = paSource;

	char *ret = NULL;
	ret = malloc( len );
	if(ret == NULL)
	{
		return NULL;
	}
	memset(ret, 0, len);
	
	memcpy(ret, *pmySrc, len);
	*pmySrc += len;

	return ret;
}

/*
*描述：获取paSource包前len个字节，转化为小段存储，并且存入paFiled中。
*		不检查paSource + len，后是否越界，所以容易出段错误
*参数：paSource：数据源
*		paFiled：需填充字段首地址
*		len：获取字节数
*返回值：-1：失败；
*		 0：成功
*用法：
*	1.必须确保paSource + len是可访问的，不然出现段错误
*	2.必须确保paFiled + len 是可访问的，不然出现段错误
*/
int zTool_PclFillField(const unsigned char **paSource, void *paFiled, int len)
{
	if(paSource == NULL || *paSource == NULL || paFiled == NULL || len == 0)
	{
		return -1;
	}
	const unsigned char **pmySrc = paSource;
	void * myFiled = paFiled;
	int myLen = len;

	char *ret = NULL;
	char newRet[Z_MAX_HEAD_FILED] = {0};
	ret = zTool_GetSpecifySize(pmySrc, myLen);
	if(ret == NULL)
	{
		return -1;
	}

	if( zTool_BToS(ret, newRet, myLen) == -1)
	{
		free(ret);
		ret = NULL;
		return -1;
	}
	free(ret);
	ret = NULL;

	memcpy(myFiled, newRet, myLen);

	return 0;
}

/*
*描述：获取paSource包前len个字节，转化为小段存储，并且存入paFiled中。
*参数：paSrc：大段
*		paDes：小段（最大转化为Z_MAX_HEAD_FILED）
*返回值：-1：失败；
*		 0：成功
*用法：
	1.必须确保paSrc + len是可访问的，不然出现段错误
	2.必须确保len = paDes的实际内存大小（例：paDes为int，则len = 4）
*/
#define ZTOOL_FILEDOFFSET 1 //移动字节偏移量

int zTool_BToS(char *paSrc, char *paDes, int len)
{
	if(paSrc == NULL || paDes == NULL || len == 0)
	{
		return -1;
	}
	char *pmySrc = paSrc;
	char *pmyDes = paDes;
	int myLen = len;
	if(myLen > Z_MAX_HEAD_FILED)
	{
		return -1;
	}

	int i = 0;
	for(i = myLen; i > 0; --i)
	{
		memcpy(pmyDes + myLen - i, pmySrc + i - 1, ZTOOL_FILEDOFFSET);
	}

	return 0;
}


ushort zTool_EasyCheckSum(ushort paChecksum, ushort paSrc )
{
	ushort ret = 0;
	ret += paChecksum;
	ret += (~paSrc);

	return ret;
}
