#include <stdio.h>
#include <stdlib.h>
#include "zTool.h"

#ifdef TEST

#define TEST_SIZE 2
int main(void)
{
	char * t = "12345678901324567890";
	const unsigned char * temp = t;
	const unsigned char * temp1 = temp;
	char temp2[125] = {0};
	const unsigned char * ret = NULL;
	int i = 0;

	printf("%d\n",*((char *)temp));
	printf("%d\n",*((char *)temp + 1));

/*	int a = 0x1234;
	printf("%x\n",*((char *)(&a)));
	printf("%x\n",*((char *)(&a) + 1));
*/

	while(1)
	{
/*		ret = zTool_GetSpecifySize(&temp, 4);
		printf("ret = %s\n", ret);
		free((void *)ret);

		ret = zTool_GetSpecifySize(&temp, 4);
		printf("ret = %s\n", ret);
		free((void *)ret);*/

		temp1 = temp;
		if( zTool_PclFillField(&temp1, temp2, TEST_SIZE) == -1)
		{
			printf("%d-------------zTool_PclFillField falied !!!!!!!!!!!\n",__LINE__);
			//break;
		}
		for(i = 0; i < TEST_SIZE; ++i)
		{
			printf("1--%c\n",temp2[i]);
		}
		printf("\n");
	}
	return 0;
}

#endif