#ifndef _Z_TOOL_H_H_
#define _Z_TOOL_H_H_

void * zTool_GetSpecifySize(const unsigned char **paSource, int len);
int zTool_PclFillField(const unsigned char **paSource, void *paFiled, int len);
int zTool_BToS(char *src, char *des, int len);

ushort zTool_CheckSum(ushort paChecksum, ushort paSrc );

#endif