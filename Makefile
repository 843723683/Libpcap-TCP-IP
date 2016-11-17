TARGET = lz
CC     = gcc
LFLAGS = -lpcap
CFLAGS = -g -Wall ${INC_DIR}

CUR_DIR        = $(shell pwd)
ZPCAP_DIR      = ${CUR_DIR}/zPcap
ZDATALINK_DIR  = ${CUR_DIR}/zDataLink
ZNETWORK_DIR   = ${CUR_DIR}/zNetwork
ZTRANSPORT_DIR = ${CUR_DIR}/zTransport
ZTOOL_DIR      = ${CUR_DIR}/zTool

INC_DIR = -I ${ZPCAP_DIR} \
          -I ${ZDATALINK_DIR} \
          -I ${ZNETWORK_DIR} \
          -I ${ZTRANSPORT_DIR} \
          -I ${ZTOOL_DIR} \

SRC = $(CUR_DIR)/main.o \
	  ${wildcard  ${ZPCAP_DIR}/*.c} \
      ${wildcard  ${ZDATALINK_DIR}/*.c} \
      ${wildcard  ${ZNETWORK_DIR}/*.c} \
      ${wildcard  ${ZTRANSPORT_DIR}/*.c} \
      ${wildcard  ${ZTOOL_DIR}/*.c} \

OBJ = ${patsubst %.c, %.o, ${SRC}}



${TARGET}:${OBJ}
	$(CC) $(LFLAGS) ${OBJ} -o $@
	@echo "Compile done."

$(OBJ):%.o:%.c
	@echo "Compiling $< ==> $@"
	${CC} ${CFLAGS} -c $< -o $@

clean:
	rm -f ${OBJ}
	rm -f *.o
	rm -f *~
	rm -f ${TARGET}
	@echo "Clean done."