/*
 * stu_socket.c
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#include "../../stu_config.h"
#include "../stu_core.h"


int
stu_nonblocking(stu_socket_t s) {
	unsigned long  nb = 1;

	return ioctlsocket(s, FIONBIO, &nb);
}

int
stu_blocking(stu_socket_t s) {
	unsigned long  nb = 0;

	return ioctlsocket(s, FIONBIO, &nb);
}

int
stu_tcp_push(stu_socket_t s) {
	return 0;
}
