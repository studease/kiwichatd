/*
 * stu_socket.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_SOCKET_H_
#define STUDEASE_CN_CORE_STU_SOCKET_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_SOCKET_INVALID -1

typedef int  stu_socket_t;

#define stu_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define stu_close_socket    close

#endif /* STUDEASE_CN_CORE_STU_SOCKET_H_ */
