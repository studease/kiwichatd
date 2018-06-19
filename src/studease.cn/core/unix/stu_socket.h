/*
 * stu_socket.h
 *
 *  Created on: 2017骞�11鏈�15鏃�
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_UNIX_STU_SOCKET_H_
#define STUDEASE_CN_CORE_UNIX_STU_SOCKET_H_

#include "../../stu_config.h"

#define STU_WRITE_SHUTDOWN   SHUT_WR
#define STU_SOCKET_INVALID  -1

typedef int  stu_socket_t;

#define stu_socket           socket
#define stu_socket_n        "socket()"

#if (STU_HAVE_FIONBIO)

int stu_nonblocking(stu_socket_t s);
int stu_blocking(stu_socket_t s);

#define stu_nonblocking_n   "ioctl(FIONBIO)"
#define stu_blocking_n      "ioctl(!FIONBIO)"

#else

#define stu_nonblocking(s)   fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define stu_nonblocking_n   "fcntl(O_NONBLOCK)"

#define stu_blocking(s)      fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)
#define stu_blocking_n      "fcntl(!O_NONBLOCK)"

#endif

#define stu_socket_shutdown     shutdown
#define stu_socket_shutdown_n  "shutdown()"

#define stu_socket_close        close
#define stu_socket_close_n     "close() socket"

int stu_tcp_nopush(stu_socket_t s);
int stu_tcp_push(stu_socket_t s);

#if (STU_LINUX)

#define stu_tcp_nopush_n    "setsockopt(TCP_CORK)"
#define stu_tcp_push_n      "setsockopt(!TCP_CORK)"

#else

#define stu_tcp_nopush_n    "setsockopt(TCP_NOPUSH)"
#define stu_tcp_push_n      "setsockopt(!TCP_NOPUSH)"

#endif

#endif /* STUDEASE_CN_CORE_UNIX_STU_SOCKET_H_ */
