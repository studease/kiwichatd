/*
 * stu_os.h
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_WIN32_STU_OS_H_
#define STUDEASE_CN_CORE_WIN32_STU_OS_H_

#include "../../stu_config.h"
#include "../stu_core.h"

#ifndef __MINGW64_VERSION_MAJOR

/* Windows defines off_t as long, which is 32-bit */
typedef __int64   off_t;
#define _OFF_T_DEFINED

#endif

typedef struct {
    stu_recv_pt   recv;
    stu_recv_pt   udp_recv;
    stu_send_pt   send;
    stu_send_pt   udp_send;
    stu_uint32_t  flags;
} stu_os_io_t;

extern stu_os_io_t   stu_os_io;
extern stu_uint32_t  stu_ncpu;
extern stu_uint32_t  stu_win32_version;
extern char          stu_unique[];

stu_int32_t  stu_os_init();

ssize_t      stu_win32_send(stu_connection_t *c, u_char *buf, size_t size);
ssize_t      stu_win32_recv(stu_connection_t *c, u_char *buf, size_t size);

ssize_t      stu_wsasend(stu_connection_t *c, u_char *buf, size_t size);
ssize_t      stu_wsarecv(stu_connection_t *c, u_char *buf, size_t size);
ssize_t      stu_udp_wsarecv(stu_connection_t *c, u_char *buf, size_t size);

ssize_t      stu_overlapped_wsasend(stu_connection_t *c, u_char *buf, size_t size);
ssize_t      stu_overlapped_wsarecv(stu_connection_t *c, u_char *buf, size_t size);
ssize_t      stu_udp_overlapped_wsarecv(stu_connection_t *c, u_char *buf, size_t size);

#endif /* STUDEASE_CN_CORE_WIN32_STU_OS_H_ */
