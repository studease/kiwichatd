/*
 * stu_os.h
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_UNIX_STU_OS_H_
#define STUDEASE_CN_CORE_UNIX_STU_OS_H_

#include "../../stu_config.h"
#include "../stu_core.h"

typedef struct {
    stu_recv_pt   recv;
    stu_recv_pt   udp_recv;
    stu_send_pt   send;
    stu_send_pt   udp_send;
    stu_uint32_t  flags;
} stu_os_io_t;

extern stu_os_io_t   stu_os_io;
extern stu_uint32_t  stu_ncpu;

stu_int32_t  stu_os_init();

ssize_t      stu_unix_recv(stu_connection_t *c, u_char *buf, size_t size);
ssize_t      stu_unix_send(stu_connection_t *c, u_char *buf, size_t size);

ssize_t      stu_udp_unix_recv(stu_connection_t *c, u_char *buf, size_t size);
ssize_t      stu_udp_unix_send(stu_connection_t *c, u_char *buf, size_t size);

#endif /* STUDEASE_CN_CORE_UNIX_STU_OS_H_ */
