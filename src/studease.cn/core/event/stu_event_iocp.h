/*
 * stu_event_iocp.h
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_EVENT_STU_EVENT_IOCP_H_
#define STUDEASE_CN_CORE_EVENT_STU_EVENT_IOCP_H_

#include "stu_event.h"

stu_fd_t     stu_event_iocp_create();

stu_int32_t  stu_event_iocp_add(stu_event_t *ev, uint32_t event, stu_uint32_t flags);
stu_int32_t  stu_event_iocp_del(stu_event_t *ev, uint32_t event, stu_uint32_t flags);
stu_int32_t  stu_event_iocp_add_connection(stu_connection_t *c);
stu_int32_t  stu_event_iocp_del_connection(stu_connection_t *c, stu_uint32_t flags);

stu_int32_t  stu_event_iocp_process_events(stu_fd_t evfd, stu_msec_t timer, stu_uint32_t flags);

#endif /* STUDEASE_CN_CORE_EVENT_STU_EVENT_IOCP_H_ */
