/*
 * stu_event_epoll.h
 *
 *  Created on: 2017年11月16日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_EVENT_STU_EVENT_EPOLL_H_
#define STUDEASE_CN_EVENT_STU_EVENT_EPOLL_H_

#include "../stu_config.h"
#include "../core/stu_core.h"

#define STU_EPOLL_SIZE   4096
#define STU_EPOLL_EVENTS 8


stu_int32_t  stu_event_epoll_create();

stu_int32_t  stu_event_epoll_add(stu_event_t *ev, uint32_t event, stu_uint32_t flags);
stu_int32_t  stu_event_epoll_del(stu_event_t *ev, uint32_t event, stu_uint32_t flags);

stu_int32_t  stu_event_epoll_process_events(stu_fd_t epfd, stu_msec_t timer, stu_uint32_t flags);

#endif /* STUDEASE_CN_EVENT_STU_EVENT_EPOLL_H_ */
