/*
 * stu_channel.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_CHANNEL_H_
#define STUDEASE_CN_CORE_STU_CHANNEL_H_

#include "../stu_config.h"
#include "stu_core.h"

typedef struct {
	stu_uint32_t  command;
	stu_pid_t     pid;
	stu_fd_t      fd;
	stu_int32_t   slot;
} stu_channel_t;

stu_int32_t  stu_channel_write(stu_socket_t s, stu_channel_t *ch, size_t size);
stu_int32_t  stu_channel_read(stu_socket_t s, stu_channel_t *ch, size_t size);
stu_int32_t  stu_channel_add_event(stu_fd_t epfd, stu_fd_t fd, uint32_t event, stu_event_handler_pt handler);
void         stu_channel_close(stu_fd_t *fd);

#endif /* STUDEASE_CN_CORE_STU_CHANNEL_H_ */
