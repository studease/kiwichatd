/*
 * stu_channel.c
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"


stu_int32_t
stu_channel_write(stu_socket_t s, stu_channel_t *ch, size_t size) {
	stu_int32_t    err;
	ssize_t        n;
	struct iovec   iov[1];
	struct msghdr  msg;
	union {
		struct cmsghdr  cm;
		char            space[CMSG_SPACE(sizeof(int))];
	} cmsg;

	if (ch->fd == -1) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	} else {
		msg.msg_control = (caddr_t) &cmsg;
		msg.msg_controllen = sizeof(cmsg);

		stu_memzero(&cmsg, sizeof(cmsg));

		cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
		cmsg.cm.cmsg_level = SOL_SOCKET;
		cmsg.cm.cmsg_type = SCM_RIGHTS;

		memcpy(CMSG_DATA(&cmsg.cm), &ch->fd, sizeof(int));
	}

	msg.msg_flags = 0;

	iov[0].iov_base = (char *) ch;
	iov[0].iov_len = size;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	n = sendmsg(s, &msg, 0);

	if (n == -1) {
		err = stu_errno;
		if (err == EAGAIN) {
			return STU_AGAIN;
		}

		stu_log_error(err, "sendmsg() failed");
		return STU_ERROR;
	}

	return STU_OK;
}

stu_int32_t
stu_channel_read(stu_socket_t s, stu_channel_t *ch, size_t size) {
	stu_int32_t    err;
	ssize_t        n;
	struct iovec   iov[1];
	struct msghdr  msg;
	union {
		struct cmsghdr  cm;
		char            space[CMSG_SPACE(sizeof(int))];
	} cmsg;

	iov[0].iov_base = (char *) ch;
	iov[0].iov_len = size;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	msg.msg_control = (caddr_t) &cmsg;
	msg.msg_controllen = sizeof(cmsg);

	n = recvmsg(s, &msg, 0);

	if (n == -1) {
		err = stu_errno;
		if (err == EAGAIN) {
			return STU_AGAIN;
		}

		stu_log_error(err, "recvmsg() failed.");
		return STU_ERROR;
	}

	if (n == 0) {
		stu_log_debug(0, "recvmsg() returned zero.");
		return STU_ERROR;
	}

	if ((size_t) n < sizeof(stu_channel_t)) {
		stu_log_error(0, "recvmsg() returned not enough data: %z.", n);
		return STU_ERROR;
	}

	if (ch->command == STU_CMD_OPEN_CHANNEL) {
		if (cmsg.cm.cmsg_len < (socklen_t) CMSG_LEN(sizeof(int))) {
			stu_log_error(0, "recvmsg() returned too small ancillary data.");
			return STU_ERROR;
		}

		if (cmsg.cm.cmsg_level != SOL_SOCKET || cmsg.cm.cmsg_type != SCM_RIGHTS) {
			stu_log_error(0, "recvmsg() returned invalid ancillary data level %d or type %d.", cmsg.cm.cmsg_level, cmsg.cm.cmsg_type);
			return STU_ERROR;
		}

		memcpy(&ch->fd, CMSG_DATA(&cmsg.cm), sizeof(int));
	}

	if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
		stu_log_error(0, "recvmsg() truncated data.");
	}

	return n;
}

stu_int32_t
stu_channel_add_event(stu_fd_t epfd, stu_fd_t fd, uint32_t event, stu_event_handler_pt handler) {
	stu_connection_t *c;
	stu_event_t      *ev;

	c = stu_connection_get(fd);
	if (c == NULL) {
		return STU_ERROR;
	}

	ev = event == STU_READ_EVENT ? &c->read : &c->write;
	if (ev == NULL) {
		stu_log_error(0, "Failed to add channel event: fd=%d, ev=%d.", fd, event);
		return STU_ERROR;
	}

	ev->epfd = epfd;
	ev->handler = handler;

	if (stu_event_add(ev, event, STU_CLEAR_EVENT) == STU_ERROR) {
		stu_connection_close(c);
		return STU_ERROR;
	}

	return STU_OK;
}

void
stu_channel_close(stu_fd_t *fd) {
	if (close(fd[0]) == -1) {
		stu_log_error(stu_errno, "close() channel failed");
	}

	if (close(fd[1]) == -1) {
		stu_log_error(stu_errno, "close() channel failed");
	}
}
