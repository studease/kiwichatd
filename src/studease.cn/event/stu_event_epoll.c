/*
 * stu_event_epoll.c
 *
 *  Created on: 2017年11月16日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "../core/stu_core.h"


stu_fd_t
stu_event_epoll_create() {
	stu_fd_t  fd;

	fd = epoll_create(STU_EPOLL_SIZE);
	if (fd == -1) {
		stu_log_error(stu_errno, "Failed to create epoll instance.");
	}

	return fd;
}

stu_int32_t
stu_event_epoll_add(stu_event_t *ev, uint32_t event, stu_uint32_t flags) {
	stu_connection_t   *c;
	stu_event_t        *e;
	uint32_t            events, prev;
	int                 op;
	struct epoll_event  ee;

	c = (stu_connection_t *) ev->data;

	events = event;

	if (event == STU_READ_EVENT) {
		e = &c->write;
		prev = EPOLLOUT;
#if (STU_READ_EVENT != EPOLLIN|EPOLLRDHUP)
		events = EPOLLIN|EPOLLRDHUP;
#endif
	} else {
		e = &c->read;
		prev = EPOLLIN|EPOLLRDHUP;
#if (STU_WRITE_EVENT != EPOLLOUT)
		events = EPOLLOUT;
#endif
	}

	if (e->active) {
		op = EPOLL_CTL_MOD;
		events |= prev;
	} else {
		op = EPOLL_CTL_ADD;
	}

	ee.events = events | (uint32_t) flags;
	ee.data.ptr = (void *) c;

	stu_log_debug(2, "epoll add event: fd=%d, op=%d, ev=%X.", c->fd, op, ee.events);

	if (epoll_ctl(ev->epfd, op, c->fd, &ee) == -1) {
		stu_log_error(stu_errno, "epoll_ctl(%d, %d) failed", op, c->fd);
		return STU_ERROR;
	}

	ev->active = TRUE;

	return STU_OK;
}

stu_int32_t
stu_event_epoll_del(stu_event_t *ev, uint32_t event, stu_uint32_t flags) {
	stu_connection_t   *c;
	stu_event_t        *e;
	uint32_t            prev;
	int                 op;
	struct epoll_event  ee;

	/*
	 * when the file descriptor is closed, the epoll automatically deletes
	 * it from its queue, so we do not need to delete explicitly the event
	 * before closing the file descriptor
	 */
	if (flags & STU_CLOSE_EVENT) {
		ev->active = FALSE;
		return STU_OK;
	}

	c = (stu_connection_t *) ev->data;

	if (event == STU_READ_EVENT) {
		e = &c->write;
		prev = EPOLLOUT;
	} else {
		e = &c->read;
		prev = EPOLLIN|EPOLLRDHUP;
	}

	if (e->active) {
		op = EPOLL_CTL_MOD;
		ee.events = prev | (uint32_t) flags;
		ee.data.ptr = (void *) c;
	} else {
		op = EPOLL_CTL_DEL;
		ee.events = 0;
		ee.data.ptr = NULL;
	}

	stu_log_debug(2, "epoll del event: fd=%d, op=%d, ev=%X.", c->fd, op, ee.events);

	if (epoll_ctl(ev->epfd, op, c->fd, &ee) == -1) {
		stu_log_error(stu_errno, "epoll_ctl(%d, %d) failed", op, c->fd);
		return STU_ERROR;
	}

	ev->active = FALSE;

	return STU_OK;
}

stu_int32_t
stu_event_epoll_process_events(stu_fd_t epfd, stu_msec_t timer, stu_uint32_t flags) {
	stu_connection_t   *c;
	struct epoll_event *ev, events[STU_EPOLL_EVENTS];
	stu_int32_t         nev, i;

	nev = epoll_wait(epfd, events, STU_EPOLL_EVENTS, timer);

	if (flags & STU_EVENT_FLAGS_UPDATE_TIME) {
		stu_time_update();
	}

	if (nev == -1) {
		stu_log_error(stu_errno, "epoll_wait error: nev=%d.", nev);
		return STU_ERROR;
	}

	for (i = 0; i < nev; i++) {
		ev = &events[i];
		c = (stu_connection_t *) events[i].data.ptr;
		if (c == NULL || c->fd == (stu_socket_t) -1) {
			continue;
		}

		if ((ev->events & EPOLLIN) && c->read.active) {
			c->read.handler(&c->read);
		}

		if ((ev->events & EPOLLOUT) && c->write.active) {
			c->write.handler(&c->write);
		}
	}

	return STU_OK;
}
