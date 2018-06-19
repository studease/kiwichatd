/*
 * stu_event_epoll.c
 *
 *  Created on: 2017骞�11鏈�16鏃�
 *      Author: Tony Lau
 */

#include "stu_event.h"

extern stu_connection_t  stu_free_connections;


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
		e = c->write;
		prev = EPOLLOUT;
#if (STU_READ_EVENT != EPOLLIN|EPOLLRDHUP)
		events = EPOLLIN|EPOLLRDHUP;
#endif
	} else {
		e = c->read;
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

	if (epoll_ctl(ev->evfd, op, c->fd, &ee) == -1) {
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
		e = c->write;
		prev = EPOLLOUT;
	} else {
		e = c->read;
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

	if (epoll_ctl(ev->evfd, op, c->fd, &ee) == -1) {
		stu_log_error(stu_errno, "epoll_ctl(%d, %d) failed", op, c->fd);
		return STU_ERROR;
	}

	ev->active = FALSE;

	return STU_OK;
}

stu_int32_t
stu_event_epoll_add_connection(stu_connection_t *c) {
	stu_event_t        *ev;
	struct epoll_event  ee;

	ev = c->read;

	ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
	ee.data.ptr = (void *) c;

	stu_log_debug(2, "epoll add connection: fd=%d, ev=%X.", c->fd, ee.events);

	if (epoll_ctl(ev->evfd, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
		stu_log_error(stu_errno, "epoll_ctl(EPOLL_CTL_ADD, %d) failed.", c->fd);
		return STU_ERROR;
	}

	c->read->active = TRUE;
	c->write->active = TRUE;

	return STU_OK;
}

stu_int32_t
stu_event_epoll_del_connection(stu_connection_t *c, stu_uint32_t flags) {
	stu_event_t        *ev;
	int                 op;
	struct epoll_event  ee;

	ev = c->read;

	/*
	 * when the file descriptor is closed the epoll automatically deletes
	 * it from its queue so we do not need to delete explicitly the event
	 * before the closing the file descriptor
	 */
	if (flags & STU_CLOSE_EVENT) {
		c->read->active = FALSE;
		c->write->active = FALSE;
		return STU_OK;
	}

	stu_log_debug(3, "epoll del connection: fd=%d.", c->fd);

	op = EPOLL_CTL_DEL;
	ee.events = 0;
	ee.data.ptr = NULL;

	if (epoll_ctl(ev->evfd, op, c->fd, &ee) == -1) {
		stu_log_error(stu_errno, "epoll_ctl(%d, %d) failed.", op, c->fd);
		return STU_ERROR;
	}

	c->read->active = FALSE;
	c->write->active = FALSE;

	return STU_OK;
}


stu_int32_t
stu_event_epoll_process_events(stu_fd_t evfd, stu_msec_t timer, stu_uint32_t flags) {
	stu_connection_t   *c;
	stu_queue_t        *q;
	struct epoll_event *ev, events[STU_EPOLL_EVENTS];
	stu_int32_t         nev, i;

	nev = epoll_wait(evfd, events, STU_EPOLL_EVENTS, timer);

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

		if ((ev->events & EPOLLIN) && c->read->active) {
			c->read->handler(c->read);
		}

		if ((ev->events & EPOLLOUT) && c->write->active) {
			c->write->handler(c->write);
		}
	}

	if (stu_mutex_trylock(&stu_free_connections.lock)) {
		goto done;
	}

	for (q = stu_queue_head(&stu_free_connections.queue); q != stu_queue_sentinel(&stu_free_connections.queue); /* void */) {
		c = stu_queue_data(q, stu_connection_t, queue);

		q = stu_queue_next(q);

		stu_queue_remove(&c->queue);
		stu_connection_free(c);
	}

	stu_mutex_unlock(&stu_free_connections.lock);

done:

	return STU_OK;
}
