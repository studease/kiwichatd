/*
 * stu_event_iocp.c
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#include "stu_event.h"

extern stu_connection_t  stu_free_connections;


stu_fd_t
stu_event_iocp_create() {
	stu_fd_t fd;

	fd = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (fd == NULL) {
		stu_log_error(stu_errno, "Failed to create iocp instance.");
	}

	return fd;
}


stu_int32_t
stu_event_iocp_add(stu_event_t *ev, uint32_t event, stu_uint32_t flags) {
	stu_connection_t *c;

	c = (stu_connection_t *) ev->data;

	c->read->active = 1;
	c->write->active = 1;

	c->read->ovlp.event = c->read;
	c->write->ovlp.event = c->write;

	stu_log_debug(2, "iocp add: fd=%d, key=%lu, ov=%p", c->fd, flags, &ev->ovlp);

	if (CreateIoCompletionPort((HANDLE) c->fd, ev->evfd, flags, 0) == NULL) {
		stu_log_error(stu_errno, "CreateIoCompletionPort() failed.");
		return STU_ERROR;
	}

	return STU_OK;
}

stu_int32_t
stu_event_iocp_del(stu_event_t *ev, uint32_t event, stu_uint32_t flags) {
	return STU_OK;
}

stu_int32_t
stu_event_iocp_add_connection(stu_connection_t *c) {
	return stu_event_iocp_add(c->read, STU_READ_EVENT, STU_CLEAR_EVENT);
}

stu_int32_t
stu_event_iocp_del_connection(stu_connection_t *c, stu_uint32_t flags) {
#if 0
	if (flags & STU_CLOSE_EVENT) {
		return STU_OK;
	}

	if (CancelIo((HANDLE) c->fd) == 0) {
		stu_log_error(stu_errno, "CancelIo() failed.");
		return STU_ERROR;
	}
#endif

	return STU_OK;
}


stu_int32_t
stu_event_iocp_process_events(stu_fd_t evfd, stu_msec_t timer, stu_uint32_t flags) {
	stu_connection_t *c;
	stu_event_ovlp_t *ovlp;
	stu_event_t      *ev;
	stu_queue_t      *q;
	int               rc;
	u_long            bytes;
	stu_uint32_t      key;
	stu_err_t         err;
	stu_msec_t        delta;

	err = 0;

	if (timer == STU_TIMER_INFINITE) {
		timer = INFINITE;
	}

	stu_log_debug(2, "iocp timer: %lu.", timer);

	rc = GetQueuedCompletionStatus(evfd, &bytes, (PULONG_PTR) &key, (LPOVERLAPPED *) &ovlp, (u_long) timer);
	if (rc == 0) {
		err = stu_errno;
	}

	delta = stu_current_msec;

	if (flags & STU_UPDATE_TIME) {
		stu_time_update();
	}

	stu_log_debug(2, "iocp: rc=%d, bytes=%lu, key=%d, ov=%p.", rc, bytes, key, ovlp);

	if (timer != INFINITE) {
		delta = stu_current_msec - delta;
		stu_log_debug(2, "iocp timer: start=%lu, delta=%lu.", timer, delta);
	}

	if (err) {
		if (ovlp == NULL) {
			if (err != WAIT_TIMEOUT) {
				stu_log_error(err, "GetQueuedCompletionStatus() failed.");
				return STU_ERROR;
			}

			return STU_OK;
		}

		ovlp->error = err;
	}

	if (ovlp == NULL) {
		stu_log_error(0, "GetQueuedCompletionStatus() returned no operation.");
		return STU_ERROR;
	}

	ev = ovlp->event;
	c = (stu_connection_t *) ev->data;

	stu_log_debug(err, "iocp event: c=0x%p, ev=%p.", c, ev);

	if (err == ERROR_NETNAME_DELETED /* the socket was closed */
		|| err == ERROR_OPERATION_ABORTED /* the operation was canceled */) {
		/*
		 * the WSA_OPERATION_ABORTED completion notification
		 * for a file descriptor that was closed
		 */
		stu_log_debug(err, "iocp event aborted: c=0x%p, ev=%p.", c, ev);
		return STU_OK;
	}

	if (err) {
		c->error = TRUE;
		stu_log_error(err, "GetQueuedCompletionStatus() returned operation error.");
	}

	switch (key) {
	case STU_IOCP_ACCEPT:
	case STU_IOCP_IO:
	case STU_IOCP_CONNECT:
		break;
	}

	ev->available = bytes;

	stu_log_debug(2, "iocp event handler: %p.", ev->handler);

	ev->handler(ev);

#if (STU_WIN32)
	if (!c->timedout && !c->error && !c->close && !c->destroyed) {
		stu_overlapped_wsarecv(c, NULL, 0);
	}
#endif

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
