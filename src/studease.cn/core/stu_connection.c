/*
 * stu_connection.c
 *
 *  Created on: 2017骞�11鏈�16鏃�
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

stu_connection_t  stu_free_connections;


stu_int32_t
stu_connection_init() {
	stu_mutex_init(&stu_free_connections.lock, NULL);
	stu_queue_init(&stu_free_connections.queue);
	return STU_OK;
}


stu_int32_t
stu_connect(stu_connection_t *c, stu_addr_t *addr) {
	stu_int32_t   rc;
	stu_err_t     err;
#if (STU_HAVE_IOCP)
	LPOVERLAPPED  ovlp;
	DWORD         bytes;

	ovlp = (LPOVERLAPPED) &c->write->ovlp;
	stu_memzero(ovlp, sizeof(WSAOVERLAPPED));
#endif

	stu_log_debug(3, "connect to %s: fd=%d.", addr->name.data, c->fd);

#if (STU_HAVE_IOCP)
	struct sockaddr_in  si;
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = INADDR_ANY;
	si.sin_port = 0;

	if (bind(c->fd, (struct sockaddr *) &si, sizeof(si)) == -1) {
		stu_log_error(stu_socket_errno, "bind() failed: fd=%d.", c->fd);
		return STU_ERROR;
	}

	rc = stu_connectex(c->fd, (struct sockaddr *) &addr->sockaddr, addr->socklen, NULL, 0, &bytes, ovlp);
#else
	rc = connect(c->fd, (struct sockaddr *) &addr->sockaddr, addr->socklen);
#endif

	if (rc == -1) {
		err = stu_socket_errno;

		if (err != STU_EINPROGRESS
#if (STU_WIN32)
				/* Winsock returns WSAEWOULDBLOCK (STU_EAGAIN) */
				&& err != STU_EAGAIN
#endif
				) {
			if (err == STU_ECONNREFUSED
	#if (STU_LINUX)
				/*
				 * Linux returns EAGAIN instead of ECONNREFUSED
				 * for unix sockets if listen queue is full
				 */
				|| err == STU_EAGAIN
	#endif
				|| err == STU_ECONNRESET
				|| err == STU_ENETDOWN
				|| err == STU_ENETUNREACH
				|| err == STU_EHOSTDOWN
				|| err == STU_EHOSTUNREACH) {
				// ERR
			} else {
				// CRIT
			}

			stu_log_error(err, "connect to %s failed: fd=%d.", addr->name.data, c->fd);

			return STU_DECLINED;
		}
	}

	stu_log_debug(3, "connected to peer %s: fd=%d.", addr->name.data, c->fd);

	return STU_OK;
}

stu_connection_t *
stu_connection_get(stu_socket_t s) {
	stu_connection_t *c;
	u_char           *p;
	size_t            sc, se;

	sc = sizeof(stu_connection_t);
	se = sizeof(stu_event_t);

	p = stu_calloc(sc + 2 * se);
	if (p == NULL) {
		return NULL;
	}

	c = (stu_connection_t *) p;
	p += sc;

	c->read = (stu_event_t *) p;
	p += se;

	c->write = (stu_event_t *) p;

	c->pool = stu_pool_create(STU_CONNECTION_POOL_DEFAULT_SIZE);
	if (c->pool == NULL) {
		stu_free(c);
		return NULL;
	}

	stu_mutex_init(&c->lock, NULL);
	stu_queue_init(&c->queue);

	c->fd = s;
	c->read->data = (void *) c;
	c->write->data = (void *) c;
	c->idle = TRUE;

	stu_log_debug(3, "got connection: c=%p, fd=%d.", c, c->fd);

	return c;
}

void
stu_connection_close(stu_connection_t *c) {
	stu_socket_t  fd;

	if (c->fd == (stu_socket_t) STU_SOCKET_INVALID) {
		stu_log_error(0, "connection already closed.");
		return;
	}

	/*if (c->read->timer_set) {
		stu_del_timer(c->read);
	}

	if (c->write->timer_set) {
		stu_del_timer(c->write);
	}*/

	stu_event_del(c->read, STU_READ_EVENT, STU_CLOSE_EVENT);
	stu_event_del(c->write, STU_WRITE_EVENT, STU_CLOSE_EVENT);

	fd = c->fd;

	c->fd = (stu_socket_t) STU_SOCKET_INVALID;
	c->close = TRUE;
	stu_socket_close(fd);

	stu_upstream_cleanup(c);

	stu_log_debug(3, "freed connection: c=%p, fd=%d.", c, fd);

	c->destroyed = TRUE;

	stu_mutex_lock(&stu_free_connections.lock);
	stu_queue_insert_tail(&stu_free_connections.queue, &c->queue);
	stu_mutex_unlock(&stu_free_connections.lock);
}

void
stu_connection_free(stu_connection_t *c) {
	stu_pool_destroy(c->pool);
	stu_free((void *) c);
}
