/*
 * stu_os.c
 *
 *  Created on: 2018��3��30��
 *      Author: Tony Lau
 */

#include "stu_os.h"

stu_uint32_t  stu_ncpu;

stu_os_io_t   stu_os_io = {
	stu_unix_recv,
	stu_udp_unix_recv,
	stu_unix_send,
	stu_udp_unix_send,
	0
};


stu_int32_t
stu_os_init() {
	stu_ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	return STU_OK;
}


ssize_t
stu_unix_send(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t *wev;
	ssize_t      n;
	stu_err_t    err;

	wev = c->write;

#if (STU_HAVE_KQUEUE)

	if ((stu_event_flags & STU_USE_KQUEUE_EVENT) && wev->pending_eof) {
		stu_log_error(wev->kq_errno, "kevent() reported about an closed connection.");
		wev->error = 1;
		return STU_ERROR;
	}

#endif

	for ( ;; ) {
		n = send(c->fd, buf, size, 0);

		stu_log_debug(3, "send: fd=%d, %d of %u.", c->fd, n, size);

		if (n > 0) {
			return n;
		}

		err = stu_socket_errno;

		if (n == 0) {
			stu_log_error(err, "send() returned zero.");
			return n;
		}

		if (err == STU_EAGAIN || err == STU_EINTR) {
			stu_log_error(err, "send() not ready.");

			if (err == STU_EAGAIN) {
				return STU_AGAIN;
			}
		} else {
			wev->error = 1;
			return STU_ERROR;
		}
	}

	return STU_ERROR;
}

ssize_t
stu_unix_recv(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t *rev;
	ssize_t      n;
	stu_err_t    err;

	rev = c->read;

#if (STU_HAVE_KQUEUE)

	if (stu_event_flags & STU_USE_KQUEUE_EVENT) {
		stu_log_debug(3, "recv: eof=%d, avail=%d, err=%d.", rev->pending_eof, rev->available, rev->kq_errno);

		if (rev->available == 0) {
			if (rev->pending_eof) {
				rev->ready = 0;
				rev->eof = 1;

				if (rev->kq_errno) {
					rev->error = 1;
					stu_set_socket_errno(rev->kq_errno);

					return STU_ERROR;
				}

				return 0;

			} else {
				rev->ready = 0;
				return STU_AGAIN;
			}
		}
	}

#endif

#if (STU_HAVE_EPOLLRDHUP)

	if (stu_event_flags & STU_USE_EPOLL_EVENT) {
		stu_log_debug(2, "recv: eof=%d, avail=%d.", rev->pending_eof, rev->available);

		if (!rev->available && !rev->pending_eof) {
			rev->ready = 0;
			return STU_AGAIN;
		}
	}

#endif

	do {
		n = recv(c->fd, buf, size, 0);

		stu_log_debug(3, "recv: fd=%d, %d of %u.", c->fd, n, size);

		if (n == 0) {

#if (STU_HAVE_KQUEUE)
			/*
			 * on FreeBSD recv() may return 0 on closed socket
			 * even if kqueue reported about available data
			 */
			if (stu_event_flags & STU_USE_KQUEUE_EVENT) {
				rev->available = 0;
			}
#endif

			return 0;
		}

		if (n > 0) {

#if (STU_HAVE_KQUEUE)
			if (stu_event_flags & STU_USE_KQUEUE_EVENT) {
				rev->available -= n;

				/*
				 * rev->available may be negative here because some additional
				 * bytes may be received between kevent() and recv()
				 */
				if (rev->available <= 0) {
					if (!rev->pending_eof) {
						rev->ready = 0;
					}

					rev->available = 0;
				}

				return n;
			}
#endif

#if (STU_HAVE_EPOLLRDHUP)
			if ((stu_event_flags & STU_USE_EPOLL_EVENT) && stu_use_epoll_rdhup) {
				if ((size_t) n < size) {
					if (!rev->pending_eof) {
						rev->ready = 0;
					}

					rev->available = 0;
				}

				return n;
			}
#endif

			return n;
		}

		err = stu_socket_errno;

		if (err == STU_EAGAIN || err == STU_EINTR) {
			stu_log_debug(3, "recv() not ready.");
			n = STU_AGAIN;
		} else {
			stu_log_error(err, "recv() failed.");
			n = STU_ERROR;
			break;
		}
	} while (err == STU_EINTR);

	if (n == STU_ERROR) {
		rev->error = 1;
	}

	return n;
}

ssize_t
stu_udp_unix_send(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t *wev;
	ssize_t      n;
	stu_err_t    err;

	wev = c->write;

	for ( ;; ) {
		n = sendto(c->fd, buf, size, 0, c->sockaddr, c->socklen);
		stu_log_debug(4, "sendto: fd:%d %z of %uz to \"%s\"", c->fd, n, size, c->addr_text.data);

		if (n >= 0) {
			if ((size_t) n != size) {
				stu_log_error(0, "sendto() incomplete");
				wev->error = 1;
				return STU_ERROR;
			}

			return n;
		}

		err = stu_socket_errno;

		if (err == STU_EAGAIN) {
			stu_log_error(STU_EAGAIN, "sendto() not ready");
			return STU_AGAIN;
		}

		if (err != STU_EINTR) {
			stu_log_error(err, "sendto() failed");
			wev->error = 1;
			return STU_ERROR;
		}
	}

    return STU_ERROR;
}

ssize_t
stu_udp_unix_recv(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t *rev;
	ssize_t      n;
	stu_err_t    err;

	rev = c->read;

	do {
		n = recv(c->fd, buf, size, 0);

		stu_log_debug(3, "recv: fd:%d %z of %uz", c->fd, n, size);

		if (n >= 0) {

#if (STU_HAVE_KQUEUE)

			if (stu_event_flags & STU_USE_KQUEUE_EVENT) {
				rev->available -= n;

				/*
				 * rev->available may be negative here because some additional
				 * bytes may be received between kevent() and recv()
				 */
				if (rev->available <= 0) {
					rev->ready = 0;
					rev->available = 0;
				}
			}

#endif

			return n;
		}

		err = stu_socket_errno;

		if (err == STU_EAGAIN || err == STU_EINTR) {
			stu_log_error(err, "recv() not ready");
			n = STU_AGAIN;
		} else {
			stu_log_error(err, "recv() failed");
			n = STU_ERROR;
			break;
		}
	} while (err == STU_EINTR);

	if (n == STU_ERROR) {
		rev->error = 1;
	}

	return n;
}
