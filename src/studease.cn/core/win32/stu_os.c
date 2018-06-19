/*
 * stu_os.c
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#include "stu_os.h"

stu_uint32_t      stu_win32_version;
stu_uint32_t      stu_ncpu;
char              stu_unique[STU_INT32_LEN + 1];

stu_os_io_t       stu_os_io = {
	stu_win32_recv,
	stu_udp_wsarecv,
	stu_win32_send,
	NULL,
	0
};

LPFN_ACCEPTEX              stu_acceptex;
LPFN_GETACCEPTEXSOCKADDRS  stu_getacceptexsockaddrs;
LPFN_TRANSMITFILE          stu_transmitfile;
LPFN_TRANSMITPACKETS       stu_transmitpackets;
LPFN_CONNECTEX             stu_connectex;
LPFN_DISCONNECTEX          stu_disconnectex;

extern stu_pid_t           stu_pid;

static u_int               osviex;
static OSVERSIONINFOEX     osvi;

static GUID  ax_guid = WSAID_ACCEPTEX;
static GUID  as_guid = WSAID_GETACCEPTEXSOCKADDRS;
static GUID  tf_guid = WSAID_TRANSMITFILE;
static GUID  tp_guid = WSAID_TRANSMITPACKETS;
static GUID  cx_guid = WSAID_CONNECTEX;
static GUID  dx_guid = WSAID_DISCONNECTEX;


stu_int32_t
stu_os_init() {
	WSADATA       wsd;
	DWORD         bytes;
	SYSTEM_INFO   si;
	stu_socket_t  fd;
	stu_err_t     err;

	/* get Windows version */
	stu_memzero(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

	osviex = GetVersionEx((OSVERSIONINFO *) &osvi);
	if (osviex == 0) {
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		if (GetVersionEx((OSVERSIONINFO *) &osvi) == 0) {
			stu_log_error(stu_errno, "GetVersionEx() failed.");
			return STU_ERROR;
		}
	}

#ifdef _MSC_VER
#pragma warning(default:4996)
#endif

	/*
	 *  Windows 3.1 Win32s   0xxxxx
	 *
	 *  Windows 95           140000
	 *  Windows 98           141000
	 *  Windows ME           149000
	 *  Windows NT 3.51      235100
	 *  Windows NT 4.0       240000
	 *  Windows NT 4.0 SP5   240050
	 *  Windows 2000         250000
	 *  Windows XP           250100
	 *  Windows 2003         250200
	 *  Windows Vista/2008   260000
	 *
	 *  Windows CE x.x       3xxxxx
	 */
	stu_win32_version = osvi.dwPlatformId * 100000 + osvi.dwMajorVersion * 10000 + osvi.dwMinorVersion * 100;

	if (osviex) {
		stu_win32_version += osvi.wServicePackMajor * 10 + osvi.wServicePackMinor;
	}

	GetSystemInfo(&si);
	stu_allocation_granularity = si.dwAllocationGranularity;
	stu_ncpu = si.dwNumberOfProcessors;

	/* init Winsock */
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
		stu_log_error(stu_socket_errno, "WSAStartup() failed.");
		return STU_ERROR;
	}

	/*
	 * get AcceptEx(), GetAcceptExSockAddrs(), TransmitFile(),
	 * TransmitPackets(), ConnectEx(), and DisconnectEx() addresses
	 */
	fd = stu_socket(AF_INET, SOCK_STREAM, 0);
	if (fd == (stu_socket_t) STU_SOCKET_INVALID) {
		stu_log_error(stu_socket_errno, stu_socket_n " failed.");
		return STU_ERROR;
	}

	if (WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &ax_guid, sizeof(GUID),
			&stu_acceptex, sizeof(LPFN_ACCEPTEX), &bytes, NULL, NULL) == -1) {
		stu_log_error(stu_socket_errno, "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_ACCEPTEX) failed.");
	}

	if (WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &as_guid, sizeof(GUID),
			&stu_getacceptexsockaddrs, sizeof(LPFN_GETACCEPTEXSOCKADDRS), &bytes, NULL, NULL) == -1) {
		stu_log_error(stu_socket_errno, "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_GETACCEPTEXSOCKADDRS) failed.");
	}

	if (WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &tf_guid, sizeof(GUID),
			&stu_transmitfile, sizeof(LPFN_TRANSMITFILE), &bytes, NULL, NULL) == -1) {
		stu_log_error(stu_socket_errno, "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_TRANSMITFILE) failed.");
	}

	if (WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &tp_guid, sizeof(GUID),
			&stu_transmitpackets, sizeof(LPFN_TRANSMITPACKETS), &bytes, NULL, NULL) == -1) {
		stu_log_error(stu_socket_errno, "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_TRANSMITPACKETS) failed.");
	}

	if (WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &cx_guid, sizeof(GUID),
			&stu_connectex, sizeof(LPFN_CONNECTEX), &bytes, NULL, NULL) == -1) {
		stu_log_error(stu_socket_errno, "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_CONNECTEX) failed.");
	}

	if (WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &dx_guid, sizeof(GUID),
			&stu_disconnectex, sizeof(LPFN_DISCONNECTEX), &bytes, NULL, NULL) == -1) {
		stu_log_error(stu_socket_errno, "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_DISCONNECTEX) failed.");
	}

	if (stu_socket_close(fd) == -1) {
		stu_log_error(stu_socket_errno, stu_socket_close_n " failed.");
	}

	if (GetEnvironmentVariable("stu_unique", stu_unique, STU_INT32_LEN + 1) == 0) {
		err = stu_errno;
		if (err != ERROR_ENVVAR_NOT_FOUND) {
			stu_log_error(err, "GetEnvironmentVariable(\"stu_unique\") failed.");
			return STU_ERROR;
		}

		stu_sprintf((u_char *) stu_unique, "%d\0", stu_pid);
	}

	return STU_OK;
}


ssize_t
stu_win32_send(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t *wev;
	ssize_t      n;
	stu_err_t    err;

	wev = c->write;

	for ( ;; ) {
		n = send(c->fd, (const char *) buf, size, 0);

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
stu_win32_recv(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t *rev;
	ssize_t      n;
	stu_err_t    err;

	rev = c->read;

	do {
		n = recv(c->fd, (char *) buf, size, 0);

		stu_log_debug(3, "recv: fd=%d, %d of %u.", c->fd, n, size);

		if (n == 0) {
			return 0;
		}

		if (n > 0) {
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
stu_wsasend(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t *wev;
	WSABUF       wsabuf;
	u_long       bytes;
	stu_err_t    err;
	stu_int32_t  n;

	wev = c->write;

	/*
	 * WSABUF must be 4-byte aligned otherwise
	 * WSASend() will return undocumented WSAEINVAL error.
	 */
	wsabuf.buf = (char *) buf;
	wsabuf.len = size;
	bytes = 0;

	n = WSASend(c->fd, &wsabuf, 1, &bytes, 0, NULL, NULL);

	stu_log_debug(3, "WSASend: fd=%d, rc=%d, %u of %u.", c->fd, n, bytes, size);

	if (n == 0) {
		return bytes;
	}

	err = stu_socket_errno;
	if (err == WSAEWOULDBLOCK) {
		stu_log_error(err, "WSASend() not ready.");
		return STU_AGAIN;
	}

	stu_log_error(err, "WSASend() failed.");

	wev->error = 1;

	return STU_ERROR;
}

ssize_t
stu_wsarecv(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t *rev;
	WSABUF       wsabuf[1];
	u_long       bytes, flags;
	stu_err_t    err;
	stu_int32_t  n;

	rev = c->read;

	wsabuf[0].buf = (char *) buf;
	wsabuf[0].len = size;
	bytes = 0;
	flags = 0;

	n = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, NULL, NULL);

	stu_log_debug(3, "WSARecv: fd=%d, rc=%d, %u of %u.", c->fd, n, bytes, size);

	if (n == -1) {
		err = stu_socket_errno;
		if (err == WSAEWOULDBLOCK) {
			stu_log_debug(3, "WSARecv() not ready.");
			return STU_AGAIN;
		}

		stu_log_error(err, "WSARecv() failed.");

		rev->error = 1;

		return STU_ERROR;
	}

	return bytes;
}

ssize_t
stu_udp_wsarecv(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t *rev;
	WSABUF       wsabuf[1];
	u_long       bytes, flags;
	stu_err_t    err;
	stu_int32_t  rc;

	rev = c->read;

	wsabuf[0].buf = (char *) buf;
	wsabuf[0].len = size;
	flags = 0;
	bytes = 0;

	rc = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, NULL, NULL);

	stu_log_debug(3, "WSARecv: fd=%d rc=%d, %u of %u.", c->fd, rc, bytes, size);

	if (rc == -1) {
		err = stu_socket_errno;
		if (err == WSAEWOULDBLOCK) {
			stu_log_error(err, "WSARecv() not ready.");
			return STU_AGAIN;
		}

		rev->error = 1;

		return STU_ERROR;
	}

	return bytes;
}


ssize_t
stu_overlapped_wsasend(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t     *wev;
	WSABUF           wsabuf;
	LPWSAOVERLAPPED  ovlp;
	u_long           bytes;
	stu_err_t        err;
	stu_int32_t      n;

	wev = c->write;

	/*
	 * WSABUFs must be 4-byte aligned otherwise
	 * WSASend() will return undocumented WSAEINVAL error.
	 */
	wsabuf.buf = (char *) buf;
	wsabuf.len = size;
	bytes = 0;

	ovlp = (LPWSAOVERLAPPED) &c->write->ovlp;
	stu_memzero(ovlp, sizeof(WSAOVERLAPPED));

	n = WSASend(c->fd, &wsabuf, 1, &bytes, 0, ovlp, NULL);

	stu_log_debug(3, "WSASend ovlp: fd:%d, n=%d, %u of %u.", c->fd, n, bytes, size);

	if (n == 0) {
		/*
		 * if a socket was bound with I/O completion port then
		 * GetQueuedCompletionStatus() would anyway return its status
		 * despite that WSASend() was already complete
		 */
		wev->active = 1;

		return STU_AGAIN;
	}

	err = stu_socket_errno;
	if (err == WSA_IO_PENDING) {
		stu_log_error(err, "WSASend() posted.");
		wev->active = 1;
		return STU_AGAIN;
	}

	stu_log_error(err, "WSASend() failed.");

	wev->error = 1;

	return STU_ERROR;
}

ssize_t
stu_overlapped_wsarecv(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t     *rev;
	WSABUF           wsabuf[1];
	LPWSAOVERLAPPED  ovlp;
	u_long           bytes, flags;
	stu_err_t        err;
	stu_int32_t      n;

	rev = c->read;

	wsabuf[0].buf = (char *) buf;
	wsabuf[0].len = size;
	bytes = 0;
	flags = 0;

	ovlp = (LPWSAOVERLAPPED) &rev->ovlp;
	stu_memzero(ovlp, sizeof(WSAOVERLAPPED));

	n = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, ovlp, NULL);

	stu_log_debug(3, "WSARecv ovlp: fd=%d, n=%d, %u of %u.", c->fd, n, bytes, size);

	if (n == -1) {
		err = stu_socket_errno;
		if (err == WSA_IO_PENDING) {
			rev->active = 1;
			stu_log_error(err, "WSARecv() posted.");
			return STU_AGAIN;
		}

		stu_log_error(err, "WSARecv() failed.");

		rev->error = 1;

		return STU_ERROR;
	}

	/*
	 * if a socket was bound with I/O completion port
	 * then GetQueuedCompletionStatus() would anyway return its status
	 * despite that WSARecv() was already complete
	 */
	rev->active = 1;

	return STU_AGAIN;
}

ssize_t
stu_udp_overlapped_wsarecv(stu_connection_t *c, u_char *buf, size_t size) {
	stu_event_t      *rev;
	WSABUF            wsabuf[1];
	LPWSAOVERLAPPED   ovlp;
	u_long            bytes, flags;
	stu_err_t         err;
	stu_int32_t       n;

	rev = c->read;

	wsabuf[0].buf = (char *) buf;
	wsabuf[0].len = size;
	flags = 0;
	bytes = 0;

	ovlp = (LPWSAOVERLAPPED) &rev->ovlp;
	stu_memzero(ovlp, sizeof(WSAOVERLAPPED));

	n = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, ovlp, NULL);

	stu_log_debug(3, "WSARecv ovlp: fd=%d, n=%d, %u of %u.", c->fd, n, bytes, size);

	if (n == -1) {
		err = stu_socket_errno;
		if (err == WSA_IO_PENDING) {
			rev->active = 1;
			stu_log_error(err, "WSARecv() posted.");
			return STU_AGAIN;
		}

		stu_log_error(err, "WSARecv() failed.");

		rev->error = 1;

		return STU_ERROR;
	}

	/*
	 * if a socket was bound with I/O completion port
	 * then GetQueuedCompletionStatus() would anyway return its status
	 * despite that WSARecv() was already complete
	 */
	rev->active = 1;

	return STU_AGAIN;
}
