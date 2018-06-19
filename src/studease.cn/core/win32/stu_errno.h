/*
 * stu_errno.h
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_WIN32_STU_ERRNO_H_
#define STUDEASE_CN_CORE_WIN32_STU_ERRNO_H_

#include "../../stu_config.h"
#include "../stu_core.h"

typedef DWORD                      stu_err_t;

#define stu_errno                  GetLastError()
#define stu_set_errno(err)         SetLastError(err)
#define stu_socket_errno           WSAGetLastError()
#define stu_set_socket_errno(err)  WSASetLastError(err)

#define STU_EPERM                  ERROR_ACCESS_DENIED
#define STU_ENOENT                 ERROR_FILE_NOT_FOUND
#define STU_ENOPATH                ERROR_PATH_NOT_FOUND
#define STU_ENOMEM                 ERROR_NOT_ENOUGH_MEMORY
#define STU_EACCES                 ERROR_ACCESS_DENIED
/*
 * there are two EEXIST error codes:
 * ERROR_FILE_EXISTS used by CreateFile(CREATE_NEW),
 * and ERROR_ALREADY_EXISTS used by CreateDirectory();
 * MoveFile() uses both
 */
#define STU_EEXIST                 ERROR_ALREADY_EXISTS
#define STU_EEXIST_FILE            ERROR_FILE_EXISTS
#define STU_EXDEV                  ERROR_NOT_SAME_DEVICE
#define STU_ENOTDIR                ERROR_PATH_NOT_FOUND
#define STU_EISDIR                 ERROR_CANNOT_MAKE
#define STU_ENOSPC                 ERROR_DISK_FULL
#define STU_EPIPE                  EPIPE
#define STU_EINTR                  WSAEINTR
#define STU_EAGAIN                 WSAEWOULDBLOCK
#define STU_EINPROGRESS            WSAEINPROGRESS
#define STU_ENOPROTOOPT            WSAENOPROTOOPT
#define STU_EOPNOTSUPP             WSAEOPNOTSUPP
#define STU_EADDRINUSE             WSAEADDRINUSE
#define STU_ECONNABORTED           WSAECONNABORTED
#define STU_ECONNRESET             WSAECONNRESET
#define STU_ENOTCONN               WSAENOTCONN
#define STU_ETIMEDOUT              WSAETIMEDOUT
#define STU_ECONNREFUSED           WSAECONNREFUSED
#define STU_ENAMETOOLONG           ERROR_BAD_PATHNAME
#define STU_ENETDOWN               WSAENETDOWN
#define STU_ENETUNREACH            WSAENETUNREACH
#define STU_EHOSTDOWN              WSAEHOSTDOWN
#define STU_EHOSTUNREACH           WSAEHOSTUNREACH
#define STU_ENOMOREFILES           ERROR_NO_MORE_FILES
#define STU_EILSEQ                 ERROR_NO_UNICODE_TRANSLATION
#define STU_ELOOP                  0
#define STU_EBADF                  WSAEBADF

#define STU_EALREADY               WSAEALREADY
#define STU_EINVAL                 WSAEINVAL
#define STU_EMFILE                 WSAEMFILE
#define STU_ENFILE                 WSAEMFILE


u_char      *stu_strerror(stu_err_t err, u_char *explain, size_t size);
stu_int32_t  stu_strerror_init(void);

#endif /* STUDEASE_CN_CORE_WIN32_STU_ERRNO_H_ */
