/*
 * stu_errno.h
 *
 *  Created on: 2017骞�11鏈�15鏃�
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_UNIX_STU_ERRNO_H_
#define STUDEASE_CN_CORE_UNIX_STU_ERRNO_H_

#include "../../stu_config.h"
#include "../stu_core.h"

typedef int                 stu_err_t;

#define STU_EPERM           EPERM
#define STU_ENOENT          ENOENT
#define STU_ENOPATH         ENOENT
#define STU_ESRCH           ESRCH
#define STU_EINTR           EINTR
#define STU_ECHILD          ECHILD
#define STU_ENOMEM          ENOMEM
#define STU_EACCES          EACCES
#define STU_EBUSY           EBUSY
#define STU_EEXIST          EEXIST
#define STU_EEXIST_FILE     EEXIST
#define STU_EXDEV           EXDEV
#define STU_ENOTDIR         ENOTDIR
#define STU_EISDIR          EISDIR
#define STU_EINVAL          EINVAL
#define STU_ENFILE          ENFILE
#define STU_EMFILE          EMFILE
#define STU_ENOSPC          ENOSPC
#define STU_EPIPE           EPIPE
#define STU_EINPROGRESS     EINPROGRESS
#define STU_ENOPROTOOPT     ENOPROTOOPT
#define STU_EOPNOTSUPP      EOPNOTSUPP
#define STU_EADDRINUSE      EADDRINUSE
#define STU_ECONNABORTED    ECONNABORTED
#define STU_ECONNRESET      ECONNRESET
#define STU_ENOTCONN        ENOTCONN
#define STU_ETIMEDOUT       ETIMEDOUT
#define STU_ECONNREFUSED    ECONNREFUSED
#define STU_ENAMETOOLONG    ENAMETOOLONG
#define STU_ENETDOWN        ENETDOWN
#define STU_ENETUNREACH     ENETUNREACH
#define STU_EHOSTDOWN       EHOSTDOWN
#define STU_EHOSTUNREACH    EHOSTUNREACH
#define STU_ENOSYS          ENOSYS
#define STU_ECANCELED       ECANCELED
#define STU_EILSEQ          EILSEQ
#define STU_ENOMOREFILES    0
#define STU_ELOOP           ELOOP
#define STU_EBADF           EBADF

#if (STU_HAVE_OPENAT)
#define STU_EMLINK          EMLINK
#endif

#if (__hpux__)
#define STU_EAGAIN          EWOULDBLOCK
#else
#define STU_EAGAIN          EAGAIN
#endif

#ifndef STU_SYS_NERR
#define STU_SYS_NERR        133
#endif

#define stu_errno                  errno
#define stu_socket_errno           errno
#define stu_set_errno(err)         errno = err
#define stu_set_socket_errno(err)  errno = err

typedef struct {
	u_char     id;
	stu_str_t *explain;
} stu_error_t;

u_char      *stu_strerror(stu_err_t err, u_char *explain, size_t size);
stu_int32_t  stu_strerror_init(void);

#endif /* STUDEASE_CN_CORE_UNIX_STU_ERRNO_H_ */
