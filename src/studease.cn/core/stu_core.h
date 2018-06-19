/*
 * core.h
 *
 *  Created on: 2017骞�10鏈�20鏃�
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_CORE_H_
#define STUDEASE_CN_CORE_STU_CORE_H_

#if (STU_LINUX)
#include <arpa/inet.h>
#include <net/if.h>
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if (STU_LINUX)
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#if (STU_WIN32)
#include <mswsock.h>
#include <winsock2.h>
#include <iphlpapi.h>
#endif

#if !(STU_WIN32)

#define stu_signal_helper(n)   SIG##n
#define stu_signal_value(n)    stu_signal_helper(n)

#define STU_SHUTDOWN_SIGNAL    QUIT
#define STU_REOPEN_SIGNAL      USR1
#define STU_CHANGEBIN_SIGNAL   USR2

#endif

#define STU_INT32_LEN         (sizeof("-2147483648") - 1)
#define STU_INT64_LEN         (sizeof("-9223372036854775808") - 1)

/* Signed.  */
typedef signed char            stu_int8_t;
typedef short                  stu_int16_t;
typedef int                    stu_int32_t;
# if __WORDSIZE == 64
typedef long                   stu_int64_t;
# else
__extension__
typedef long long              stu_int64_t;
# endif

/* Unsigned.  */
typedef unsigned char          stu_uint8_t;
typedef unsigned short         stu_uint16_t;
typedef unsigned int           stu_uint32_t;
#if __WORDSIZE == 64
typedef unsigned long          stu_uint64_t;
#else
__extension__
typedef unsigned long long     stu_uint64_t;
#endif

typedef int64_t                stu_off_t;

typedef double                 stu_double_t;
typedef unsigned char          stu_bool_t;

#define TRUE                   1
#define FALSE                  0


#define STU_ALIGNMENT          sizeof(unsigned long)

#define stu_align(d, a)        (((d) + (a - 1)) & ~(a - 1))
#define stu_align_ptr(p, a)    \
	(u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


#define STU_OK                 0
#define STU_ERROR             -1
#define STU_AGAIN             -2
#define STU_BUSY              -3
#define STU_DONE              -4
#define STU_DECLINED          -5
#define STU_ABORT             -6


#define stu_abs(value)      (((value) >= 0) ? (value) : - (value))
#define stu_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define stu_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))


#define CR                    (u_char) '\r'
#define LF                    (u_char) '\n'
#define HT                    (u_char) '\t'
#define CRLF                  "\r\n"
#define LFHT                  "\n\t"

#define stu_inline             inline


typedef struct    stu_file_s        stu_file_t;
typedef struct    stu_event_s       stu_event_t;
typedef struct    stu_connection_s  stu_connection_t;
typedef struct    stu_upstream_s    stu_upstream_t;

typedef void    (*stu_event_handler_pt)(stu_event_t *ev);

typedef ssize_t (*stu_recv_pt)(stu_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*stu_send_pt)(stu_connection_t *c, u_char *buf, size_t size);


#include "stu_string.h"
#include "stu_queue.h"
#include "stu_mutex.h"
#include "stu_rwlock.h"
#include "stu_spinlock.h"
#include "stu_rbtree.h"
#if (STU_LINUX)
#include "unix/stu_atomic.h"
#include "unix/stu_errno.h"
#include "unix/stu_shmem.h"
#include "unix/stu_os.h"
#include "unix/stu_time.h"
#include "unix/stu_file.h"
#else
#include "win32/stu_atomic.h"
#include "win32/stu_errno.h"
#include "win32/stu_shmem.h"
#include "win32/stu_os.h"
#include "win32/stu_time.h"
#include "win32/stu_file.h"
#endif
#include "stu_times.h"
#include "stu_files.h"
#include "stu_log.h"
#include "stu_base64.h"
#include "stu_sha1.h"
#include "stu_hmac.h"
#include "stu_md5.h"
#include "stu_rsa.h"
#include "stu_json.h"
#include "stu_alloc.h"
#include "stu_palloc.h"
#include "stu_buf.h"
#include "stu_list.h"
#include "stu_hash.h"
#if (STU_LINUX)
#include "unix/stu_socket.h"
#else
#include "win32/stu_socket.h"
#endif
#include "stu_inet.h"
#include "event/stu_event.h"
#include "stu_connection.h"
#include "stu_upstream.h"
#include "stu_timer.h"
#include "stu_mq.h"
#include "stu_thread.h"
#if (STU_LINUX)
#include "unix/stu_process.h"
#include "unix/stu_channel.h"
#else
#include "win32/stu_process.h"
#endif
#include "../utils/stu_utils.h"

#endif /* STUDEASE_CN_CORE_STU_CORE_H_ */
