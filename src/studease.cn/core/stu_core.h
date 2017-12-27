/*
 * core.h
 *
 *  Created on: 2017年10月20日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_CORE_H_
#define STUDEASE_CN_CORE_STU_CORE_H_

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define stu_signal_helper(n)   SIG##n
#define stu_signal_value(n)    stu_signal_helper(n)

#define STU_SHUTDOWN_SIGNAL    QUIT
#define STU_REOPEN_SIGNAL      USR1
#define STU_CHANGEBIN_SIGNAL   USR2

/* Signed.  */
typedef signed char            stu_int8_t;
typedef short int              stu_int16_t;
typedef int                    stu_int32_t;
# if __WORDSIZE == 64
typedef long int               stu_int64_t;
# else
__extension__
typedef long long int          stu_int64_t;
# endif

/* Unsigned.  */
typedef unsigned char          stu_uint8_t;
typedef unsigned short int     stu_uint16_t;
typedef unsigned int           stu_uint32_t;
#if __WORDSIZE == 64
typedef unsigned long int      stu_uint64_t;
#else
__extension__
typedef unsigned long long int stu_uint64_t;
#endif

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


#define stu_abs(value)         (((value) >= 0) ? (value) : - (value))
#define stu_max(val1, val2)    ((val1 < val2) ? (val2) : (val1))
#define stu_min(val1, val2)    ((val1 > val2) ? (val2) : (val1))


#define CR                     (u_char) '\r'
#define LF                     (u_char) '\n'
#define HT                     (u_char) '\t'
#define CRLF                   "\r\n"
#define LFHT                   "\n\t"

#define stu_inline             inline


typedef struct stu_upstream_s stu_upstream_t;

#include "stu_string.h"
#include "stu_queue.h"
#include "stu_file.h"
#include "stu_mutex.h"
#include "stu_rwlock.h"
#include "stu_spinlock.h"
#include "stu_rbtree.h"
#include "stu_time.h"
#include "stu_atomic.h"
#include "stu_log.h"
#include "stu_errno.h"
#include "stu_shmem.h"
#include "stu_base64.h"
#include "stu_sha1.h"
#include "stu_md5.h"
#include "stu_rsa.h"
#include "stu_json.h"
#include "stu_alloc.h"
#include "stu_palloc.h"
#include "stu_buf.h"
#include "stu_list.h"
#include "stu_hash.h"
#include "stu_inet.h"
#include "stu_socket.h"
#include "../event/stu_event.h"
#include "stu_connection.h"
#include "stu_upstream.h"
#include "stu_timer.h"
#include "stu_thread.h"
#include "stu_process.h"
#include "stu_channel.h"
#include "../utils/stu_hardware.h"

#endif /* STUDEASE_CN_CORE_STU_CORE_H_ */
