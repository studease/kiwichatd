/*
 * stu_config.h
 *
 *  Created on: 2017年10月20日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_STU_CONFIG_H_
#define STUDEASE_CN_STU_CONFIG_H_

#define STU_LINUX                1
#define STU_WIN32                0

#if (STU_WIN32)
#define STU_HAVE_GETTIMEZONE     1
#else
#define STU_HAVE_GMTOFF          0
#endif

#define STU_HAVE_EPOLL           STU_LINUX
#define STU_HAVE_KQUEUE          0
#define STU_HAVE_IOCP            STU_WIN32

#define STU_HAVE_MAP_ANON        0
#define STU_HAVE_MAP_DEVZERO     0
#define STU_HAVE_SYSVSHM         1

#define STU_HAVE_PREAD           STU_LINUX
#define STU_HAVE_PWRITE          STU_LINUX
#define STU_HAVE_LOCALTIME_R     1
#define STU_HAVE_OPENSSL_EVP_H   1
#define STU_HAVE_OPENSSL_SHA1_H  1
#define STU_HAVE_OPENSSL_HMAC_H  1
#define STU_HAVE_OPENSSL_MD5_H   1
#define STU_HAVE_OPENSSL_RSA_H   1

#endif /* STUDEASE_CN_STU_CONFIG_H_ */
