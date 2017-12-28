/*
 * kcd_message.h
 *
 *  Created on: 2017年12月20日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_MESSAGE_H_
#define KIWICHATD_COM_CORE_KCD_MESSAGE_H_

#include "kcd_core.h"

typedef struct {
	stu_rwlock_t  lock;
	stu_file_t    file;
	stu_uint32_t  message_n;
} kcd_message_t;

stu_int32_t  kcd_message_init(kcd_message_t *m, stu_str_t * path, stu_str_t *id);

off_t        kcd_message_push(kcd_message_t *m, u_char *data, size_t size);
u_char      *kcd_message_read(kcd_message_t *m, u_char *dst, off_t *offset);

#endif /* KIWICHATD_COM_CORE_KCD_MESSAGE_H_ */
