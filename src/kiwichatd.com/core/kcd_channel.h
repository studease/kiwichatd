/*
 * kcd_channel.h
 *
 *  Created on: 2017年12月1日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_CHANNEL_H_
#define KIWICHATD_COM_CORE_KCD_CHANNEL_H_

#include "kcd_core.h"

#define KCD_CHANNEL_LIST_DEFAULT_SIZE          1024

#define KCD_CHANNEL_ID_MAX_LEN                 16

#define KCD_CHANNEL_PUSH_USER_DEFAULT_INTERVAL 30
#define KCD_CHANNEL_PUSH_STAT_DEFAULT_INTERVAL 300

struct kcd_channel_s {
	stu_str_t      id;
	stu_hash_t     userlist;
	stu_uint8_t    state;

	unsigned       record:1;
};

stu_int32_t  kcd_channel_init_hash();

stu_int32_t  kcd_channel_insert(stu_str_t *id, kcd_user_t *user);
stu_int32_t  kcd_channel_insert_locked(kcd_channel_t *ch, kcd_user_t *user);

void         kcd_channel_remove(kcd_channel_t *ch, kcd_user_t *user);
void         kcd_channel_remove_locked(kcd_channel_t *ch, kcd_user_t *user);

void         kcd_channel_broadcast(kcd_channel_t *ch, u_char *data, size_t len, off_t off);

stu_int32_t  kcd_channel_add_push_user_timer(stu_msec_t timer);
stu_int32_t  kcd_channel_add_push_stat_timer(stu_msec_t timer);

#endif /* KIWICHATD_COM_CORE_KCD_CHANNEL_H_ */
