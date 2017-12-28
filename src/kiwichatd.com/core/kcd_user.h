/*
 * kcd_user.h
 *
 *  Created on: 2017年12月1日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_USER_H_
#define KIWICHATD_COM_CORE_KCD_USER_H_

#include "kcd_core.h"

#define KCD_USER_LIST_DEFAULT_SIZE 1024

#define KCD_USER_TOKEN_MAX_LEN     256
#define KCD_USER_ID_MAX_LEN        16
#define KCD_USER_NAME_MAX_LEN      32
#define KCD_USER_ICON_MAX_LEN      64

#define STU_USER_ROLE_VISITOR      0x00
#define STU_USER_ROLE_NORMAL       0x01
#define STU_USER_ROLE_VIP          0x0E
#define STU_USER_ROLE_ASSISTANT    0x10
#define STU_USER_ROLE_SECRETARY    0x20
#define STU_USER_ROLE_ANCHOR       0x30
#define STU_USER_ROLE_ADMIN        0x40
#define STU_USER_ROLE_SU_ADMIN     0x80
#define STU_USER_ROLE_SYSTEM       0xC0

typedef struct {
	stu_str_t         id;
	stu_str_t         name;
	stu_str_t         icon;
	stu_uint8_t       role;
	stu_uint16_t      interval; // ms
	stu_uint64_t      active;   // ms

	stu_str_t         token;
	stu_str_t         chan;

	stu_connection_t *connection;
	kcd_channel_t    *channel;

	off_t             history;
	off_t             current;
} kcd_user_t;

stu_int32_t  kcd_user_init(kcd_user_t *user, stu_str_t *id, stu_str_t *name, stu_str_t *icon, stu_str_t *token, stu_str_t *chan);
void         kcd_user_set_role(kcd_user_t *user, stu_uint8_t role);

#endif /* KIWICHATD_COM_CORE_KCD_USER_H_ */
