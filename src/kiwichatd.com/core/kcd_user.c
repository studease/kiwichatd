/*
 * kcd_user.c
 *
 *  Created on: 2017年12月1日
 *      Author: Tony Lau
 */

#include "kcd_core.h"

static stu_uint16_t stu_user_get_interval(stu_uint8_t role);


stu_int32_t
kcd_user_init(kcd_user_t *user, stu_str_t *id, stu_str_t *name, stu_str_t *icon, stu_str_t *token, stu_str_t *chan) {
	if (user->connection == NULL
			|| user->connection->timedout || user->connection->error
			|| user->connection->close || user->connection->destroyed) {
		return STU_ABORT;
	}

	if (user->id.data == NULL) {
		user->id.data = stu_pcalloc(user->connection->pool, KCD_USER_ID_MAX_LEN + 1);
		if (user->id.data == NULL) {
			return STU_ERROR;
		}
	}

	if (user->name.data == NULL) {
		user->name.data = stu_pcalloc(user->connection->pool, KCD_USER_NAME_MAX_LEN + 1);
		if (user->name.data == NULL) {
			return STU_ERROR;
		}
	}

	if (user->icon.data == NULL) {
		user->icon.data = stu_pcalloc(user->connection->pool, KCD_USER_ICON_MAX_LEN + 1);
		if (user->icon.data == NULL) {
			return STU_ERROR;
		}
	}

	if (id && id->len) {
		stu_strncpy(user->id.data, id->data, id->len);
		user->id.len = id->len;
	}
	if (name && name->len) {
		stu_strncpy(user->name.data, name->data, name->len);
		user->name.len = name->len;
	}
	if (icon && icon->len) {
		stu_strncpy(user->icon.data, icon->data, icon->len);
		user->icon.len = icon->len;
	}

	if (token && token->len) {
		if (user->token.data == NULL) {
			user->token.data = stu_pcalloc(user->connection->pool, KCD_USER_TOKEN_MAX_LEN + 1);
			if (user->token.data == NULL) {
				return STU_ERROR;
			}
		}

		stu_strncpy(user->token.data, token->data, token->len);
		user->token.len = token->len;
	}

	if (chan && chan->len) {
		if (user->chan.data == NULL) {
			user->chan.data = stu_pcalloc(user->connection->pool, KCD_CHANNEL_ID_MAX_LEN + 1);
			if (user->chan.data == NULL) {
				return STU_ERROR;
			}
		}

		stu_strncpy(user->chan.data, chan->data, chan->len);
		user->chan.len = chan->len;
	}

	return STU_OK;
}

void
kcd_user_set_role(kcd_user_t *user, stu_uint8_t role) {
	user->role = role;
	user->interval = stu_user_get_interval(role);
}

static stu_uint16_t
stu_user_get_interval(stu_uint8_t role) {
	stu_uint16_t  n, vip;

	n = 2000;

	if (role == 0) {
		return n;
	}

	if (role & 0xF0) {
		return 0;
	}

	n *= .5;

	vip = role >> 1;
	n -= vip * 100;

	return n;
}
