/*
 * kcd_protocol.c
 *
 *  Created on: 2017年11月17日
 *      Author: Tony Lau
 */

#include "kcd_core.h"

stu_str_t  KCD_PROTOCOL_CMD         = stu_string("cmd");
stu_str_t  KCD_PROTOCOL_RAW         = stu_string("raw");
stu_str_t  KCD_PROTOCOL_REQ         = stu_string("req");
stu_str_t  KCD_PROTOCOL_DATA        = stu_string("data");
stu_str_t  KCD_PROTOCOL_TYPE        = stu_string("type");
stu_str_t  KCD_PROTOCOL_CHANNEL     = stu_string("channel");
stu_str_t  KCD_PROTOCOL_USER        = stu_string("user");
stu_str_t  KCD_PROTOCOL_ID          = stu_string("id");
stu_str_t  KCD_PROTOCOL_NAME        = stu_string("name");
stu_str_t  KCD_PROTOCOL_ICON        = stu_string("icon");
stu_str_t  KCD_PROTOCOL_ROLE        = stu_string("role");
stu_str_t  KCD_PROTOCOL_STATE       = stu_string("state");
stu_str_t  KCD_PROTOCOL_STATUS      = stu_string("status");
stu_str_t  KCD_PROTOCOL_TOTAL       = stu_string("total");
stu_str_t  KCD_PROTOCOL_ERROR       = stu_string("error");
stu_str_t  KCD_PROTOCOL_CODE        = stu_string("code");

stu_str_t  KCD_PROTOCOL_CMD_TEXT    = stu_string("text");
stu_str_t  KCD_PROTOCOL_CMD_MUTE    = stu_string("mute");
stu_str_t  KCD_PROTOCOL_CMD_KICKOUT = stu_string("kickout");
stu_str_t  KCD_PROTOCOL_CMD_EXTERN  = stu_string("extern");
stu_str_t  KCD_PROTOCOL_CMD_PING    = stu_string("ping");
stu_str_t  KCD_PROTOCOL_CMD_PONG    = stu_string("pong");

stu_str_t  KCD_PROTOCOL_RAW_IDENT   = stu_string("ident");
stu_str_t  KCD_PROTOCOL_RAW_TEXT    = stu_string("text");
stu_str_t  KCD_PROTOCOL_RAW_JOIN    = stu_string("join");
stu_str_t  KCD_PROTOCOL_RAW_LEFT    = stu_string("left");
stu_str_t  KCD_PROTOCOL_RAW_USERS   = stu_string("users");
stu_str_t  KCD_PROTOCOL_RAW_MUTE    = stu_string("mute");
stu_str_t  KCD_PROTOCOL_RAW_KICKOUT = stu_string("kickout");
stu_str_t  KCD_PROTOCOL_RAW_ERROR   = stu_string("error");
