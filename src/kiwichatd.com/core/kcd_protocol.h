/*
 * kcd_protocol.h
 *
 *  Created on: 2017年11月17日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_PROTOCOL_H_
#define KIWICHATD_COM_CORE_KCD_PROTOCOL_H_

#include "kcd_core.h"

#define KCD_PROTOCOL_UNI      0x00
#define KCD_PROTOCOL_MULTI    0x01
#define KCD_PROTOCOL_HISTORY  0x02

extern stu_str_t  KCD_PROTOCOL_CMD;
extern stu_str_t  KCD_PROTOCOL_RAW;
extern stu_str_t  KCD_PROTOCOL_REQ;
extern stu_str_t  KCD_PROTOCOL_DATA;
extern stu_str_t  KCD_PROTOCOL_TYPE;
extern stu_str_t  KCD_PROTOCOL_CHANNEL;
extern stu_str_t  KCD_PROTOCOL_USER;
extern stu_str_t  KCD_PROTOCOL_ID;
extern stu_str_t  KCD_PROTOCOL_NAME;
extern stu_str_t  KCD_PROTOCOL_ICON;
extern stu_str_t  KCD_PROTOCOL_ROLE;
extern stu_str_t  KCD_PROTOCOL_STATE;
extern stu_str_t  KCD_PROTOCOL_STATUS;
extern stu_str_t  KCD_PROTOCOL_TOTAL;
extern stu_str_t  KCD_PROTOCOL_ERROR;
extern stu_str_t  KCD_PROTOCOL_CODE;

extern stu_str_t  KCD_PROTOCOL_CMD_TEXT;
extern stu_str_t  KCD_PROTOCOL_CMD_HISTORY;
extern stu_str_t  KCD_PROTOCOL_CMD_MUTE;
extern stu_str_t  KCD_PROTOCOL_CMD_KICKOUT;
extern stu_str_t  KCD_PROTOCOL_CMD_EXTERN;
extern stu_str_t  KCD_PROTOCOL_CMD_PING;
extern stu_str_t  KCD_PROTOCOL_CMD_PONG;

extern stu_str_t  KCD_PROTOCOL_RAW_IDENT;
extern stu_str_t  KCD_PROTOCOL_RAW_TEXT;
extern stu_str_t  KCD_PROTOCOL_RAW_HISTORY;
extern stu_str_t  KCD_PROTOCOL_RAW_JOIN;
extern stu_str_t  KCD_PROTOCOL_RAW_LEFT;
extern stu_str_t  KCD_PROTOCOL_RAW_USERS;
extern stu_str_t  KCD_PROTOCOL_RAW_MUTE;
extern stu_str_t  KCD_PROTOCOL_RAW_KICKOUT;
extern stu_str_t  KCD_PROTOCOL_RAW_ERROR;

#endif /* KIWICHATD_COM_CORE_KCD_PROTOCOL_H_ */
