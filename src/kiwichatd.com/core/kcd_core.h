/*
 * kcd_core.h
 *
 *  Created on: 2017年11月17日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_CORE_H_
#define KIWICHATD_COM_CORE_KCD_CORE_H_

#include "../../studease.cn/websocket/stu_websocket.h"

typedef enum {
	PREVIEW    = 0x00,
	ENTERPRISE = 0x01
} kcd_edition_t;

typedef struct kcd_channel_s kcd_channel_t;

#include "kcd_license.h"
#include "kcd_conf.h"
#include "kcd_protocol.h"
#include "kcd_user.h"
#include "kcd_message.h"
#include "kcd_channel.h"
#include "kcd_request.h"
#include "kcd_cycle.h"
#include "kcd_process.h"

#endif /* KIWICHATD_COM_CORE_KCD_CORE_H_ */
