/*
 * stu_timer.h
 *
 *  Created on: 2017骞�11鏈�16鏃�
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_TIMER_H_
#define STUDEASE_CN_CORE_STU_TIMER_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_TIMER_MAXIMUM     1024
#define STU_TIMER_INFINITE   (stu_msec_t) -1
#define STU_TIMER_LAZY_DELAY  300

/* used in stu_log_debug() */
#define stu_timer_ident(p)   ((stu_connection_t *) (p))->fd

typedef struct {
	stu_mutex_t        lock;

	stu_rbtree_t       tree;
	stu_rbtree_node_t  sentinel;
} stu_timer_t;


stu_int32_t  stu_timer_init(void);
stu_msec_t   stu_timer_find(void);
void         stu_timer_expire(void);
void         stu_timer_cancel(void);

void         stu_timer_add(stu_event_t *ev, stu_msec_t timer);
void         stu_timer_add_locked(stu_event_t *ev, stu_msec_t timer);

void         stu_timer_del(stu_event_t *ev);
void         stu_timer_del_locked(stu_event_t *ev);

#endif /* STUDEASE_CN_CORE_STU_TIMER_H_ */
