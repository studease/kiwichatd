/*
 * stu_list.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_LIST_H_
#define STUDEASE_CN_CORE_STU_LIST_H_

#include "../stu_config.h"
#include "stu_core.h"

typedef void  (*stu_list_foreach_pt)(void *value);
typedef void  (*stu_list_cleanup_pt)(void *value);

typedef struct  stu_list_s stu_list_t;

typedef struct {
	stu_queue_t  queue;
	stu_list_t  *list;
	void        *value;
} stu_list_elt_t;

typedef struct {
	void *(*malloc_fn)(size_t size);
	void  (*free_fn)(void *ptr);
} stu_list_hooks_t;

struct stu_list_s {
	stu_mutex_t       lock;

	stu_list_elt_t    elts;
	stu_list_elt_t   *current;
	stu_uint32_t      length;

	stu_list_hooks_t  hooks;
};


void  stu_list_init(stu_list_t *list, stu_list_hooks_t *hooks);

stu_list_elt_t *stu_list_insert_before(stu_list_t *list, void *value, stu_list_elt_t *elt);
stu_list_elt_t *stu_list_insert_after(stu_list_t *list, void *value, stu_list_elt_t *elt);
stu_list_elt_t *stu_list_insert_head(stu_list_t *list, void *value);
stu_list_elt_t *stu_list_insert_tail(stu_list_t *list, void *value);

void *stu_list_remove(stu_list_t *list, stu_list_elt_t *elt);
void  stu_list_destroy(stu_list_t *list, stu_list_cleanup_pt cleanup);

void  stu_list_foreach(stu_list_t *list, stu_list_foreach_pt cb);

void  stu_list_empty_free_pt(void *ptr);

#endif /* STUDEASE_CN_CORE_STU_LIST_H_ */
