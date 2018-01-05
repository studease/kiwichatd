/*
 * stu_rbtree.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_RBTREE_H_
#define STUDEASE_CN_CORE_STU_RBTREE_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_RBTREE_NODE_RED   0x01
#define STU_RBTREE_NODE_BLACK 0x00

typedef stu_uint64_t  stu_rbtree_key_t;
typedef stu_int64_t   stu_rbtree_key_int_t;

typedef struct stu_rbtree_node_s  stu_rbtree_node_t;

typedef void               (*stu_rbtree_insert_pt)(stu_rbtree_node_t *root, stu_rbtree_node_t *node, stu_rbtree_node_t *sentinel);
typedef stu_rbtree_node_t *(*stu_rbtree_search_pt)(stu_rbtree_node_t *root, stu_rbtree_key_t key, stu_rbtree_node_t *sentinel);

struct stu_rbtree_node_s {
	stu_rbtree_key_t      key;
	stu_rbtree_node_t    *left;
	stu_rbtree_node_t    *right;
	stu_rbtree_node_t    *parent;
	u_char                color;
	u_char                data;
};

typedef struct {
	stu_rbtree_node_t    *root;
	stu_rbtree_node_t    *sentinel;
	stu_rbtree_insert_pt  insert;
	stu_rbtree_search_pt  search;
} stu_rbtree_t;


#define stu_rbtree_init(tree, s, i, f) \
	stu_rbtree_sentinel_init(s);        \
	(tree)->root = s;                   \
	(tree)->sentinel = s;               \
	(tree)->insert = i;                 \
	(tree)->search = f

void  stu_rbtree_insert(stu_rbtree_t *tree, stu_rbtree_node_t *node);
void  stu_rbtree_delete(stu_rbtree_t *tree, stu_rbtree_node_t *node);

void  stu_rbtree_insert_value(stu_rbtree_node_t *root, stu_rbtree_node_t *node, stu_rbtree_node_t *sentinel);
void  stu_rbtree_insert_timer_value(stu_rbtree_node_t *root, stu_rbtree_node_t *node, stu_rbtree_node_t *sentinel);

stu_rbtree_node_t *stu_rbtree_search(stu_rbtree_t *tree, stu_rbtree_key_t key);
stu_rbtree_node_t *stu_rbtree_search_value(stu_rbtree_node_t *root, stu_rbtree_key_t key, stu_rbtree_node_t *sentinel);

#define stu_rbtree_red(node)           ((node)->color = STU_RBTREE_NODE_RED)
#define stu_rbtree_black(node)         ((node)->color = STU_RBTREE_NODE_BLACK)
#define stu_rbtree_is_red(node)        ((node)->color)
#define stu_rbtree_is_black(node)      (!stu_rbtree_is_red(node))
#define stu_rbtree_copy_color(n1, n2)  (n1->color = n2->color)

/* a sentinel must be black */
#define stu_rbtree_sentinel_init(node)  stu_rbtree_black(node)


static stu_inline stu_rbtree_node_t *
stu_rbtree_min(stu_rbtree_node_t *node, stu_rbtree_node_t *sentinel) {
	while (node->left != sentinel) {
		node = node->left;
	}

	return node;
}

#endif /* STUDEASE_CN_CORE_STU_RBTREE_H_ */
