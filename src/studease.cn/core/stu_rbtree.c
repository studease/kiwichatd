/*
 * stu_rbtree.c
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

static stu_inline void stu_rbtree_left_rotate(stu_rbtree_node_t **root, stu_rbtree_node_t *sentinel, stu_rbtree_node_t *node);
static stu_inline void stu_rbtree_right_rotate(stu_rbtree_node_t **root, stu_rbtree_node_t *sentinel, stu_rbtree_node_t *node);


void
stu_rbtree_insert(stu_rbtree_t *tree, stu_rbtree_node_t *node) {
	stu_rbtree_node_t **root, *tmp, *sentinel;

	/* a binary tree insert */
	root = (stu_rbtree_node_t **) &tree->root;
	sentinel = tree->sentinel;

	if (*root == sentinel) {
		node->parent = NULL;
		node->left = sentinel;
		node->right = sentinel;
		stu_rbtree_black(node);
		*root = node;

		return;
	}

	tree->insert(*root, node, sentinel);

	/* re-balance tree */
	while (node != *root && stu_rbtree_is_red(node->parent)) {
		if (node->parent == node->parent->parent->left) {
			tmp = node->parent->parent->right;
			if (stu_rbtree_is_red(tmp)) {
				stu_rbtree_black(node->parent);
				stu_rbtree_black(tmp);
				stu_rbtree_red(node->parent->parent);
				node = node->parent->parent;
			} else {
				if (node == node->parent->right) {
					node = node->parent;
					stu_rbtree_left_rotate(root, sentinel, node);
				}

				stu_rbtree_black(node->parent);
				stu_rbtree_red(node->parent->parent);
				stu_rbtree_right_rotate(root, sentinel, node->parent->parent);
			}
		} else {
			tmp = node->parent->parent->left;
			if (stu_rbtree_is_red(tmp)) {
				stu_rbtree_black(node->parent);
				stu_rbtree_black(tmp);
				stu_rbtree_red(node->parent->parent);
				node = node->parent->parent;
			} else {
				if (node == node->parent->left) {
					node = node->parent;
					stu_rbtree_right_rotate(root, sentinel, node);
				}

				stu_rbtree_black(node->parent);
				stu_rbtree_red(node->parent->parent);
				stu_rbtree_left_rotate(root, sentinel, node->parent->parent);
			}
		}
	}

	stu_rbtree_black(*root);
}

void
stu_rbtree_insert_value(stu_rbtree_node_t *tmp, stu_rbtree_node_t *node, stu_rbtree_node_t *sentinel) {
	stu_rbtree_node_t **p;

	for ( ;; ) {
		p = (node->key < tmp->key) ? &tmp->left : &tmp->right;
		if (*p == sentinel) {
			break;
		}

		tmp = *p;
	}

	*p = node;
	node->parent = tmp;
	node->left = sentinel;
	node->right = sentinel;
	stu_rbtree_red(node);
}

void
stu_rbtree_insert_timer_value(stu_rbtree_node_t *tmp, stu_rbtree_node_t *node, stu_rbtree_node_t *sentinel) {
	stu_rbtree_node_t **p;

	for ( ;; ) {
		/*
		 * Timer values
		 * 1) are spread in small range, usually several minutes,
		 * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
		 * The comparison takes into account that overflow.
		 */

		/* node->key < tmp->key */
		p = ((stu_rbtree_key_int_t) (node->key - tmp->key) < 0) ? &tmp->left : &tmp->right;
		if (*p == sentinel) {
			break;
		}

		tmp = *p;
	}

	*p = node;
	node->parent = tmp;
	node->left = sentinel;
	node->right = sentinel;
	stu_rbtree_red(node);
}

stu_rbtree_node_t *
stu_rbtree_search(stu_rbtree_t *tree, stu_rbtree_key_t key) {
	stu_rbtree_node_t **root, *sentinel;

	/* a binary tree search */
	root = (stu_rbtree_node_t **) &tree->root;
	sentinel = tree->sentinel;

	if (*root == sentinel) {
		return NULL;
	}

	return tree->search(*root, key, sentinel);
}

stu_rbtree_node_t *
stu_rbtree_search_value(stu_rbtree_node_t *tmp, stu_rbtree_key_t key, stu_rbtree_node_t *sentinel) {
	stu_rbtree_node_t **p;

	for ( ;; ) {
		if (key == tmp->key) {
			return tmp;
		}

		p = (key < tmp->key) ? &tmp->left : &tmp->right;
		if (*p == sentinel) {
			break;
		}

		tmp = *p;
	}

	return NULL;
}

void
stu_rbtree_delete(stu_rbtree_t *tree, stu_rbtree_node_t *node) {
	stu_rbtree_node_t **root, *sentinel, *subst, *tmp, *w;
	stu_uint32_t        red;

	/* a binary tree delete */
	root = (stu_rbtree_node_t **) &tree->root;
	sentinel = tree->sentinel;

	if (node->left == sentinel) {
		tmp = node->right;
		subst = node;
	} else if (node->right == sentinel) {
		tmp = node->left;
		subst = node;
	} else {
		subst = stu_rbtree_min(node->right, sentinel);
		if (subst->left != sentinel) {
			tmp = subst->left;
		} else {
			tmp = subst->right;
		}
	}

	if (subst == *root) {
		*root = tmp;
		stu_rbtree_black(tmp);

		/* DEBUG stuff */
		node->left = NULL;
		node->right = NULL;
		node->parent = NULL;
		node->key = 0;

		return;
	}

	red = stu_rbtree_is_red(subst);

	if (subst == subst->parent->left) {
		subst->parent->left = tmp;
	} else {
		subst->parent->right = tmp;
	}

	if (subst == node) {
		tmp->parent = subst->parent;
	} else {
		if (subst->parent == node) {
			tmp->parent = subst;
		} else {
			tmp->parent = subst->parent;
		}

		subst->left = node->left;
		subst->right = node->right;
		subst->parent = node->parent;
		stu_rbtree_copy_color(subst, node);

		if (node == *root) {
			*root = subst;
		} else {
			if (node == node->parent->left) {
				node->parent->left = subst;
			} else {
				node->parent->right = subst;
			}
		}

		if (subst->left != sentinel) {
			subst->left->parent = subst;
		}

		if (subst->right != sentinel) {
			subst->right->parent = subst;
		}
	}

	/* DEBUG stuff */
	node->left = NULL;
	node->right = NULL;
	node->parent = NULL;
	node->key = 0;

	if (red) {
		return;
	}

	/* a delete fixup */
	while (tmp != *root && stu_rbtree_is_black(tmp)) {
		if (tmp == tmp->parent->left) {
			w = tmp->parent->right;
			if (stu_rbtree_is_red(w)) {
				stu_rbtree_black(w);
				stu_rbtree_red(tmp->parent);
				stu_rbtree_left_rotate(root, sentinel, tmp->parent);
				w = tmp->parent->right;
			}

			if (stu_rbtree_is_black(w->left) && stu_rbtree_is_black(w->right)) {
				stu_rbtree_red(w);
				tmp = tmp->parent;
			} else {
				if (stu_rbtree_is_black(w->right)) {
					stu_rbtree_black(w->left);
					stu_rbtree_red(w);
					stu_rbtree_right_rotate(root, sentinel, w);
					w = tmp->parent->right;
				}

				stu_rbtree_copy_color(w, tmp->parent);
				stu_rbtree_black(tmp->parent);
				stu_rbtree_black(w->right);
				stu_rbtree_left_rotate(root, sentinel, tmp->parent);
				tmp = *root;
			}
		} else {
			w = tmp->parent->left;
			if (stu_rbtree_is_red(w)) {
				stu_rbtree_black(w);
				stu_rbtree_red(tmp->parent);
				stu_rbtree_right_rotate(root, sentinel, tmp->parent);
				w = tmp->parent->left;
			}

			if (stu_rbtree_is_black(w->left) && stu_rbtree_is_black(w->right)) {
				stu_rbtree_red(w);
				tmp = tmp->parent;
			} else {
				if (stu_rbtree_is_black(w->left)) {
					stu_rbtree_black(w->right);
					stu_rbtree_red(w);
					stu_rbtree_left_rotate(root, sentinel, w);
					w = tmp->parent->left;
				}

				stu_rbtree_copy_color(w, tmp->parent);
				stu_rbtree_black(tmp->parent);
				stu_rbtree_black(w->left);
				stu_rbtree_right_rotate(root, sentinel, tmp->parent);
				tmp = *root;
			}
		}
	}

	stu_rbtree_black(tmp);
}


static stu_inline void
stu_rbtree_left_rotate(stu_rbtree_node_t **root, stu_rbtree_node_t *sentinel, stu_rbtree_node_t *node) {
	stu_rbtree_node_t *tmp;

	 /*
	   |                        |
	  x                  y
	  / \                      / \
	a   y  ---left-->  x   c
		/ \                 / \
	  b   c          a   b
	       (node = x)
	*/

	tmp = node->right;
	node->right = tmp->left;
	if (tmp->left != sentinel) {
		tmp->left->parent = node;
	}

	tmp->parent = node->parent;
	if (node == *root) {
		*root = tmp;
	} else if (node == node->parent->left) {
		node->parent->left = tmp;
	} else {
		node->parent->right = tmp;
	}

	tmp->left = node;
	node->parent = tmp;
}

static stu_inline void
stu_rbtree_right_rotate(stu_rbtree_node_t **root, stu_rbtree_node_t *sentinel, stu_rbtree_node_t *node) {
	stu_rbtree_node_t *tmp;

	/*
	   |                        |
	  x                  y
	  / \                      / \
	a   y  <--right--  x   c
		/ \                 / \
	  b   c          a   b
	       (node = y)
	*/

	tmp = node->left;
	node->left = tmp->right;
	if (tmp->right != sentinel) {
		tmp->right->parent = node;
	}

	tmp->parent = node->parent;
	if (node == *root) {
		*root = tmp;
	} else if (node == node->parent->right) {
		node->parent->right = tmp;
	} else {
		node->parent->left = tmp;
	}

	tmp->right = node;
	node->parent = tmp;
}
