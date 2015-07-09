#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "set.h"

void set_new(set_struct *set, set_elements_equals_fn equals) {
	set->head = NULL;
	set->equals = equals;
}

bool set_contains(const set_struct *set, const void *element) {
	set_node_struct *node = set->head;
	while (node != NULL) {
		if (set->equals(node->element, element)) return true;
		node = node->next;
	}
	return false;
}

int set_add_new(set_struct *set, const void *element) {
	set_node_struct *node = malloc(sizeof(set_node_struct));
	if (node == NULL) {perror("malloc"); return -1;}
	node->element = element;
	node->next = set->head;
	set->head = node;
	return 0;
}

bool set_remove(set_struct *set, const void *element) {
	set_node_struct **node_p = &set->head;
	while(*node_p != NULL) {
		if (set->equals((*node_p)->element, element)) break;
		node_p = &(*node_p)->next;
	}
	if (*node_p == NULL) return false;
	set_node_struct *node = *node_p;
	*node_p = node->next;
	free(node);
	return true;
}

void set_clear(set_struct *set) {
	set_node_struct *node = set->head;
	set_node_struct *next;
	while (node != NULL) {
		next = node->next;
		free(node);
		node = next;
	}
}

bool set_is_empty(const set_struct *set) {
	return (set->head == NULL);
}

void *set_extract_any_element(set_struct *set) {
	set_node_struct *node = set->head;
	assert(node != NULL);
	set->head = node->next;
	void *element = (void *)node->element;
	free(node);
	return element;
}

