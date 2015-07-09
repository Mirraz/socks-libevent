#ifndef SET_H
#define SET_H

#include <stdbool.h>

/* linked list */

struct set_node_struct_;
typedef struct set_node_struct_ set_node_struct;
struct set_node_struct_ {
	const void *element;
	set_node_struct *next;
};

typedef bool (*set_elements_equals_fn)(const void *element1, const void *element2);

typedef struct {
	set_node_struct *head;
	set_elements_equals_fn equals;
} set_struct;

void set_new(set_struct *set, set_elements_equals_fn equals);
bool set_contains(const set_struct *set, const void *element);
int set_add_new(set_struct *set, const void *element);   // element must not already be in set
bool set_remove(set_struct *set, const void *element);
void set_clear(set_struct *set);
bool set_is_empty(const set_struct *set);
void *set_extract_any_element(set_struct *set);   // set must not be empty

#endif/*SET_H*/
