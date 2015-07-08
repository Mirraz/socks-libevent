#ifndef STACK_H
#define STACK_H

#include <stdbool.h>

struct stack_node_struct_;
typedef struct stack_node_struct_ stack_node_struct;
struct stack_node_struct_ {
	const void *element;
	stack_node_struct *next;
};

typedef struct {
	stack_node_struct *head;
} stack_struct;

void stack_new(stack_struct *stack);
bool stack_is_empty(const stack_struct *stack);
int stack_push(stack_struct *stack, const void *element);
void *stack_pop(stack_struct *stack);
void *stack_front(const stack_struct *stack);
void stack_clear(stack_struct *stack);

#endif/*STACK_H*/

