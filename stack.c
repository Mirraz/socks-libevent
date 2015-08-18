#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "stack.h"

void stack_new(stack_struct *stack) {
	stack->head = NULL;
}

bool stack_is_empty(const stack_struct *stack) {
	return stack->head == NULL;
}

int stack_push(stack_struct *stack, const void *element) {
	stack_node_struct *node = malloc(sizeof(stack_node_struct));
	if (node == NULL) {perror("malloc"); return -1;}
	node->element = element;
	node->next = stack->head;
	stack->head = node;
	return 0;
}

void *stack_pop(stack_struct *stack) {
	assert(!stack_is_empty(stack));
	stack_node_struct *node = stack->head;
	stack->head = node->next;
	const void *element = node->element;
	free(node);
	return (void *)element;
}

void *stack_front(const stack_struct *stack) {
	assert(!stack_is_empty(stack));
	return (void *)(stack->head->element);
}

void stack_clear(stack_struct *stack) {
	while (!stack_is_empty(stack)) stack_pop(stack);
}

