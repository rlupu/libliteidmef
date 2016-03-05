/*
   This file is part of the Libliteidmef Library. Libliteidmef provides 
	the API to the IDMEF-based alerting layer. 
	Copyright (C) 2015 Radu Lupu 

  	Libliteidmef library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   Libliteidmef library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the Libliteidmef Library; if not, see
   <http://www.gnu.org/licenses/>. 
*/

/*
 *	Multiple stacks enabled per process/thread;
 * multiple data types accepted; not reentrant.
 *
 * Author:		rlupu
 * Release:		2015/11/16
 */

#include "stack.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#define STACK_MAX_NO				16


static stack_t *_stack[STACK_MAX_NO];
static unsigned char initd = 0;

 

char stack_init(void){
	unsigned int i;
#ifdef STACK_DEBUG
	fprintf(stdout, "stack_init(): running ...\n");
#endif

	assert(initd == 0);	//TODO: replace with if(initd) ...

	for(i = 0; i < STACK_MAX_NO; i++)
		_stack[i] = NULL;

	initd = 1;

	return 0;
}

char stack_new(unsigned char dt, unsigned char sz, stack_t **s){
	unsigned int i;

#ifdef STACK_DEBUG
	fprintf(stdout, "stack_new(): running ...\n");
#endif

	for(i = 0; i < STACK_MAX_NO; i++)
		if(_stack[i] == NULL) break;

	assert(i < STACK_MAX_NO);

	_stack[i] = (stack_t *)malloc(sizeof(stack_t)*sizeof(unsigned char));
	assert(_stack[i] != NULL);

	if(dt == STACK_UCHAR){
		_stack[i]->data = (unsigned char *)malloc(sz*sizeof(unsigned char));
		assert(_stack[i]->data != NULL);
	}else if(dt == STACK_CHAR){
		_stack[i]->data = (char *)malloc(sz*sizeof(char));
		assert(_stack[i]->data != NULL);
	}else if(dt == STACK_UINT){
		_stack[i]->data = (unsigned int *)malloc(sz*sizeof(unsigned int));
		assert(_stack[i]->data != NULL);
	}else if(dt == STACK_INT){
		_stack[i]->data = (int *)malloc(sz*sizeof(int));
		assert(_stack[i]->data != NULL);
	}else if(dt == STACK_UCHAR_PTR){
		_stack[i]->data = (unsigned char **)malloc(sz*sizeof(unsigned char *));
		assert(_stack[i]->data != NULL);
	}else if(dt == STACK_UINT_PTR){
		_stack[i]->data = (unsigned int **)malloc(sz*sizeof(unsigned int *));
		assert(_stack[i]->data != NULL);
	}else if(dt == STACK_VOID_PTR){
		_stack[i]->data = (void **)malloc(sz*sizeof(void *));
		assert(_stack[i]->data != NULL);
	}else{
		fprintf(stdout, "%s(%d): out of room.\n", __FILE__, __LINE__);
		return (-1);
	}

	_stack[i]->dtype = dt;
	_stack[i]->size = sz;
	_stack[i]->left = sz;
	*s = _stack[i];
	
	return 0;
}

      
char stack_push(stack_t *s, any_t d){
#ifdef STACK_DEBUG
	fprintf(stdout, "stack_push(): running ...\n");
#endif

	assert(s != NULL);

	if(s->left <= 0){	//check out whether stack is full 
#ifdef STACK_DEBUG
		fprintf(stdout, "%s(%d): stack is full.\n", __FILE__, __LINE__);
#endif
		return (-1);
	}

	if(s->dtype == STACK_UCHAR)
		*( (unsigned char *)(s->data) + s->size - s->left) = *( (unsigned char *)d.value);
	else if(s->dtype == STACK_UINT)
		*( (unsigned int *)(s->data) + s->size - s->left) = *( (unsigned int *)d.value);
	else if(s->dtype == STACK_UCHAR_PTR)
		*( (unsigned char **)(s->data) + s->size - s->left) = *( (unsigned char **)d.value);
	else if(s->dtype == STACK_UINT_PTR)
		*( (unsigned int **)(s->data) + s->size - s->left) = *( (unsigned int **)d.value);
	else if(s->dtype == STACK_VOID_PTR)
		*( (void **)(s->data) + s->size - s->left) = *( (void **)d.value);

	//else ...

	s->left--;

	return (s->left);
}

char stack_pop(stack_t *s, any_t *pd){
#ifdef STACK_DEBUG
	fprintf(stdout, "stack_pop(): running ...\n");
#endif

	assert(s != NULL);

	if(s->left == s->size){		//check out whether stack is empty
		fprintf(stdout, "%s(%d): stack is empty.\n", __FILE__, __LINE__);
		return (0);
	}

	if(pd->value == NULL)
		return (++(s->left));

	if(s->dtype == STACK_UCHAR)
		*( (unsigned char *)(pd->value)) = *( (unsigned char *)(s->data) + s->size - s->left -1);
	else if(s->dtype == STACK_UINT)
		*( (unsigned int *)(pd->value)) = *( (unsigned int *)(s->data) + s->size - s->left -1);
	else if(s->dtype == STACK_UCHAR_PTR)
		//*( (unsigned char **)(pd->value)) = (unsigned char *)0x3214234;
		*( (unsigned char **)(pd->value)) = *( (unsigned char **)(s->data) + s->size - s->left -1);
	else if(s->dtype == STACK_UINT_PTR)
		//*( (unsigned char **)(pd->value)) = (unsigned int *)0x3214234;
		*( (unsigned int **)(pd->value)) = *( (unsigned int **)(s->data) + s->size - s->left -1);
	else if(s->dtype == STACK_VOID_PTR)
		*( (void **)(pd->value)) = *( (void **)(s->data) + s->size - s->left -1);

	return (++(s->left));
}

char stack_peek(stack_t *s, any_t *pd){
#ifdef STACK_DEBUG
	fprintf(stdout, "stack_peek(): running ...\n");
#endif

	assert(s != NULL);

	if(s->left == s->size){		//check whether stack is empty
#ifdef STACK_DEBUG
		fprintf(stdout, "%s(%d): stack is empty.\n", __FILE__, __LINE__);
#endif
		return (0);
	}

	if(s->dtype == STACK_UCHAR)
		*( (unsigned char *)(pd->value)) = *( (unsigned char *)(s->data) + s->size - s->left -1);
	else if(s->dtype == STACK_UINT)
		*( (unsigned int *)(pd->value)) = *( (unsigned int *)(s->data) + s->size - s->left -1);
	else if(s->dtype == STACK_UCHAR_PTR)
		*( (unsigned char **)(pd->value)) = *( (unsigned char **)(s->data) + s->size - s->left -1);
	else if(s->dtype == STACK_UINT_PTR)
		*( (unsigned int **)(pd->value)) = *( (unsigned int **)(s->data) + s->size - s->left -1);
	else if(s->dtype == STACK_VOID_PTR)
		*( (void **)(pd->value)) = *( (void **)(s->data) + s->size - s->left -1);

	return (s->left);
}



char stack_free(stack_t *s){		//TODO: test it. 
	unsigned int i;
#ifdef STACK_DEBUG
	fprintf(stdout, "stack_free(): running ...\n");
#endif

	assert(s != NULL);

	for(i = 0; i < STACK_MAX_NO; i++)
		if(_stack[i] == s){ 
			free(s->data);
			free(s);
			_stack[i] = NULL;
			
			return 0;
		}

	return (-1);
}

