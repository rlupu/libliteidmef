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

#ifndef __STACK_H__
#define __STACK_H__

#define STACK_UCHAR			1	
#define STACK_CHAR			2	
#define STACK_UINT			3	
#define STACK_INT				4	
#define STACK_FLOAT			5	

#define STACK_UCHAR_PTR		6	
#define STACK_UINT_PTR		7	
#define STACK_VOID_PTR		8	

typedef union __attribute__((__transparent_union__)) {
	unsigned char value[8];
	unsigned char uc;
	char c;
	unsigned int ui;
	int i;
	float f;
	double d;
	unsigned char *puc;
	char *pc;
	unsigned int *pui;
	int *pi;
	void *pv;
} any_t;



typedef struct {
	unsigned char dtype;
	unsigned char size;
	unsigned char left;		//# of empty cells

	void *data;	

} stack_t;



extern char stack_init(void);
extern char stack_new(unsigned char, unsigned char, stack_t **);
extern char stack_push(stack_t *, any_t);
extern char stack_pop(stack_t *, any_t *);
extern char stack_peek(stack_t *, any_t *);
extern char stack_free(stack_t *);




#endif
