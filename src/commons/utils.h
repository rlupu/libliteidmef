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
 * Author:		rlupu
 * Release:		2015/11/16
 */


#ifndef __UTILS_H__
#define __UTILS_H__


#ifndef FALSE
#define	FALSE		0
#endif

#ifndef TRUE
#define	TRUE		1
#endif

#ifndef EOS
#define EOS			'\0'
#endif

#ifndef EOF
#define EOF			NULL
#endif

#ifndef ENONE
#define ENONE		0
#endif

#ifndef byte
typedef unsigned char byte;
#endif

//printf's text colors
#define RESET   	"\033[0m"
#define BLACK   	"\033[30m"      /* Black */
#define RED     	"\033[31m"      /* Red */
#define GREEN   	"\033[32m"      /* Green */
#define YELLOW  	"\033[33m"      /* Yellow */
#define BLUE    	"\033[34m"      /* Blue */
#define MAGENTA 	"\033[35m"      /* Magenta */
#define CYAN    	"\033[36m"      /* Cyan */
#define WHITE  		"\033[37m"      /* White */
#define BOLDBLACK   	"\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     	"\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   	"\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  	"\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    	"\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA 	"\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    	"\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   	"\033[1m\033[37m"      /* Bold White */


extern void signal_setup(int, void (*)(int));


#endif
