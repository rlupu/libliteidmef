/*
   This file is part of the Libliteidmef Library. Libliteidmef provides 
	the API to the IDMEF-based notification layer. 
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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>

#include "idmef_plugin.h"

#include "src/commons/utils.h"

#define IDMEF_MASK_TAG				0xff000000
#define IDMEF_MASK_ATTR				0x00ffffff


const unsigned char IDMEF_ATTR_VALUE_XMLNS[]		= "http://iana.org/idmef";
const unsigned char IDMEF_ATTR_VALUE_VER[]		= "1.0";
const unsigned char IDMEF_ATTR_VALUE_UNKNOWN[] 	= "unknown";

extern pthread_t tid_idmefserver;
extern void *idmef_server(void *);



char idmef_new(idmef_ifs_t *io, idmef_t **ctxt, void (*cb)(void) ){
	unsigned char flag = FALSE;
	struct timeval tv;

	assert( (io != NULL) && (*ctxt == NULL));

	//alloc. message ctxt  
	 if((*ctxt = (idmef_t *)malloc(sizeof(idmef_t)*sizeof(unsigned char)) ) == NULL){
		fprintf(stderr, "%s(%s): could not malloc message context. %s\n", __FILE__, __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}
	(*ctxt)->version = (unsigned char **)IDMEF_ATTR_VALUE_VER;
	(*ctxt)->xmlns = (unsigned char **)IDMEF_ATTR_VALUE_XMLNS;
	(*ctxt)->en_attrs = IDMEF_ATTR_MESSAGE_XMLNS | IDMEF_ATTR_MESSAGE_VER; 			//manadatory attrs
	gettimeofday(&tv, NULL);
	(*ctxt)->ts = tv.tv_usec;

	(*ctxt)->alert_tag = NULL;
	(*ctxt)->heartbeat_tag = NULL;																//not implemented, yet

	(*ctxt)->iov = (struct iovec *)malloc(IDMEF_MAX_IOV_LEN*sizeof(struct iovec));
	assert((*ctxt)->iov != NULL);

	(*ctxt)->iov_len = 0;
	(*ctxt)->iov_blob_len = 0;
	(*ctxt)->mode_in = IDMEF_MODE_IDLE;
	(*ctxt)->fd_in = -1;
	(*ctxt)->sd_in = -1;
	(*ctxt)->mode_out = IDMEF_MODE_IDLE;
	memset(&((*ctxt)->remote_out), 0, sizeof(struct sockaddr_in));		
	(*ctxt)->fd_out = -1;
	(*ctxt)->sd_out = -1;
	(*ctxt)->fs_out = NULL;

	(*ctxt)->cbfunc = cb;


	(*ctxt)->mode_in = io->mode_in;

	if(io->mode_in == IDMEF_MODE_FILE ){
		if(access(io->filename_in, F_OK) == 0) flag = TRUE;					//check wheather eggress file exists

		if (((*ctxt)->fs_in = fopen(io->filename_in, "r")) < 0){ 	
			fprintf(stderr, "%s(%s): could not open alarms dump file. %s\n", __FILE__, __LINE__, strerror(errno));
			exit(EXIT_FAILURE);
		}
		(*ctxt)->fd_in = fileno((*ctxt)->fs_in);
	} else if(io->mode_in == IDMEF_MODE_SOCK){									//open server socket and create server thread
		int optval = 1;
		struct sockaddr_in sa;

		(*ctxt)->sd_in = socket(PF_INET, SOCK_STREAM, 0);
		assert((*ctxt)->sd_in >=0);

		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(IDMEF_PORT);
		sa.sin_addr.s_addr = htonl(INADDR_ANY);									//TODO: change to "in->ip_addr"

		if(setsockopt((*ctxt)->sd_in, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
			perror("SO_REUSEADDR");
			exit(EXIT_FAILURE);
		}
		//unlink("127.0.0.1"); ???
		if(bind((*ctxt)->sd_in, (struct sockaddr *)&sa, sizeof(sa)) < 0 ){
			perror("bind");
			exit(EXIT_FAILURE);
		}
		if(listen((*ctxt)->sd_in, 10) < 0){	//max 10 conn. waiting from ids's response module 
			perror("listen");
			exit(EXIT_FAILURE);
		}

		pthread_create(&tid_idmefserver, NULL, &idmef_server, (void *)*ctxt);		//start server
	}

	(*ctxt)->mode_out = io->mode_out;

	if( io->mode_out == IDMEF_MODE_FILE || io->mode_out == IDMEF_MODE_FS){
		if(access(io->filename_out, F_OK) == 0) flag = TRUE;				//check wheather eggress file exists

		if (((*ctxt)->fs_out = fopen(io->filename_out, "a")) < 0){ 	
			fprintf(stderr, "%s(%d): could not open alarms dump file. %s\n", __FILE__, __LINE__, strerror(errno));
			exit(EXIT_FAILURE);
		}
		(*ctxt)->fd_out = fileno((*ctxt)->fs_out);

		if(!flag){
			fprintf((*ctxt)->fs_out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\n");
			fflush((*ctxt)->fs_out);
		}

		//fprintf(stdout, "ctxt's addr=%p\n", *ctxt);
		//fprintf(stdout, "fd_out's =%d\n", (*ctxt)->fd_out);
		//fprintf(stdout, "fs_out's =%p\n", (*ctxt)->fs_out);
		//fflush((*ctxt)->fs_out);
	}

	if( io->mode_out == IDMEF_MODE_SOCK || io->mode_out == IDMEF_MODE_FS ){		//to avoid open socket multiple times
		(*ctxt)->sd_out = socket(PF_INET, SOCK_STREAM, 0);
		assert((*ctxt)->sd_out >= 0);

		(*ctxt)->remote_out.sin_family = AF_INET;
		(*ctxt)->remote_out.sin_port = htons(IDMEF_PORT);

		assert(io->ipaddr_out != NULL);
		if(inet_pton(AF_INET, io->ipaddr_out, &((*ctxt)->remote_out.sin_addr) ) <= 0){
			fprintf(stderr, "%s(%d): remote agent. %s\n", __FILE__, __LINE__, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if( connect((*ctxt)->sd_out, (struct sockaddr *)&((*ctxt)->remote_out), sizeof(struct sockaddr_in)) < 0){
			fprintf(stderr, "%s(%d): cannot connect remote agent. %s\n", __FILE__, __LINE__, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	return (0);
}


char idmef_chcon(idmef_t *ctxt, idmef_ifs_t *o){		//not tested, yet

	if( (ctxt->sd_out < 0) || (o->ipaddr_out == NULL) || (ctxt == NULL) || 
		((ctxt->mode_out != IDMEF_MODE_SOCK) && (ctxt->mode_out != IDMEF_MODE_FS)) ) return (-1);

	close(ctxt->sd_out);
	
	ctxt->sd_out = socket(PF_INET, SOCK_STREAM, 0);
	assert(ctxt->sd_out >= 0);
	ctxt->remote_out.sin_family = AF_INET;
	ctxt->remote_out.sin_port = htons(IDMEF_PORT);

	if(inet_pton(AF_INET, o->ipaddr_out, &(ctxt->remote_out.sin_addr) ) <= 0){
		fprintf(stderr, "%s(%d): remote agent. %s\n", __FILE__, __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	if( connect(ctxt->sd_out, (struct sockaddr *)&(ctxt->remote_out), sizeof(struct sockaddr_in)) < 0){
		fprintf(stderr, "%s(%d): cannot  reconnect to the new remote agent. %s\n", __FILE__, __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	return (0);
}


/* 
 * Implements only: mandatory attributes, ALERT tag.
 */

char idmef_message_addtag(idmef_t *msg, unsigned int code, void **tag){
	unsigned char i;

	assert(msg != NULL);

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_ALERT){ 										//optional tag
		if(msg->alert_tag == NULL){

			if((msg->alert_tag = (idmef_alert_t *)malloc(sizeof(idmef_alert_t)*sizeof(unsigned char)) ) == NULL){
				fprintf(stderr, "%s(%s): could not malloc alert_tag's room. %s\n", __FILE__, __LINE__, strerror(errno));
				exit(EXIT_FAILURE);
			}

			msg->alert_tag->messageid = (unsigned char **)NULL;								//mandatory attr
			msg->alert_tag->messageid_len = (unsigned int *)NULL;								//mandatory attr
			msg->alert_tag->messageid_ts = msg->ts;

			msg->alert_tag->en_attrs |= IDMEF_ATTR_ALERT_MESSAGEID;
			msg->alert_tag->en_attrs |= (code & IDMEF_MASK_ATTR);

			msg->alert_tag->analyzer_tag.name = (unsigned char **)NULL;
			msg->alert_tag->analyzer_tag.name_len = (unsigned int *)NULL;

			msg->alert_tag->analyzer_tag.en_attrs |= IDMEF_ATTR_ANALYZER_NAME;
			msg->alert_tag->analyzer_tag.ctxt = msg;

			msg->alert_tag->createtime_tag.body = (unsigned char **)NULL;
			msg->alert_tag->createtime_tag.body_len = (unsigned int *)NULL;
			msg->alert_tag->createtime_tag.en_attrs |= IDMEF_ATTR_CREATETIME_BODY;
			msg->alert_tag->createtime_tag.ctxt = msg;

			for(i = 0; i < IDMEF_MAX_SOURCES_NO; i++) msg->alert_tag->source_tag[i] = NULL;		//optional attribute 
			msg->alert_tag->sources_no = 0;

			for(i = 0; i < IDMEF_MAX_TARGETS_NO; i++) msg->alert_tag->target_tag[i] = NULL;				 
			msg->alert_tag->targets_no = 0;

			msg->alert_tag->classification_tag.text = (unsigned char **)NULL;				//mandatory attr 
			msg->alert_tag->classification_tag.text_len = (unsigned int *)NULL;		 
			for(i = 0; i < IDMEF_MAX_REF_NO; i++) msg->alert_tag->classification_tag.reference_tag[i] = NULL;		 
			msg->alert_tag->classification_tag.references_no = 0;
			msg->alert_tag->classification_tag.en_attrs |= IDMEF_ATTR_CLASSIFICATION_TEXT;
			msg->alert_tag->classification_tag.ctxt = msg;

			msg->alert_tag->ctxt = msg;		//= ctxt
		}

		msg->alert_tag->ts = msg->ts;

		if(tag != NULL)	
			*tag = (void *)(msg->alert_tag);

		return(0);
	}

	return(-1);
}

void *idmef_message_gettag(idmef_t *msg, unsigned int tag){ 
	assert(msg != NULL);

	if((tag & IDMEF_MASK_TAG) == IDMEF_TAG_ALERT){
		if(msg->alert_tag == NULL){
			idmef_alert_t *alert = NULL;

			idmef_message_addtag(msg, IDMEF_TAG_ALERT, (void **)&alert);
			alert->ts = ~(msg->ts);
		}
		return (msg->alert_tag);
	}

	return (NULL);
}

char idmef_message_setattr(unsigned int code, idmef_t *tag){
	//TBD.
}

/*
 * Adds only one target/source_tag per call.
 *
 */

char idmef_alert_addtag(idmef_alert_t *alert, unsigned int code, void **tag){

	assert(alert != NULL);														//you should alloc alert tag first

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_TARGET){					//optional tag
		if(alert->targets_no >= IDMEF_MAX_TARGETS_NO){
			fprintf(stderr, "%s(%d): pre-established IDMEF_MAX_TARGETS_NO const exceded.\n", __FILE__, __LINE__);
			return (-2);
		}

		if(alert->target_tag[alert->targets_no] == NULL){

			if((alert->target_tag[alert->targets_no] = (idmef_target_t *)malloc(sizeof(idmef_target_t)*sizeof(unsigned char)) ) == NULL){
				fprintf(stderr, "%s(%d): could not malloc target_tag's room. %s\n", __FILE__, __LINE__, strerror(errno));
				exit(EXIT_FAILURE);
			}

			alert->target_tag[alert->targets_no]->ident 			= (unsigned char **)NULL;
			alert->target_tag[alert->targets_no]->ident_len 	= (unsigned int *)NULL;
			alert->target_tag[alert->targets_no]->interface 	= (unsigned char **)NULL;
			alert->target_tag[alert->targets_no]->interface_len= (unsigned int *)NULL;
			alert->target_tag[alert->targets_no]->decoy 			= (unsigned char **)NULL;
			alert->target_tag[alert->targets_no]->decoy_len		= (unsigned int *)NULL;

			alert->target_tag[alert->targets_no]->node_tag 		= NULL;
			alert->target_tag[alert->targets_no]->service_tag 	= NULL;
			//TODO: init other tags ...

			alert->target_tag[alert->targets_no]->en_attrs = (code & IDMEF_MASK_ATTR);

			alert->target_tag[alert->targets_no]->ctxt = alert->ctxt;
		}

		if(tag != NULL)	
			*tag = (void *)(alert->target_tag[alert->targets_no]);
	
		alert->targets_no++;

		//compress target_tag pointers' space 
		//for(i = 0; i < IDMEF_MAX_TARGETS_NO - 1; i++)
		//	if(alert->target_tag[i] == NULL){ 
		//		for(j = i+1; j < IDMEF_MAX_TARGETS_NO; j++)
		//			if(alert->target_tag[j] != NULL){
		//				alert->target_tag[i] = alert->target_tag[j];
		//				alert->target_tag[j] = NULL;
		//				break;
		//			}
		//		if(j == IDMEF_MAX_TARGETS_NO)
		//			break;
		//	}
		return (0);
	}

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_SOURCE){					//optional tag
		if(alert->sources_no >= IDMEF_MAX_SOURCES_NO){ 
			fprintf(stderr, "%s(%d): pre-established IDMEF_MAX_SOURCES_NO const exceded.\n", __FILE__, __LINE__);
			return (-2);
		}

		if(alert->source_tag[alert->sources_no] == NULL){

			if((alert->source_tag[alert->sources_no] = (idmef_source_t *)malloc(sizeof(idmef_source_t)*sizeof(unsigned char)) ) == NULL){
				fprintf(stderr, "%s(%d): could not malloc source_tag's room. %s\n", __FILE__, __LINE__, strerror(errno));
				exit(EXIT_FAILURE);
			}

			alert->source_tag[alert->sources_no]->ident 			= (unsigned char **)NULL;
			alert->source_tag[alert->sources_no]->ident_len 	= (unsigned int *)NULL;
			alert->source_tag[alert->sources_no]->spoofed 		= (unsigned char **)NULL;
			alert->source_tag[alert->sources_no]->spoofed_len	= (unsigned int *)NULL;
			alert->source_tag[alert->sources_no]->interface 	= (unsigned char **)NULL;
			alert->source_tag[alert->sources_no]->interface_len= (unsigned int *)NULL;

			alert->source_tag[alert->sources_no]->node_tag 		= NULL;
			alert->source_tag[alert->sources_no]->service_tag 	= NULL;
			//TODO: init other tags ...

			alert->source_tag[alert->sources_no]->en_attrs = (code & IDMEF_MASK_ATTR);

			alert->source_tag[alert->sources_no]->ctxt = alert->ctxt;
		}

		if(tag != NULL)	
			*tag = (void *)(alert->source_tag[alert->sources_no]);

		alert->sources_no++;

		//compress source_tag pointers' space 
		//for(i = 0; i < IDMEF_MAX_SOURCES_NO - 1; i++)
		//	if(alert->source_tag[i] == NULL){ 
		//		for(j = i+1; j < IDMEF_MAX_SOURCES_NO; j++)
		//			if(alert->source_tag[j] != NULL){
		//				alert->source_tag[i] = alert->source_tag[j];
		//				alert->source_tag[j] = NULL;
		//				break;
		//			}
		//		if(j == IDMEF_MAX_SOURCES_NO)
		//			break;
		//	}
		return (0);
	}

	return(-1);
}

char idmef_alert_deltag(idmef_alert_t *alert, unsigned int code, unsigned char pos){
	unsigned int i, j;

	assert(alert != NULL);

	if((code & IDMEF_MASK_TAG) == IDMEF_TAG_TARGET){		
		assert(pos < IDMEF_MAX_TARGETS_NO);

		if(alert->target_tag[pos] != NULL){
			//remove pos'th target_tag element 
			free(alert->target_tag[pos]);	
			alert->target_tag[pos] = NULL;

			//then, compact address_tag[] list ...
			for(i = 0; i < IDMEF_MAX_TARGETS_NO - 1; i++)
				if(alert->target_tag[i] == NULL){ 
					for(j = i+1; j < IDMEF_MAX_TARGETS_NO; j++)
						if(alert->target_tag[j] != NULL){
							alert->target_tag[i] = alert->target_tag[j];
							alert->target_tag[j] = NULL;
							break;
						}
					if(j == IDMEF_MAX_TARGETS_NO) break;	//no elems lasts
				}
			alert->targets_no--;
		} else 
			return (-2);
		return (0);
	}

	if((code & IDMEF_MASK_TAG) == IDMEF_TAG_SOURCE){		
		assert(pos < IDMEF_MAX_SOURCES_NO);

		if(alert->source_tag[pos] != NULL){
			//remove pos'th source_tag element 
			free(alert->source_tag[pos]);	
			alert->source_tag[pos] = NULL;

			//then, compact address_tag[] list ...
			for(i = 0; i < IDMEF_MAX_SOURCES_NO - 1; i++)
				if(alert->source_tag[i] == NULL){ 
					for(j = i+1; j < IDMEF_MAX_SOURCES_NO; j++)
						if(alert->source_tag[j] != NULL){
							alert->source_tag[i] = alert->source_tag[j];
							alert->source_tag[j] = NULL;
							break;
						}
					if(j == IDMEF_MAX_SOURCES_NO) break;	//no elems lasts
				}
			alert->sources_no--;
		} else 
			return (-2);
		return (0);
	}

 	return (-1);
}

void *idmef_alert_gettag(idmef_alert_t *alert, unsigned int tag, unsigned char pos){ 
	if(alert == NULL) return (NULL);

	if((tag & IDMEF_MASK_TAG) == IDMEF_TAG_ANALYZER){
		return &(alert->analyzer_tag);

	}else if((tag & IDMEF_MASK_TAG) == IDMEF_TAG_CLASSIFICATION){
		return &(alert->classification_tag);

	}else if((tag & IDMEF_MASK_TAG) == IDMEF_TAG_CREATETIME){
		return &(alert->createtime_tag);

	}else if((tag & IDMEF_MASK_TAG) == IDMEF_TAG_TARGET){
		if( (pos < 0) || (pos >= IDMEF_MAX_TARGETS_NO)) return (NULL);

		if(alert->target_tag[0] == NULL){ 
			idmef_alert_addtag(alert, IDMEF_TAG_TARGET, NULL);	
			alert->targets_no = 0;
		}
		if((alert->targets_no > pos) || (pos == 0))
			return (alert->target_tag[pos]);

	}else if((tag & IDMEF_MASK_TAG) == IDMEF_TAG_SOURCE){
		if( (pos < 0) || (pos >= IDMEF_MAX_SOURCES_NO)) return (NULL);

		if(alert->source_tag[0] == NULL){ 
			idmef_alert_addtag(alert, IDMEF_TAG_SOURCE, NULL);	
			alert->sources_no = 0;
		}
		if((alert->sources_no > pos) || (pos == 0))
			return (alert->source_tag[pos]);
	}

	return (NULL);
}

void idmef_alert_wrattr(idmef_alert_t *alert, unsigned int attr, unsigned char *value, unsigned int len){
	if(alert == NULL) return;

	if(attr == IDMEF_ATTR_ALERT_MESSAGEID){
		if(alert->messageid == (unsigned char **)NULL){					//no room avail.
			alert->messageid = (unsigned char **)&(alert->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - alert->ctxt->iov_blob_len].iov_base);
			alert->messageid_len = &(alert->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - alert->ctxt->iov_blob_len].iov_len);
			alert->ctxt->iov_blob_len++;
		}
		*(alert->messageid) = value;										//within postcompilation
		*(alert->messageid_len) = len;
		alert->messageid_ts = alert->ts;		
	}
}

char idmef_alert_setattr(idmef_alert_t *alert, unsigned int code){ //TODO: it is really necessary ?????
	assert(alert != NULL);
/*
	if( ((idmef_t *)(*tag))->alert_tag == NULL ){ 
		idmef_message_addtag((idmef_t *)*tag, IDMEF_TAG_ALERT|code, tag);		
	} else{
		*tag = (void *)( ((idmef_t *)*tag)->alert_tag);
	}
 	((idmef_alert_t *)(*tag))->en_attrs |= (code & IDMEF_MASK_ATTR);
*/

 	alert->en_attrs |= (code & IDMEF_MASK_ATTR);

	return 0;
}

char idmef_alert_rstattr(idmef_alert_t *alert, unsigned int code){ 	
	assert(alert != NULL);

 	alert->en_attrs &= (~code & IDMEF_MASK_ATTR);

	return 0;
}

char idmef_alert_rdattr(idmef_alert_t *alert, unsigned int code, unsigned char **value, unsigned int *value_len){ 
	assert(value != NULL);

	if(alert == NULL){
		*value_len = 0;
		return (-2);
	}

	if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_ALERT_MESSAGEID){
		if( (alert->messageid != NULL) 
			&& (alert->messageid_ts == alert->ctxt->ts) ){	
				*value_len = *(alert->messageid_len);
				*value = *(alert->messageid);
		} else{
			*value_len = 0;
		}
		return (0);
	}

	return (-1);
}


char idmef_analyzer_rstattr(idmef_analyzer_t *analyzer, unsigned int code){ 	
	assert(analyzer != NULL);

 	analyzer->en_attrs &= (~code & IDMEF_MASK_ATTR);
	if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_ANALYZER_NAME){
		analyzer->name = (unsigned char **)NULL;
		analyzer->name_len = (unsigned int *)NULL;
	}
	return 0;
}

void idmef_analyzer_wrattr(idmef_analyzer_t *analyzer, unsigned int attr, unsigned char *value, unsigned int len){
	if(analyzer == NULL) return;

	if(attr == IDMEF_ATTR_ANALYZER_NAME){						
		if(analyzer->name == (unsigned char **)NULL){					//within precompilation 
			analyzer->name = (unsigned char **)&(analyzer->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - analyzer->ctxt->iov_blob_len].iov_base);
			analyzer->name_len = &(analyzer->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - analyzer->ctxt->iov_blob_len].iov_len);
			analyzer->ctxt->iov_blob_len++;
		}
		*(analyzer->name) = value;											//within postcompilation
		*(analyzer->name_len) = len;
		analyzer->name_ts = analyzer->ctxt->ts;
	}
}

char idmef_analyzer_rdattr(idmef_analyzer_t *analyzer, unsigned int code, unsigned char **value, unsigned int *value_len){ 
	assert(value != NULL);

	if(analyzer == NULL){
		*value_len = 0;
		return (-2);
	}

	if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_ANALYZER_NAME) 
		//REDUNDANT: if( (((idmef_analyzer_t *)*tag_value)->en_attrs & IDMEF_ATTR_ANALYZER_NAME)
		if( analyzer->name_ts == analyzer->ctxt->ts){	
			*value_len = *(analyzer->name_len);
			*value = *(analyzer->name);
			return 0;
		} else{
			*value_len = 0;
			return 0;
		}

	return (-1);
}


char idmef_createtime_setattr(idmef_createtime_t *ct, unsigned int code){ 
	assert(ct != NULL);

 	ct->en_attrs |= (code & IDMEF_MASK_ATTR);

	return 0;
}

char idmef_cretatetime_rstattr(idmef_createtime_t *ct, unsigned int code){ 	
	assert(ct != NULL);

 	ct->en_attrs &= (~code & IDMEF_MASK_ATTR);

	return 0;
}

void idmef_createtime_wrattr(idmef_createtime_t *ct, unsigned int attr, unsigned char *value, unsigned int len){
	if(ct == NULL) return;

	if(attr == IDMEF_ATTR_CREATETIME_BODY){
		if(ct->body == (unsigned char **)NULL){					// no room avail.
			ct->body = (unsigned char **)&(ct->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - ct->ctxt->iov_blob_len].iov_base);
			ct->body_len = &(ct->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - ct->ctxt->iov_blob_len].iov_len);
			ct->ctxt->iov_blob_len++;
		}
		*(ct->body) = value;											//within postcompilation
		*(ct->body_len) = len;	
		ct->body_ts = ct->ctxt->ts;
	}
}

char idmef_createtime_rdattr(idmef_createtime_t *ct, unsigned int code, unsigned char **value, unsigned int *value_len){ 
	assert(value != NULL);

	if(ct == NULL){
		*value_len = 0;
		return (-2);
	}

	//if(code & IDMEF_MASK_ATTR == IDMEF_ATTR_CREATETIME_BODY){
	if( ct->body_ts == ct->ctxt->ts){	
		*value_len = *(ct->body_len);
		*value = *(ct->body);
		return (0);
	} else{
		*value_len = 0;
		return (0);
	}
	return (-1);
}

char idmef_target_addtag(idmef_target_t *target, unsigned int code, void **tag){

	assert(target != NULL);

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_NODE){				//optional tag
		if(target->node_tag == NULL){				//therefore, all the pointers must be init by NULL !
			unsigned int i;

			if((target->node_tag = (idmef_node_t *)malloc(sizeof(idmef_node_t)*sizeof(unsigned char)) ) == NULL){
				fprintf(stderr, "%s(%s): could not malloc node_tag's room. %s\n", __FILE__, __LINE__, strerror(errno));
				exit(EXIT_FAILURE);
			}
			target->node_tag->ident 			= (unsigned char **) NULL;
			target->node_tag->ident_len 		= (unsigned int *)NULL;
			target->node_tag->category 		= (unsigned char **) NULL;
			target->node_tag->category_len 	= (unsigned int *)NULL;
			for(i = 0; i < IDMEF_MAX_ADDRS_NO; i++) target->node_tag->address_tag[i] = (idmef_addr_t *)NULL;
			target->node_tag->addresses_no = 0;

			target->node_tag->ctxt = target->ctxt;
		}
		target->node_tag->en_attrs = (code & IDMEF_MASK_ATTR);
		target->node_tag->ts = target->ctxt->ts;

		if(tag != NULL)	
			*tag = (void *)(target->node_tag);

		return (0);
	} else if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_SERVICE){	//optional tag, therefore, all pointers must be NULLyfied !
		if(target->service_tag == NULL){		//avoid multiple adds, but still allows attrs setting

			if((target->service_tag = (idmef_service_t *)malloc(sizeof(idmef_service_t)*sizeof(unsigned char)) ) == NULL){
				fprintf(stderr, "%s(%s): could not malloc service_tag's room. %s\n", __FILE__, __LINE__, strerror(errno));
				exit(EXIT_FAILURE);
			}
			target->service_tag->ident 						= (unsigned char **) NULL;
			target->service_tag->ident_len 					= (unsigned int *)NULL;
			target->service_tag->ip_version					= (unsigned char **) NULL;
			target->service_tag->ip_version_len				= (unsigned int *)NULL;
			target->service_tag->iana_protocol_number		= (unsigned char **) NULL;
			target->service_tag->iana_protocol_number_len= (unsigned int *)NULL;
			target->service_tag->iana_protocol_name		= (unsigned char **) NULL;
			target->service_tag->iana_protocol_name_len	= (unsigned int *)NULL;

			target->service_tag->name				= (unsigned char **)NULL;
			target->service_tag->name_len			= (unsigned int *)NULL;
			target->service_tag->port				= (unsigned char **)NULL;
			target->service_tag->port_len			= (unsigned int *)NULL;
			if(code & IDMEF_MASK_ATTR & IDMEF_ATTR_SERVICE_PORT)
				target->service_tag->port_ts = target->ctxt->ts;	
			target->service_tag->portlist			= (unsigned char **)NULL;
			target->service_tag->portlist_len	= (unsigned int *)NULL;
			target->service_tag->protocol			= (unsigned char **)NULL;
			target->service_tag->protocol_len	= (unsigned int *)NULL;

			target->service_tag->ctxt = target->ctxt;
		}
		target->service_tag->en_attrs = (code & IDMEF_MASK_ATTR);
		target->service_tag->ts = target->ctxt->ts;

		if(tag != NULL)	
			*tag = (void *)(target->service_tag);
	
		return (0);
	}
	return (-1);
}

char idmef_target_deltag(idmef_target_t *target, unsigned int code, unsigned char pos){
	unsigned int i;

	assert(target != NULL);

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_NODE){	
		if(target->node_tag != NULL){ 									//node tag is optional
			//free subtags memory 
			for(i = 0; i < IDMEF_MAX_ADDRS_NO; i++){
				if(target->node_tag->address_tag[i] != NULL) 
					//free subtags memory
					//TODO: addresses!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
					target->node_tag->address_tag[i]->netmask_ts = 0;	//?????????
					free(target->node_tag->address_tag[i]);
			}
			free(target->node_tag);
			target->node_tag = NULL;	
			return 0;
		}	
		return (-2);
	}
	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_SERVICE){	
		if(target->service_tag != NULL){ 
			free(target->service_tag);		
			target->service_tag = NULL;	
			return 0;
		}
		return (-2);
	}
	return (-1);
}

/* 
 * It always returns the first target object. If none it will alloc a new one.
 */
void *idmef_target_gettag(idmef_target_t *target, unsigned int tag){
	if(target == NULL) return (NULL);

	if( (tag & IDMEF_MASK_TAG) == IDMEF_TAG_NODE){	
		if(target->node_tag == NULL){ 
			idmef_target_addtag(target, IDMEF_TAG_NODE, NULL);	
			target->node_tag->ts = ~(target->ctxt->ts);
		}
		return (target->node_tag);

	}else if( (tag & IDMEF_MASK_TAG) == IDMEF_TAG_SERVICE){	
		if(target->service_tag == NULL){
			idmef_target_addtag(target, IDMEF_TAG_SERVICE, NULL);	
			target->service_tag->ts = ~(target->ctxt->ts);
		}	
		return (target->service_tag);
	}
	return (NULL);
}

char idmef_source_addtag(idmef_source_t *source, unsigned int code, void **tag){
	unsigned char i;

	assert(source != NULL);

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_NODE){				//optional tag
		if(source->node_tag == NULL){				//therefore, all the pointers must be init by NULL !

			if((source->node_tag = (idmef_node_t *)malloc(sizeof(idmef_node_t)*sizeof(unsigned char)) ) == NULL){
				fprintf(stderr, "%s(%s): could not malloc node_tag's room. %s\n", __FILE__, __LINE__, strerror(errno));
				exit(EXIT_FAILURE);
			}
			source->node_tag->ident 			= (unsigned char **) NULL;
			source->node_tag->ident_len 		= (unsigned int *)NULL;
			source->node_tag->category 		= (unsigned char **) NULL;
			source->node_tag->category_len 	= (unsigned int *)NULL;
			for(i = 0; i < IDMEF_MAX_ADDRS_NO; i++) source->node_tag->address_tag[i] = (idmef_addr_t *)NULL;
			source->node_tag->addresses_no = 0;

			source->node_tag->ctxt = source->ctxt;
		}
		source->node_tag->en_attrs = (code & IDMEF_MASK_ATTR);
		source->node_tag->ts = source->ctxt->ts;

		if(tag != NULL)	
			*tag = (void *)(source->node_tag);
	
		return(0);
	}

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_SERVICE){				//optional tag
		if(source->service_tag == NULL){				//therefore, all the pointers must be init by NULL 

			if((source->service_tag = (idmef_service_t *)malloc(sizeof(idmef_service_t)*sizeof(unsigned char)) ) == NULL){
				fprintf(stderr, "%s(%s): could not malloc service_tag's room. %s\n", __FILE__, __LINE__, strerror(errno));
				exit(EXIT_FAILURE);
			}
			source->service_tag->ident 						= (unsigned char **) NULL;
			source->service_tag->ident_len 					= (unsigned int *)NULL;
			source->service_tag->ip_version					= (unsigned char **) NULL;
			source->service_tag->ip_version_len				= (unsigned int *)NULL;
			source->service_tag->iana_protocol_number		= (unsigned char **) NULL;
			source->service_tag->iana_protocol_number_len= (unsigned int *)NULL;
			source->service_tag->iana_protocol_name		= (unsigned char **) NULL;
			source->service_tag->iana_protocol_name_len	= (unsigned int *)NULL;

			source->service_tag->name				= (unsigned char **)NULL;
			source->service_tag->name_len			= (unsigned int *)NULL;
			source->service_tag->port				= (unsigned char **)NULL;
			source->service_tag->port_len			= (unsigned int *)NULL;
			if( (code & IDMEF_MASK_ATTR) == IDMEF_ATTR_SERVICE_PORT)
				source->service_tag->port_ts = source->ctxt->ts;	
			source->service_tag->portlist			= (unsigned char **)NULL;
			source->service_tag->portlist_len	= (unsigned int *)NULL;
			source->service_tag->protocol			= (unsigned char **)NULL;
			source->service_tag->protocol_len	= (unsigned int *)NULL;
	
			source->service_tag->ctxt = source->ctxt;
		}
		source->service_tag->en_attrs = (code & IDMEF_MASK_ATTR);
		source->service_tag->ts = source->ctxt->ts;

		if(tag != NULL)	
			*tag = (void *)(source->service_tag);

		return(0);
	}
	return(-1);
}

/* 
 * It always returns the first source object. If none it will alloc a new one.
 */
void *idmef_source_gettag(idmef_source_t *source, unsigned int tag){
	if(source == NULL) return (NULL);

	if( (tag & IDMEF_MASK_TAG) == IDMEF_TAG_NODE){	
		if(source->node_tag == NULL){ 
			idmef_source_addtag(source, IDMEF_TAG_NODE, NULL);	
			source->node_tag->ts = ~(source->ctxt->ts);
		}
		return (source->node_tag);
	}else if( (tag & IDMEF_MASK_TAG) == IDMEF_TAG_SERVICE){	
		if(source->service_tag == NULL){
			idmef_source_addtag(source, IDMEF_TAG_SERVICE, NULL);	
			source->service_tag->ts = ~(source->ctxt->ts);
		}
		return (source->service_tag);
	}

	return (NULL);
}

char idmef_source_deltag(idmef_source_t *src, unsigned int code, unsigned char pos){
	unsigned int i;

	assert(src != NULL);

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_NODE){	
		if(src->node_tag != NULL){ 									//node tag is optional
			//free subtags memory 
			for(i = 0; i < IDMEF_MAX_ADDRS_NO; i++){
				if(src->node_tag->address_tag[i] != NULL) 
					//free subtags memory
					//TODO: addresses!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
					src->node_tag->address_tag[i]->netmask_ts = 0;	//?????????
					free(src->node_tag->address_tag[i]);
			}
			free(src->node_tag);
			src->node_tag = NULL;	
			return 0;
		}	
		return (-2);
	}
	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_SERVICE){	
		if(src->service_tag != NULL){ 
			free(src->service_tag);		
			src->service_tag = NULL;	
			return 0;
		}
		return (-2);
	}
	return (-1);
}

char idmef_node_deltag(idmef_node_t *node, unsigned int code, unsigned char pos){
	unsigned int i, j;

	assert(node != NULL);

	if((code & IDMEF_MASK_TAG) == IDMEF_TAG_ADDR){			//optional tag
		assert(pos < IDMEF_MAX_ADDRS_NO);

		if(node->address_tag[pos] != NULL){
			//remove pos'th address_tag element 
			free(node->address_tag[pos]);	
			node->address_tag[pos] = NULL;

			//then, compact address_tag[] list ...
			for(i = 0; i < IDMEF_MAX_ADDRS_NO - 1; i++)
				if(node->address_tag[i] == NULL){ 
					for(j = i+1; j < IDMEF_MAX_ADDRS_NO; j++)
						if(node->address_tag[j] != NULL){
							node->address_tag[i] = node->address_tag[j];
							node->address_tag[j] = NULL;
							break;
						}
					if(j == IDMEF_MAX_ADDRS_NO) break;	//no elems lasts
				}
			node->addresses_no--;
		} else 
			return (-2);

		return (0);
	}

 	return (-1);
}

char idmef_node_addtag(idmef_node_t *node, unsigned int code, void **tag){

	assert(node != NULL);

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_ADDR){				//optional tag
		if(node->addresses_no >= IDMEF_MAX_ADDRS_NO){
			fprintf(stderr, "%s(%d): pre-established IDMEF_MAX_ADDRS_NO const exceded.\n", __FILE__, __LINE__);
			return (-2);
		}

		if(node->address_tag[node->addresses_no] == NULL){
			if((node->address_tag[node->addresses_no] = (idmef_addr_t *)malloc(sizeof(idmef_addr_t)*sizeof(unsigned char)) ) == NULL){
				fprintf(stderr, "%s(%s): could not malloc address_tag's room. %s\n", __FILE__, __LINE__, strerror(errno));
				exit(EXIT_FAILURE);
			}

			node->address_tag[node->addresses_no]->ident 			= (unsigned char **)NULL;
			node->address_tag[node->addresses_no]->ident_len 		= (unsigned int *)NULL;

		 	node->address_tag[node->addresses_no]->category 		= (unsigned char **)&(node->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - node->ctxt->iov_blob_len].iov_base);
		 	node->address_tag[node->addresses_no]->category_len 	= &(node->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - node->ctxt->iov_blob_len].iov_len);
			node->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - node->ctxt->iov_blob_len].iov_base	= IDMEF_ATTR_VALUE_UNKNOWN;	
			node->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - node->ctxt->iov_blob_len].iov_len	= strlen(IDMEF_ATTR_VALUE_UNKNOWN);
			node->ctxt->iov_blob_len++;
			node->address_tag[node->addresses_no]->category_ts = node->ctxt->ts;

			node->address_tag[node->addresses_no]->vlan_name 		= (unsigned char **)NULL;
			node->address_tag[node->addresses_no]->vlan_name_len	= (unsigned int *)NULL;
			node->address_tag[node->addresses_no]->vlan_num 		= (unsigned char **)NULL;
			node->address_tag[node->addresses_no]->vlan_num_len	= (unsigned int *)NULL;

			node->address_tag[node->addresses_no]->address 		= (unsigned char **)NULL;
			node->address_tag[node->addresses_no]->address_len	= (unsigned int *)NULL;
			node->address_tag[node->addresses_no]->netmask 		= (unsigned char **)NULL;
			node->address_tag[node->addresses_no]->netmask_len	= (unsigned int *)NULL;
			if(code & IDMEF_ATTR_ADDR_NETMASK){
				node->address_tag[node->addresses_no]->netmask_ts = node->ctxt->ts;
			}

		 	node->address_tag[node->addresses_no]->en_attrs = (code & IDMEF_MASK_ATTR) | IDMEF_ATTR_ADDR_CATEGORY;	// | ...

			node->address_tag[node->addresses_no]->ctxt = node->ctxt;
		}
		node->address_tag[node->addresses_no]->ts = node->ctxt->ts;

		if(tag != NULL)	
			*tag = (void *)(node->address_tag[node->addresses_no]);

		node->addresses_no++;
	}
}

void *idmef_node_gettag(idmef_node_t *node, unsigned int tag, unsigned char pos){
	if((node == NULL) || (pos < 0))	return (NULL);

	if((tag & IDMEF_MASK_TAG) == IDMEF_TAG_ADDR){
		if(pos >= IDMEF_MAX_ADDRS_NO) return (NULL);

		if(node->address_tag[0] == NULL){
			idmef_node_addtag(node, IDMEF_TAG_ADDR, NULL);	
			node->address_tag[0]->ts = ~(node->ctxt->ts);	
		}
		if((node->addresses_no > pos) || (pos == 0) )
		return (node->address_tag[pos]);
	}
	return (NULL);
}

char idmef_addr_setattr(idmef_addr_t *addr, unsigned int code){ 
	assert(addr != NULL);

 	addr->en_attrs |= (code & IDMEF_MASK_ATTR);

	if(code & IDMEF_MASK_ATTR & IDMEF_ATTR_ADDR_NETMASK)
		addr->netmask_ts = addr->ctxt->ts;

	return 0;
}

char idmef_addr_rstattr(idmef_addr_t *addr, unsigned int code){ 	
	assert(addr != NULL);

 	addr->en_attrs &= (~code & IDMEF_MASK_ATTR);

	return 0;
}

void idmef_addr_wrattr(idmef_addr_t *addr, unsigned int attr, unsigned char *value, unsigned int len){
	if(addr == NULL) return;

	if(attr == IDMEF_ATTR_ADDR_ADDRESS){
		if(addr->address == (unsigned char **)NULL){						//within precompilation 
			addr->address = (unsigned char **)&(addr->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - addr->ctxt->iov_blob_len].iov_base);
			addr->address_len = &(addr->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - addr->ctxt->iov_blob_len].iov_len);
			addr->ctxt->iov_blob_len++;
		}
		*(addr->address) = value;											//within postcompilation
		*(addr->address_len) = len;
		addr->address_ts = addr->ctxt->ts;
		return;
	}
	if(attr == IDMEF_ATTR_ADDR_NETMASK){
		if(addr->netmask == (unsigned char **)NULL){						//within precompilation 
			addr->netmask = (unsigned char **)&(addr->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - addr->ctxt->iov_blob_len].iov_base);
			addr->netmask_len = &(addr->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - addr->ctxt->iov_blob_len].iov_len);
			addr->ctxt->iov_blob_len++;
		}	
		*(addr->netmask) = value;											//within postcompilation
		*(addr->netmask_len) = len;
		addr->netmask_ts = addr->ctxt->ts;
		return;
	}
	if(attr == IDMEF_ATTR_ADDR_CATEGORY){
		if(addr->category == (unsigned char **)NULL){				//within precompilation 
			addr->category = (unsigned char **)&(addr->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - addr->ctxt->iov_blob_len].iov_base);
			addr->category_len = &(addr->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - addr->ctxt->iov_blob_len].iov_len);
			addr->ctxt->iov_blob_len++;
		}
		*(addr->category) = value;											//within postcompilation
		*(addr->category_len) = len;
		addr->category_ts = addr->ctxt->ts;	
	}
}

char idmef_addr_rdattr(idmef_addr_t *addr, unsigned int code, unsigned char **value, unsigned int *value_len){ 
	assert(value != NULL);

	if(addr == NULL){
		*value_len = 0;
		return (-2);
	}

	if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_ADDR_CATEGORY){
		if( (addr->category != NULL)
			&& (addr->category_ts == addr->ctxt->ts)){	
			*value_len = *(addr->category_len);
			*value = *(addr->category);
		} else{
			*value_len = 0;
		}
		return (0);
	}else if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_ADDR_ADDRESS){
		if( (addr->address != NULL)
			&& (addr->address_ts == addr->ctxt->ts)){	
			*value_len = *(addr->address_len);
			*value = *(addr->address);
		} else{
			*value_len = 0;
		}
		return (0);
	}else if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_ADDR_NETMASK){
		if( (addr->netmask != NULL)
			&& (addr->netmask_ts == addr->ctxt->ts)){	
			*value_len = *(addr->netmask_len);
			*value = *(addr->netmask);
		} else{
			*value_len = 0;
		}
		return (0);
	}
	return (-1);	//attr's code error
}

char idmef_service_setattr(idmef_service_t *sv, unsigned int code){ 	
	assert(sv != NULL);

 	sv->en_attrs |= (code & IDMEF_MASK_ATTR);

	if(code & IDMEF_ATTR_SERVICE_PORT)
		sv->port_ts = sv->ctxt->ts;

	return 0;
}

char idmef_service_rstattr(idmef_service_t *sv, unsigned int code){ 	
	assert(sv != NULL);

 	sv->en_attrs &= (~code & IDMEF_MASK_ATTR);

	return 0;
}

void idmef_service_wrattr(idmef_service_t *service, unsigned int attr, unsigned char *value, unsigned int len){
	if(service == NULL) return;

	if(attr == IDMEF_ATTR_SERVICE_PORT){
		if(service->port == (unsigned char **)NULL){						//within precompilation 
			service->port = (unsigned char **)&(service->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - service->ctxt->iov_blob_len].iov_base);
			service->port_len = &(service->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - service->ctxt->iov_blob_len].iov_len);
			service->ctxt->iov_blob_len++;
		}
		*(service->port) = value;											//within postcompilation
		*(service->port_len) = len;
		service->port_ts = service->ts;
	}
}

char idmef_service_rdattr(idmef_service_t *service, unsigned int code, unsigned char **value, unsigned int *value_len){ 
	assert(value != NULL);

	if(service == NULL){
		*value_len = 0;
		return (-2);
	}

	if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_SERVICE_PORT){
		if( (service->port != NULL) 
			&& (service->port_ts == service->ctxt->ts)){	
			*value_len = *(service->port_len);
			*value = *(service->port);
		}else{ //whenever not comiled or enabled
			*value_len = 0; 
		}
		return (0);
	}

	return (-1);
}

char idmef_classification_addtag(idmef_classification_t *cls, unsigned int code, void **tag){
	assert(cls != NULL);

	if( (code & IDMEF_MASK_TAG) == IDMEF_TAG_REFERENCE){				//optional tag
		if (cls->references_no >= IDMEF_MAX_REF_NO){
			fprintf(stderr, "%s(%d): pre-established IDMEF_MAX_REF_NO const exceded.\n", __FILE__, __LINE__);
			return (-2);
		}

		if(cls->reference_tag[cls->references_no] == NULL){ 
			if((cls->reference_tag[cls->references_no] = (idmef_reference_t *)malloc(sizeof(idmef_reference_t)*sizeof(unsigned char)) ) == NULL){
				fprintf(stderr, "%s(%s): could not malloc reference_tag's room. %s\n", __FILE__, __LINE__, strerror(errno));
				exit(EXIT_FAILURE);
			}

		 	cls->reference_tag[cls->references_no]->origin		= (unsigned char **)&(cls->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - cls->ctxt->iov_blob_len].iov_base);
		 	cls->reference_tag[cls->references_no]->origin_len = &(cls->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - cls->ctxt->iov_blob_len].iov_len);
			cls->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - cls->ctxt->iov_blob_len].iov_base	= IDMEF_ATTR_VALUE_UNKNOWN;	
			cls->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - cls->ctxt->iov_blob_len].iov_len	= strlen(IDMEF_ATTR_VALUE_UNKNOWN);
			cls->ctxt->iov_blob_len++;

			cls->reference_tag[cls->references_no]->meaning		= (unsigned char **)NULL;	
			cls->reference_tag[cls->references_no]->meaning_len= (unsigned int *)NULL;
			cls->reference_tag[cls->references_no]->name			= (unsigned char **)NULL;	
			cls->reference_tag[cls->references_no]->name_len 	= (unsigned int *)NULL;
			cls->reference_tag[cls->references_no]->url			= (unsigned char **)NULL;	
			cls->reference_tag[cls->references_no]->url_len 	= (unsigned int *)NULL;

			cls->reference_tag[cls->references_no]->ctxt = cls->ctxt;
		}
	 	cls->reference_tag[cls->references_no]->en_attrs = (code & IDMEF_MASK_ATTR) | IDMEF_ATTR_REFERENCE_ORIGIN | IDMEF_ATTR_REFERENCE_NAME | IDMEF_ATTR_REFERENCE_URL;	//mandatory attrs

		if(tag != NULL)	
			*tag = (void *)(cls->reference_tag[cls->references_no]);

		cls->references_no++;
	}
	return (0);
}

char idmef_classification_deltag(idmef_classification_t *cls, unsigned int code, unsigned char pos){
	unsigned int i, j;

	assert(cls != NULL);

	if((code & IDMEF_MASK_TAG) == IDMEF_TAG_REFERENCE){			//optional tag
		assert(pos < IDMEF_MAX_REF_NO);

		if(cls->reference_tag[pos] != NULL){
			//remove pos'th reference_tag element 
			free(cls->reference_tag[pos]);	
			cls->reference_tag[pos] = NULL;

			//then, compress reference_tag[] list ...
			for(i = 0; i < IDMEF_MAX_REF_NO - 1; i++)
				if(cls->reference_tag[i] == NULL){ 
					for(j = i+1; j < IDMEF_MAX_REF_NO; j++)
						if(cls->reference_tag[j] != NULL){
							cls->reference_tag[i] = cls->reference_tag[j];
							cls->reference_tag[j] = NULL;
							break;
						}
					if(j == IDMEF_MAX_REF_NO) break;	//no elems lasts
				}
			cls->references_no--;
		} else 
			return (-2);

		return (0);
	}

 	return (-1);
}

void *idmef_classification_gettag(idmef_classification_t *cls, unsigned int tag, unsigned char pos){
	if(cls == NULL) return (NULL);

	if((tag & IDMEF_MASK_TAG) == IDMEF_TAG_REFERENCE){
		if((pos < 0) || (pos >= IDMEF_MAX_REF_NO)) return (NULL);

		if(cls->reference_tag[0] == NULL){
			idmef_classification_addtag(cls, IDMEF_TAG_REFERENCE, NULL);	
			cls->references_no = 0;	
		}

		if((cls->references_no > pos) || (pos == 0))
			return (cls->reference_tag[pos]);
	}
	return (NULL);
}

void idmef_classification_wrattr(idmef_classification_t *cls, unsigned int attr, unsigned char *value, unsigned int len){
	if(cls == NULL) return;

	if(attr == IDMEF_ATTR_CLASSIFICATION_TEXT){
		if(cls->text == (unsigned char **)NULL){					//within precompilation 
			cls->text = (unsigned char **)&(cls->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - cls->ctxt->iov_blob_len].iov_base);
			cls->text_len = &(cls->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - cls->ctxt->iov_blob_len].iov_len);
			cls->ctxt->iov_blob_len++;
		}
		*(cls->text) = value;										//within postcompilation
		*(cls->text_len) = len;
		cls->text_ts = cls->ctxt->ts;
	}
}

char idmef_classification_rdattr(idmef_classification_t *cls, unsigned int code, unsigned char **value, unsigned int *value_len){ 
	assert(value != NULL);

	if(cls == NULL){
		*value_len = 0;
		return (-2);
	}

	if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_CLASSIFICATION_TEXT){
		if(cls->text_ts == cls->ctxt->ts){	
			*value_len = *(cls->text_len);
			*value = *(cls->text);
		} else{
			*value_len = 0;
		}
		return (0);
	}

	return (-1);

}

idmef_reference_t *idmef_reference_gettag(idmef_classification_t *cls, unsigned char pos){
	if(cls == NULL) return (NULL);

	if(cls->reference_tag[0] == NULL){
		idmef_classification_addtag(cls, IDMEF_TAG_REFERENCE, NULL);	
	}

	if( (cls->references_no > pos) || (pos == 0))
		return (cls->reference_tag[pos]);
	else
		return (NULL);
}

void idmef_reference_wrattr(idmef_reference_t *ref, unsigned int attr, unsigned char *value, unsigned int len){
	if(ref == NULL) return;

	if(attr == IDMEF_ATTR_REFERENCE_ORIGIN){
		if(ref->origin == (unsigned char **)NULL){						//within precompilation 
			ref->origin = (unsigned char **)&(ref->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - ref->ctxt->iov_blob_len].iov_base);
			ref->origin_len = &(ref->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - ref->ctxt->iov_blob_len].iov_len);
			ref->ctxt->iov_blob_len++;
		}
		*(ref->origin) = value;											//within postcompilation
		*(ref->origin_len) = len;
		ref->origin_ts = ref->ts;
		return;
	}
	if(attr == IDMEF_ATTR_REFERENCE_NAME){
		if(ref->name == (unsigned char **)NULL){						//within precompilation 
			ref->name = (unsigned char **)&(ref->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - ref->ctxt->iov_blob_len].iov_base);
			ref->name_len = &(ref->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - ref->ctxt->iov_blob_len].iov_len);
			ref->ctxt->iov_blob_len++;
		}
		*(ref->name) = value;											//within postcompilation
		*(ref->name_len) = len;
		ref->name_ts = ref->ts;
		return;
	}
	if(attr == IDMEF_ATTR_REFERENCE_URL){
		if(ref->url == (unsigned char **)NULL){						//within precompilation 
			ref->url = (unsigned char **)&(ref->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - ref->ctxt->iov_blob_len].iov_base);
			ref->url_len = &(ref->ctxt->iov[IDMEF_MAX_IOV_LEN - 1 - ref->ctxt->iov_blob_len].iov_len);
			ref->ctxt->iov_blob_len++;
		}
		*(ref->url) = value;											//within postcompilation
		*(ref->url_len) = len;
		ref->url_ts = ref->ts;
	}
}

char idmef_reference_setattr(idmef_reference_t *ref, unsigned int code){ 	//TODO: it is really necessary ?????
	assert(ref != NULL);

	//idmef_classification_addtag((idmef_classification_t *)*tag, IDMEF_TAG_REFERENCE|code, tag);		
 	ref->en_attrs |= (code & IDMEF_MASK_ATTR);

	return 0;
}

char idmef_reference_rstattr(idmef_reference_t *ref, unsigned int code){ 	
	assert(ref != NULL);

 	ref->en_attrs &= (~code & IDMEF_MASK_ATTR);

	return 0;
}

char idmef_reference_rdattr(idmef_reference_t *ref, unsigned int code, unsigned char **value, unsigned int *value_len){ 
	assert(value != NULL);

	if(ref == NULL){
		*value_len = 0;
		return (-2);
	}

	if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_REFERENCE_ORIGIN){
		if(ref->origin_ts == ref->ctxt->ts){	
			*value_len = *(ref->origin_len);
			*value = *(ref->origin);
		} else{
			*value_len = 0;
		}
		return (0);
	}

	if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_REFERENCE_NAME){
		if(ref->name_ts == ref->ctxt->ts){	
			*value_len = *(ref->name_len);
			*value = *(ref->name);
		} else{
			*value_len = 0;
		}
		return (0);
	}

	if((code & IDMEF_MASK_ATTR) == IDMEF_ATTR_REFERENCE_URL){
		if(ref->url_ts == ref->ctxt->ts){	
			*value_len = *(ref->url_len);
			*value = *(ref->url);
		} else{
			*value_len = 0;
		}
		return (0);
	}

	return (-1);
}


static void idmef_compile_service_tag(idmef_service_t *service, struct iovec *iov, unsigned char *o){

	(*o)++;
	iov[*o].iov_base = "\t\t\t<idmef:Service>\n";								//Start of Service tag (optional)
	iov[*o].iov_len = strlen("\t\t\t<idmef:Service>\n");									

	//if(service->en_attrs & IDMEF_ATTR_SERVICE_PORT){
	if(service->port_ts == service->ctxt->ts){
		(*o)++;
		iov[*o].iov_base = "\t\t\t\t<idmef:port>";								//port attr (optional)
		iov[*o].iov_len = strlen("\t\t\t\t<idmef:port>");									

		(*o)++;
		if(service->port != (unsigned char **)NULL){	
			iov[*o].iov_base = *(service->port);
			iov[*o].iov_len = *(service->port_len);	
		}else{
			iov[*o].iov_len = 0;
		}
		service->port = (unsigned char **)&(iov[*o].iov_base);
		service->port_len = (unsigned int *)&(iov[*o].iov_len);
	
		(*o)++;
		iov[*o].iov_base = "</idmef:port>\n";		
		iov[*o].iov_len = strlen("</idmef:port>\n");									
	}

	(*o)++;
	iov[*o].iov_base = "\t\t\t</idmef:Service>\n";								//End of Service tag
	iov[*o].iov_len = strlen("\t\t\t</idmef:Service>\n");									
}

static void idmef_compile_address_tag(idmef_addr_t *addr, struct iovec *iov, unsigned char *o){
	(*o)++;
	iov[*o].iov_base = "\t\t\t\t<idmef:Address";									//Start of Addr tag 
	iov[*o].iov_len = strlen("\t\t\t\t<idmef:Address");									

	if(addr->category_ts == addr->ctxt->ts){
		(*o)++;
		iov[*o].iov_base = " category=\"";		
		iov[*o].iov_len = strlen(" category=\"");									

		(*o)++;
		if(addr->category != (unsigned char **)NULL){							//categ attr(optional)
			iov[*o].iov_base = *(addr->category);
			iov[*o].iov_len = *(addr->category_len);	
		}else{
			iov[*o].iov_len = 0;
		}
		addr->category = (unsigned char **)&(iov[*o].iov_base);
		addr->category_len = (unsigned int *)&(iov[*o].iov_len);

		(*o)++;
		iov[*o].iov_base = "\"";		
		iov[*o].iov_len = strlen("\"");									
	}

	(*o)++;
	iov[*o].iov_base = ">\n\t\t\t\t\t<idmef:address>";							//address attr(mandatory)
	iov[*o].iov_len = strlen(">\n\t\t\t\t\t<idmef:address>");									

	(*o)++;
	if(addr->address != (unsigned char **)NULL){		
		iov[*o].iov_base = *(addr->address);
		iov[*o].iov_len = *(addr->address_len);		
	}else{
		iov[*o].iov_len = 0;
	}
	addr->address = (unsigned char **)&(iov[*o].iov_base);
	addr->address_len = (unsigned int *)&(iov[*o].iov_len);

	(*o)++;
	iov[*o].iov_base = "</idmef:address>\n";											 
	iov[*o].iov_len = strlen("</idmef:address>\n");									

	if(addr->netmask_ts == addr->ctxt->ts){
		(*o)++;
		iov[*o].iov_base = "\t\t\t\t\t<idmef:netmask>";						//netmask attr (optional)
		iov[*o].iov_len = strlen("\t\t\t\t\t<idmef:netmask>");									

		(*o)++;
		if(addr->netmask != (unsigned char **)NULL){		
			iov[*o].iov_base = *(addr->netmask);
			iov[*o].iov_len = *(addr->netmask_len);				
		}else{
			iov[*o].iov_len = 0;
		}
		addr->netmask = (unsigned char **)&(iov[*o].iov_base);
		addr->netmask_len = (unsigned int *)&(iov[*o].iov_len);

		(*o)++;
		iov[*o].iov_base = "</idmef:netmask>\n";											
		iov[*o].iov_len = strlen("</idmef:netmask>\n");									
	}

	(*o)++;
	iov[*o].iov_base = "\t\t\t\t</idmef:Address>\n";						//End of Addr tag 
	iov[*o].iov_len = strlen("\t\t\t\t</idmef:Address>\n");									
}


static void idmef_compile_reference_tag(idmef_reference_t *ref, struct iovec *iov, unsigned char *o){

	(*o)++;
	iov[*o].iov_base = "\t\t\t<idmef:Reference";								//Start of Reference tag
	iov[*o].iov_len = strlen("\t\t\t<idmef:Reference");

	(*o)++;
	iov[*o].iov_base = " origin=\"";												//origin attr (mandatory)	
	iov[*o].iov_len = strlen(" origin=\"");									

	(*o)++;
	if(ref->origin != (unsigned char **)NULL){			//check out if settled at compilation time
		iov[*o].iov_base = *(ref->origin);
		iov[*o].iov_len = *(ref->origin_len);
	}else{
		iov[*o].iov_len = 0;
	}
	ref->origin = (unsigned char **)&(iov[*o].iov_base);
	ref->origin_len = &(iov[*o].iov_len);

	(*o)++;
	iov[*o].iov_base = "\"";		
	iov[*o].iov_len = strlen("\"");									

	(*o)++;
	iov[*o].iov_base = ">\n\t\t\t\t<idmef:name>";								//name attr (mandatory)	
	iov[*o].iov_len = strlen(">\n\t\t\t\t<idmef:name>");								

	(*o)++;
	if(ref->name != (unsigned char **)NULL){	
		iov[*o].iov_base = *(ref->name);
		iov[*o].iov_len = *(ref->name_len);		
	}else{
		iov[*o].iov_len = 0;
	}
	ref->name = (unsigned char **)&(iov[*o].iov_base);
	ref->name_len = (unsigned int *)&(iov[*o].iov_len);

	(*o)++;
	iov[*o].iov_base = "</idmef:name>\n";										
	iov[*o].iov_len = strlen("</idmef:name>\n");									

	(*o)++;
	iov[*o].iov_base = "\t\t\t\t<idmef:url>";										//url attr (mandatory)	
	iov[*o].iov_len = strlen("\t\t\t\t<idmef:url>");							

	(*o)++;
	if(ref->url != (unsigned char **)NULL){	
		iov[*o].iov_base = *(ref->url);
		iov[*o].iov_len = *(ref->url_len);	
	}else{
		iov[*o].iov_len = 0;
	}
	ref->url = (unsigned char **)&(iov[*o].iov_base);
	ref->url_len = (unsigned int *)&(iov[*o].iov_len);

	(*o)++;
	iov[*o].iov_base = "</idmef:url>\n";							
	iov[*o].iov_len = strlen("</idmef:url>\n");				

	(*o)++;
	iov[*o].iov_base = "\t\t\t</idmef:Reference>\n";							//End of Reference tag
	iov[*o].iov_len = strlen("\t\t\t</idmef:Reference>\n");
}

static void idmef_compile_node_tag(idmef_node_t *node, struct iovec *iov, unsigned char *o){
	unsigned int i;

	(*o)++;
	iov[*o].iov_base = "\t\t\t<idmef:Node>\n";						//Start of Node tag (optional)
	iov[*o].iov_len = strlen("\t\t\t<idmef:Node>\n");									

	for(i = 0; i < node->addresses_no; i++){							//Search for Addr tag (optional)
		idmef_compile_address_tag(node->address_tag[i], iov, o);
	}						
	(*o)++;
	iov[*o].iov_base = "\t\t\t</idmef:Node>\n";							
	iov[*o].iov_len = strlen("\t\t\t</idmef:Node>\n");
}





/* 
 * Conversion of idmef-tree data structure to iov[] array.
 * TODO: check en_attrs and alloc mem accordingly.
 */

void idmef_compile(idmef_t *ctxt){
	unsigned char offset, i;
	struct iovec *iov;

	assert(ctxt != NULL);

	iov = (struct iovec *)malloc(IDMEF_MAX_IOV_LEN*sizeof(struct iovec));
	assert(iov != NULL);


	//start (re)compilation, here
	offset = 0;								//Start of Message tag
	iov[offset].iov_base = "<idmef:IDMEF-Message version=\"1.0\" xmlns:idmef=\"http://iana.org/idmef\">\n";
	iov[offset].iov_len = strlen("<idmef:IDMEF-Message version=\"1.0\" xmlns:idmef=\"http://iana.org/idmef\">\n");

	if(ctxt->alert_tag->ts == ctxt->ts){
		offset++;																			
		iov[offset].iov_base = "\t<idmef:Alert ";
		iov[offset].iov_len = strlen("\t<idmef:Alert ");

		if(ctxt->alert_tag->messageid_ts == ctxt->ts){
			offset++;																			
			iov[offset].iov_base = "messageid=\"";
			iov[offset].iov_len = strlen("messageid=\"");

			offset++;																			
			if(ctxt->alert_tag->messageid != NULL){
				iov[offset].iov_base = *(ctxt->alert_tag->messageid);
				iov[offset].iov_len = *(ctxt->alert_tag->messageid_len);														
			}else
				iov[offset].iov_len = 0;
			ctxt->alert_tag->messageid = (unsigned char **)&(iov[offset].iov_base);		//message id attribute (mandatory)
			ctxt->alert_tag->messageid_len = &(iov[offset].iov_len);
		}//Note: necessary, whenever compiled before setting its value 
		offset++;
		iov[offset].iov_base = "\">\n";
		iov[offset].iov_len = strlen("\">\n");


		offset++;
		iov[offset].iov_base = "\t\t<idmef:Analyzer name=\"";						//Start of Analyzer tag(mandatory)
		iov[offset].iov_len = strlen("\t\t<idmef:Analyzer name=\"");

		offset++;
		if(ctxt->alert_tag->analyzer_tag.name != (unsigned char **)NULL){				//name attr (mandatory)
			iov[offset].iov_base = *(ctxt->alert_tag->analyzer_tag.name);
			iov[offset].iov_len = *(ctxt->alert_tag->analyzer_tag.name_len);														
		}else{
			iov[offset].iov_len = 0;
		}
		ctxt->alert_tag->analyzer_tag.name = (unsigned char **)&(iov[offset].iov_base);
		ctxt->alert_tag->analyzer_tag.name_len = &(iov[offset].iov_len);


		offset++;
		iov[offset].iov_base = "\">\n\t\t</idmef:Analyzer>\n\t\t<idmef:CreateTime>";		//End of Analyzer tag
		iov[offset].iov_len = strlen("\">\n\t\t</idmef:Analyzer>\n\t\t<idmef:CreateTime>");

		offset++;
		if(ctxt->alert_tag->createtime_tag.body != (unsigned char **)NULL){			//body attr(mandatory)
			iov[offset].iov_base = *(ctxt->alert_tag->createtime_tag.body);
			iov[offset].iov_len = *(ctxt->alert_tag->createtime_tag.body_len);														
		}else{
			iov[offset].iov_len = 0;
		}
		ctxt->alert_tag->createtime_tag.body = (unsigned char **)&(iov[offset].iov_base);
		ctxt->alert_tag->createtime_tag.body_len = &(iov[offset].iov_len);

		offset++;
		iov[offset].iov_base = "</idmef:CreateTime>\n";							
		iov[offset].iov_len = strlen("</idmef:CreateTime>\n");						//End of CreateTime tag


		for(i = 0; i < ctxt->alert_tag->targets_no; i++){								//Search for Target tag (optional)
			offset++;
			iov[offset].iov_base = "\t\t<idmef:Target>\n";							//Start of Target tag
			iov[offset].iov_len = strlen("\t\t<idmef:Target>\n");									

			if(ctxt->alert_tag->target_tag[i]->node_tag != NULL){
				idmef_compile_node_tag(ctxt->alert_tag->target_tag[i]->node_tag, iov, &offset);
			}

			if(ctxt->alert_tag->target_tag[i]->service_tag != NULL){
				idmef_compile_service_tag(ctxt->alert_tag->target_tag[i]->service_tag, iov, &offset);
			}
			offset++;
			iov[offset].iov_base = "\t\t</idmef:Target>\n";							//End of Target tag
			iov[offset].iov_len = strlen("\t\t</idmef:Target>\n");									
		}	//end of for( ...target_tag[i] ...


		for(i = 0; i < ctxt->alert_tag->sources_no; i++){									//Search for Source tag (optional)
			offset++;
			iov[offset].iov_base = "\t\t<idmef:Source>\n";						//Start of Source tag
			iov[offset].iov_len = strlen("\t\t<idmef:Source>\n");									

			if(ctxt->alert_tag->source_tag[i]->node_tag != NULL)			
				idmef_compile_node_tag(ctxt->alert_tag->source_tag[i]->node_tag, iov, &offset);


			if(ctxt->alert_tag->source_tag[i]->service_tag != NULL)
				idmef_compile_service_tag(ctxt->alert_tag->source_tag[i]->service_tag, iov, &offset);

			offset++;
			iov[offset].iov_base = "\t\t</idmef:Source>\n";						//End of Source tag
			iov[offset].iov_len = strlen("\t\t</idmef:Source>\n");						
		} //end of for( ... source_tag[i] ...

		offset++;
		iov[offset].iov_base = "\t\t<idmef:Classification text=\"";				//Start of Classification tag(mandatory)
		iov[offset].iov_len = strlen("\t\t<idmef:Classification text=\"");	

		offset++;																				//text attribute(mandatory)
		if(ctxt->alert_tag->classification_tag.text != (unsigned char **)NULL){						
			iov[offset].iov_base = *(ctxt->alert_tag->classification_tag.text);
			iov[offset].iov_len = *(ctxt->alert_tag->classification_tag.text_len);	
		}else{
			iov[offset].iov_len = 0;
		}
		ctxt->alert_tag->classification_tag.text = (unsigned char **)&(iov[offset].iov_base);
		ctxt->alert_tag->classification_tag.text_len = &(iov[offset].iov_len);

		offset++;
		iov[offset].iov_base = "\">\n";		
		iov[offset].iov_len = strlen("\">\n");

		for(i = 0; i < ctxt->alert_tag->classification_tag.references_no; i++)	//Search for Reference tag (optional)
			idmef_compile_reference_tag(ctxt->alert_tag->classification_tag.reference_tag[i], iov, &offset);

		offset++;
		iov[offset].iov_base = "\t\t</idmef:Classification>\n";					//End of classification tag
		iov[offset].iov_len = strlen("\t\t</idmef:Classification>\n");
	
		offset++;
		iov[offset].iov_base = "\t</idmef:Alert>\n";									//End of Alert tag
		iov[offset].iov_len = strlen("\t</idmef:Alert>\n");
	}

	if(ctxt->heartbeat_tag != NULL){ 
		//TODO: ...
	}//end of "heartbeat_tag"	

	offset++;
	iov[offset].iov_base = "</idmef:IDMEF-Message>\n\n";							//End of Message tag
	iov[offset].iov_len = strlen("</idmef:IDMEF-Message>\n\n");



	if(ctxt->iov != NULL){
		free(ctxt->iov);
	}
	ctxt->iov = iov;

	assert(offset < IDMEF_MAX_IOV_LEN);
	ctxt->iov_len = offset + 1;
	ctxt->iov_blob_len = 0;
}


void idmef_write(idmef_t *ctxt){
	unsigned char a;
	unsigned int c;
	ssize_t n;

	assert(ctxt != NULL);

	//simple check for the presence of mandatory attributes
	//if(ctxt->alert_tag != NULL){
		//assert( ctxt->alert_tag->messageid_len  != NULL); 
		//assert( ctxt->alert_tag->analyzer_tag.name_len  != NULL); 
		//assert( ctxt->alert_tag->createtime_tag.body_len  != NULL); 
		//assert( ctxt->alert_tag->classification_tag.text_len  != NULL); 

		//assert( *(ctxt->alert_tag->messageid_len)  != 0); 
		//assert( *(ctxt->alert_tag->analyzer_tag.name_len)  != 0); 
		//assert( *(ctxt->alert_tag->createtime_tag.body_len)  != 0); 
		//assert( *(ctxt->alert_tag->classification_tag.text_len)  != 0); 


		//TODO: check for addr tag & its mandatory attribute, "address"
		//...
	//} //else{
	//	exit(EXIT_FAILURE); 	//error
	//	fprintf(stderr, "Missing mandatory tags/atrributes !\n");
	//}

	if(ctxt->mode_out == IDMEF_MODE_FILE || ctxt->mode_out == IDMEF_MODE_FS){
		n = writev(ctxt->fd_out, ctxt->iov, ctxt->iov_len);
		fflush(ctxt->fs_out);
	}

	if(ctxt->mode_out == IDMEF_MODE_SOCK || ctxt->mode_out == IDMEF_MODE_FS){
		n = writev(ctxt->sd_out, ctxt->iov, ctxt->iov_len);
	}
}

char idmef_loop(void){

	pthread_join(tid_idmefserver, NULL);

	return (0);
}

char idmef_free(idmef_t *ctxt){
	assert(ctxt != NULL);

	//TODO: free iov[] space; must go in depth

	if(ctxt->fs_out != NULL){
		fflush(ctxt->fs_out);
		fclose(ctxt->fs_out);
	}

	if(ctxt->sd_out >= 0){
		close(ctxt->sd_out);
	}

	return (0);
}






/*
ANNEX
=====
	fprintf(idmef_fd, "<idmef:IDMEF-Message version=\"1.0\" xmlns:idmef=\"http://iana.org/idmef\" />\n");
		fprintf(idmef_fd, "\t<idmef:Alert messageid=\"%s\">\n", "abcdef12345");			//TODO: replace w/ event_id
			fprintf(idmef_fd, "\t\t<idmef:Analyzer name=\"%s\">\n", IDS_ANALYZERID);
			fprintf(idmef_fd, "\t\t</idmef:Analyzer>\n");

			fprintf(idmef_fd, "\t\t<idmef:CreateTime>%s</idmef:CreateTime>\n", "2015-01-20T16:54:00+2:00");

			fprintf(idmef_fd, "\t\t<idmef:Classification text=\"%s\">\n", "TCP egress attempt ! ....");
			fprintf(idmef_fd, "\t\t</idmef:Classification>\n");
		fprintf(idmef_fd, "\t</idmef:Alert>\n");
	fprintf(idmef_fd, "</idmef:IDMEF-Message>\n\n");
*/
