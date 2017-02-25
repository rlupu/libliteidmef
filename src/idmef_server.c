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
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>

#include "idmef_plugin.h"
#include "commons/utils.h"
#include "commons/stack.h"

#define IDMEF_PARSER_STATE_IDLE                 0
#define IDMEF_PARSER_STATE_TAGMARGIN            1	
#define IDMEF_PARSER_STATE_TAGSTART0            2	
#define IDMEF_PARSER_STATE_TAGSTART1            3	
#define IDMEF_PARSER_STATE_TAGEND0              4	
#define IDMEF_PARSER_STATE_TAGEND1              5	
#define IDMEF_PARSER_STATE_TAGEND2              6	

#define IDMEF_PARSER_STATE_MESSAGE              7
#define IDMEF_PARSER_STATE_TAGEND_MESSAGE       8	
#define IDMEF_PARSER_STATE_ALERT0               9	
#define IDMEF_PARSER_STATE_ALERT1               10	
#define IDMEF_PARSER_STATE_ALERT2               11	
#define IDMEF_PARSER_STATE_ANALYZER0            12
#define IDMEF_PARSER_STATE_ANALYZER1            13	
#define IDMEF_PARSER_STATE_ANALYZER2            14	
#define IDMEF_PARSER_STATE_CREATETIME0          15	
#define IDMEF_PARSER_STATE_CREATETIME1          16	
#define IDMEF_PARSER_STATE_CREATETIME2          17	
#define IDMEF_PARSER_STATE_CREATETIME3          18	
#define IDMEF_PARSER_STATE_TARGET               19	
#define IDMEF_PARSER_STATE_SOURCE               20	
#define IDMEF_PARSER_STATE_NODE                 21	
#define IDMEF_PARSER_STATE_ADDRESS0             22	
#define IDMEF_PARSER_STATE_ADDRESS1             23	
#define IDMEF_PARSER_STATE_ADDRESS2             24	
#define IDMEF_PARSER_STATE_ADDRESS3             25	
#define IDMEF_PARSER_STATE_ADDRESS4             26
#define IDMEF_PARSER_STATE_NETMASK0             27	
#define IDMEF_PARSER_STATE_NETMASK1             28	
#define IDMEF_PARSER_STATE_SERVICE              29	
#define IDMEF_PARSER_STATE_PORT0                30	
#define IDMEF_PARSER_STATE_PORT1                31	
#define IDMEF_PARSER_STATE_CLASSIFICATION0      32	
#define IDMEF_PARSER_STATE_CLASSIFICATION1      33	
#define IDMEF_PARSER_STATE_CLASSIFICATION2      34	
#define IDMEF_PARSER_STATE_REFERENCE0           35	
#define IDMEF_PARSER_STATE_REFERENCE1           36	
#define IDMEF_PARSER_STATE_REFERENCE2           37	
#define IDMEF_PARSER_STATE_NAME0                38	
#define IDMEF_PARSER_STATE_NAME1                39	
#define IDMEF_PARSER_STATE_URL0                 40
#define IDMEF_PARSER_STATE_URL1                 41	



pthread_t tid_idmefserver;



//run as never ending thread
void *idmef_server(void *ctxt){
	int ids_sa_len, newsd;
	struct sockaddr_in ids_sa;
	pid_t pid;


	ids_sa_len = sizeof(ids_sa);

	if( ((idmef_t *)ctxt)->iov == NULL){
		((idmef_t *)ctxt)->iov = (struct iovec *)malloc(IDMEF_MAX_IOV_LEN*sizeof(struct iovec));
		assert( ((idmef_t *)ctxt)->iov != NULL);
	}

	fprintf(stdout, "Waiting for IDS(s) to connect ... .\n");

	while(1){
		if((newsd = accept(((idmef_t *)ctxt)->sd_in, (struct sockaddr *)&ids_sa, &ids_sa_len)) < 0){	
			perror("accept");
			exit(EXIT_FAILURE);
		}
		fprintf(stdout, "IDS connected from ...%s .\n", inet_ntoa(ids_sa.sin_addr));

		pid = fork();

		if(pid == 0){
			unsigned int i, j, state;
			unsigned char *prev_iovbase = NULL;
			stack_t *tags = NULL, *ptags = NULL, *ptags_0 = NULL;
			unsigned char rbuff[8192];
			int rbytes;
			struct timeval tv;

			//close(sd);
			stack_init();
			stack_new(STACK_UINT, 16, &tags);          //size of stack is 16 (i.e. IDMEF message depth)
			stack_new(STACK_VOID_PTR, 16, &ptags);     //idem
			stack_new(STACK_VOID_PTR, 16, &ptags_0);   //idem

			while(1){
				rbytes = 0;
				rbytes = recvfrom(newsd, rbuff, sizeof(rbuff), 0, (struct sockaddr *)NULL, NULL);
#ifdef IDMEF_DEBUG
				//rbuff[rbytes] = EOS;
				//fprintf(stdout, "%s", rbuff);
#endif
				prev_iovbase = rbuff;
				((idmef_t *)ctxt)->iov_len = 0;
				gettimeofday(&tv, NULL);
				((idmef_t *)ctxt)->ts = tv.tv_usec;
				state = IDMEF_PARSER_STATE_IDLE;

				for(i = 0; i < rbytes;){
					if((rbuff[i] == ' ') || (rbuff[i] == '\t') || (rbuff[i] == '\n')){ 
						i++; continue; 
					} //eat up blank chars

					switch(state){
					case IDMEF_PARSER_STATE_IDLE:		
						if(rbuff[i] == '<') 	state = IDMEF_PARSER_STATE_TAGMARGIN;
						i++;
						break;

					case IDMEF_PARSER_STATE_TAGMARGIN:
						if(rbuff[i] == '/'){
							i++; state = IDMEF_PARSER_STATE_TAGEND0;
							break;
						}
						if(strncasecmp("idmef", rbuff+i , 5) == 0){
							i = i + 5; state = IDMEF_PARSER_STATE_TAGSTART0;
							break;
						}
						i++;
						break;

					case IDMEF_PARSER_STATE_TAGSTART0:
						if(rbuff[i] == ':')	state = IDMEF_PARSER_STATE_TAGSTART1;
						i++;
						break;

					case IDMEF_PARSER_STATE_TAGEND0:
						if(strncasecmp("idmef", rbuff+i , 5) == 0){
							state = IDMEF_PARSER_STATE_TAGEND1;
							i = i + 5; 
							break;
						}
						i++;
						break;

					case IDMEF_PARSER_STATE_TAGEND1:
						if(rbuff[i] == ':')	state = IDMEF_PARSER_STATE_TAGEND2;
						i++;
						break;

					case IDMEF_PARSER_STATE_TAGSTART1:{
						unsigned int current_tagbody;
						void *current_parenttag = NULL;
						void *current_parenttag_0 = NULL;

						stack_peek(tags, (any_t *)&current_tagbody);		
						stack_peek(ptags, (any_t *)&current_parenttag);
						stack_peek(ptags_0, (any_t *)&current_parenttag_0);

						if(strncasecmp("IDMEF-Message", rbuff+i, 13) == 0){
#ifdef IDMEF_DEBUG
							fprintf(stdout, "New IDMEF message received (state=%d)!\n", state);
#endif
							((idmef_t *)ctxt)->iov[0].iov_base = prev_iovbase;
							((idmef_t *)ctxt)->iov[0].iov_len = rbytes;	

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);	
							state = IDMEF_PARSER_STATE_MESSAGE;
							i = i + 13;	
						} else if(strncasecmp("Alert", rbuff+i, 5) == 0){
#ifdef IDMEF_DEBUG
							fprintf(stdout, "\tALERT tag found (state=%d)!\n", state);
#endif
							if(((idmef_t *)ctxt)->alert_tag != NULL){    //also, check for the others hooked (opt.)tags
								((idmef_t *)ctxt)->alert_tag->targets_no = 0;
								((idmef_t *)ctxt)->alert_tag->sources_no = 0;
								//init, ...
								stack_push(tags, IDMEF_TAG_ALERT);
								stack_push(ptags, ((idmef_t *)ctxt)->alert_tag);
								stack_push(ptags_0, ((idmef_t *)ctxt)->alert_tag);
								((idmef_t *)ctxt)->alert_tag->ts = ((idmef_t *)ctxt)->ts;
								state = IDMEF_PARSER_STATE_ALERT0;
							}else
								//TODO: go to Alert tag end
								state = IDMEF_PARSER_STATE_IDLE;
							i = i + 5;			
						} else if(strncasecmp("Analyzer", rbuff+i, 8) == 0){
							if(current_tagbody == IDMEF_TAG_ALERT){     //TODO: check out corresp. attr is enabled
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\tANALYZER tag found (state=%d)!\n", state);
#endif
								state = IDMEF_PARSER_STATE_ANALYZER0;
							} else
									state = IDMEF_PARSER_STATE_IDLE;
							i = i + 8;			
						} else if(strncasecmp("CreateTime", rbuff+i, 10) == 0){
							if(current_tagbody == IDMEF_TAG_ALERT){     //TODO: check out corresp. attr is enabled
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\tCREATETIME tag found (state=%d)!\n", state);
#endif
								state = IDMEF_PARSER_STATE_CREATETIME0;
							}else
								state = IDMEF_PARSER_STATE_IDLE;
							i = i + 10;			
						} else if(strncasecmp("Node", rbuff+i, 4) == 0){
							if(current_tagbody == IDMEF_TAG_TARGET){    //TODO: check out corresp. attr is enabled
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\tNODE tag found (state=%d)!\n", state);
#endif
								if(((idmef_target_t *)current_parenttag_0)->node_tag != NULL){	
									if(((idmef_target_t *)current_parenttag)->node_tag == NULL){  //create new node_tag
										idmef_target_addtag(((idmef_target_t *)current_parenttag), IDMEF_TAG_NODE |\
									 		((idmef_target_t *)current_parenttag_0)->node_tag->en_attrs, NULL);
									}
									((idmef_target_t *)current_parenttag)->node_tag->addresses_no = 0;  //reset
									stack_push(tags, IDMEF_TAG_NODE);
									stack_push(ptags, ((idmef_target_t *)current_parenttag)->node_tag);
									stack_push(ptags_0, ((idmef_target_t *)current_parenttag_0)->node_tag);
									state = IDMEF_PARSER_STATE_NODE;
								} else
									state = IDMEF_PARSER_STATE_IDLE;
							} else if(current_tagbody == IDMEF_TAG_SOURCE){
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\tSNODE tag found (state=%d)!\n", state);
#endif
								if(((idmef_source_t *)current_parenttag_0)->node_tag != NULL){	
									if(((idmef_source_t *)current_parenttag)->node_tag == NULL){ //create new node_tag
										idmef_source_addtag(((idmef_source_t *)current_parenttag), IDMEF_TAG_NODE |\
											((idmef_source_t *)current_parenttag_0)->node_tag->en_attrs, NULL);
									}
									((idmef_source_t *)current_parenttag)->node_tag->addresses_no = 0; //reset

									stack_push(tags, IDMEF_TAG_NODE);
									stack_push(ptags, ((idmef_source_t *)current_parenttag)->node_tag); 
									stack_push(ptags_0, ((idmef_source_t *)current_parenttag_0)->node_tag); 
									state = IDMEF_PARSER_STATE_NODE;
								} else
									state = IDMEF_PARSER_STATE_IDLE;
							} else{
								state = IDMEF_PARSER_STATE_IDLE;
							}
							i = i + 4;			

						} else if(strncasecmp("Target", rbuff+i, 6) == 0){
							if(current_tagbody == IDMEF_TAG_ALERT){    //TODO: check out corresp. attr is enabled
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\tTARGET tag found (state=%d)!\n", state);
#endif
								if(((idmef_alert_t *)current_parenttag_0)->target_tag[0] != NULL){	
									unsigned char tn = ((idmef_alert_t *)current_parenttag)->targets_no;

									if(((idmef_alert_t *)current_parenttag)->target_tag[tn] == NULL){
										idmef_alert_addtag((idmef_alert_t *)current_parenttag, IDMEF_TAG_TARGET |\
											((idmef_alert_t *)current_parenttag_0)->target_tag[0]->en_attrs, NULL);
									}  else
										((idmef_alert_t *)current_parenttag)->targets_no++;
								
									stack_push(tags, IDMEF_TAG_TARGET);
									stack_push(ptags, ((idmef_alert_t *)current_parenttag)->target_tag[tn]);
									stack_push(ptags_0, ((idmef_alert_t *)current_parenttag_0)->target_tag[0]);
									state = IDMEF_PARSER_STATE_TARGET;
								} else{
									state = IDMEF_PARSER_STATE_IDLE;
								}
							} else{
								state = IDMEF_PARSER_STATE_IDLE;
							}
							i = i + 6;			

						} else if(strncasecmp("Source", rbuff+i, 6) == 0){
							if(current_tagbody == IDMEF_TAG_ALERT){    //TODO: check out corresp. attr is enabled
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\tSOURCE tag found (state=%d)!\n", state);
#endif
								if(((idmef_alert_t *)current_parenttag_0)->source_tag[0] != NULL){
									unsigned char sn = ((idmef_alert_t *)current_parenttag)->sources_no;

									if(((idmef_alert_t *)current_parenttag)->source_tag[sn] == NULL){
										idmef_alert_addtag((idmef_alert_t *)current_parenttag, IDMEF_TAG_SOURCE |\
											((idmef_alert_t *)current_parenttag_0)->source_tag[0]->en_attrs, NULL);
									} else 
										((idmef_alert_t *)current_parenttag)->sources_no++;

									stack_push(tags, IDMEF_TAG_SOURCE);
									stack_push(ptags, ((idmef_alert_t *)current_parenttag)->source_tag[sn]);	
									stack_push(ptags_0, ((idmef_alert_t *)current_parenttag_0)->source_tag[0]);	
									state = IDMEF_PARSER_STATE_SOURCE;
								} else{
									state = IDMEF_PARSER_STATE_IDLE;
								}
							} else{
								state = IDMEF_PARSER_STATE_IDLE;
							}
							i = i + 6;			

						} else if(strncasecmp("Address", rbuff+i, 7) == 0){
							if(current_tagbody == IDMEF_TAG_NODE){
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\t\tADDRESS tag found (state=%d)!\n", state);
#endif
								if( ((idmef_node_t *)current_parenttag_0)->address_tag[0] != NULL){
									unsigned char an = ((idmef_node_t *)current_parenttag)->addresses_no;

									if(((idmef_node_t *)current_parenttag)->address_tag[an] == NULL){
										idmef_node_addtag((idmef_node_t *)current_parenttag, IDMEF_TAG_ADDR |\
											((idmef_node_t *)current_parenttag_0)->address_tag[0]->en_attrs, NULL);
									} else
										((idmef_node_t *)current_parenttag)->addresses_no++;

									stack_push(tags, IDMEF_TAG_ADDR);
									stack_push(ptags, ((idmef_node_t *)current_parenttag)->address_tag[an]);
									stack_push(ptags_0, ((idmef_node_t *)current_parenttag_0)->address_tag[0]);
									state = IDMEF_PARSER_STATE_ADDRESS0;
								} else{
									state = IDMEF_PARSER_STATE_IDLE;
								}
							}else if(current_tagbody == IDMEF_TAG_ADDR){
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\t\t\tADDRESS tag found (state=%d)!\n", state);
#endif
								stack_push(tags, IDMEF_TAG_ADDR);
								stack_push(ptags, ((idmef_addr_t *)current_parenttag));
								stack_push(ptags_0, ((idmef_addr_t *)current_parenttag_0));
								state = IDMEF_PARSER_STATE_ADDRESS4;
							} else
								state = IDMEF_PARSER_STATE_IDLE;
							i = i + 7;			

						} else if(strncasecmp("netmask", rbuff+i, 7) == 0){
							if(current_tagbody == IDMEF_TAG_ADDR){
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\t\t\tNETMASK tag found (state=%d)!\n", state);
#endif
								state = IDMEF_PARSER_STATE_NETMASK0;
							} else
								state = IDMEF_PARSER_STATE_IDLE;
							i = i + 7;			

						} else if(strncasecmp("Service", rbuff+i, 7) == 0){
							state = IDMEF_PARSER_STATE_IDLE;
							if(current_tagbody == IDMEF_TAG_TARGET){
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\tSERVICE tag found (state=%d)!\n", state);
#endif
								if(((idmef_target_t *)current_parenttag_0)->service_tag != NULL){ //check if service enabled
									if(((idmef_target_t *)current_parenttag)->service_tag == NULL)
										idmef_target_addtag( (idmef_target_t *)current_parenttag, IDMEF_TAG_SERVICE |\
											((idmef_target_t *)current_parenttag_0)->service_tag->en_attrs, NULL);
									stack_push(tags, IDMEF_TAG_SERVICE);
									stack_push(ptags, ((idmef_target_t *)current_parenttag)->service_tag);
									stack_push(ptags_0, ((idmef_target_t *)current_parenttag_0)->service_tag);
									state = IDMEF_PARSER_STATE_SERVICE;
								}
							}else if (current_tagbody == IDMEF_TAG_SOURCE){
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\tSERVICE tag found (state=%d)!\n", state);
#endif
								if(((idmef_source_t *)current_parenttag_0)->service_tag != NULL){ //check if service enabled
									if(((idmef_source_t *)current_parenttag)->service_tag == NULL)
										idmef_source_addtag( (idmef_source_t *)current_parenttag, IDMEF_TAG_SERVICE |\
											((idmef_source_t *)current_parenttag_0)->service_tag->en_attrs, NULL);

									stack_push(tags, IDMEF_TAG_SERVICE);
									stack_push(ptags, ((idmef_source_t *)current_parenttag)->service_tag);
									stack_push(ptags_0, ((idmef_source_t *)current_parenttag_0)->service_tag);
									state = IDMEF_PARSER_STATE_SERVICE;
								}	
							}
							i = i + 7;			

						} else if(strncasecmp("port", rbuff+i, 4) == 0){
							if(current_tagbody == IDMEF_TAG_SERVICE){     //TODO: check out corresp. attr is enabled
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\t\tPORT tag found (state=%d)!\n", state);
#endif
								//if(current_parenttag->en_attrs){         //ramp up parser processing 
									state = IDMEF_PARSER_STATE_PORT0;
								//}
							}else
								state = IDMEF_PARSER_STATE_IDLE;
							i = i + 4;			

						} else if(strncasecmp("Classification", rbuff+i, 14) == 0){
							if(current_tagbody == IDMEF_TAG_ALERT){      //TODO: check out corresp. attr is enabled
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\tCLASSIFICATION tag found (state=%d)!\n", state);
#endif
								((idmef_alert_t *)current_parenttag)->classification_tag.references_no = 0; //reset
								stack_push(tags, IDMEF_TAG_CLASSIFICATION);
								stack_push(ptags, &( ((idmef_alert_t *)current_parenttag)->classification_tag));
								stack_push(ptags_0, &( ((idmef_alert_t *)current_parenttag_0)->classification_tag));
								state = IDMEF_PARSER_STATE_CLASSIFICATION0;
							} else
								state = IDMEF_PARSER_STATE_IDLE;
							i = i + 14;			

						} else if(strncasecmp("Reference", rbuff+i, 9) == 0){
							if(current_tagbody == IDMEF_TAG_CLASSIFICATION){  //TODO: check out corresp. attr is enabled
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\tREFERENCE tag found (state=%d)!\n", state);
#endif
								if( ((idmef_classification_t *)current_parenttag_0)->reference_tag[0] != NULL){ 
									//TODO:replace alerttag with parenttag
									unsigned char rn = ((idmef_classification_t *)current_parenttag)->references_no;

									if( ((idmef_classification_t *)current_parenttag)->reference_tag[rn] == NULL){
										idmef_classification_addtag((idmef_classification_t *)current_parenttag,\
                                 IDMEF_TAG_REFERENCE | ((idmef_classification_t *)current_parenttag_0)->reference_tag[0]\
	                              ->en_attrs, NULL);
									} 
									((idmef_classification_t *)current_parenttag)->references_no++;

									stack_push(tags, IDMEF_TAG_REFERENCE);
									stack_push(ptags, ((idmef_classification_t *)current_parenttag)->reference_tag[rn]);
									stack_push(ptags_0, ((idmef_classification_t *)current_parenttag_0)->reference_tag[0]);
									state = IDMEF_PARSER_STATE_REFERENCE0;
								} else
									state = IDMEF_PARSER_STATE_IDLE;
							}else
								state = IDMEF_PARSER_STATE_IDLE;
							i = i + 9;			

						} else if(strncasecmp("name", rbuff+i, 4) == 0){
							if(current_tagbody == IDMEF_TAG_REFERENCE){	
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\t\tNAME tag found (state=%d)!\n", state);
#endif
								state = IDMEF_PARSER_STATE_NAME0;
							}else
								state = IDMEF_PARSER_STATE_IDLE;
							i = i + 4;			

						} else if(strncasecmp("url", rbuff+i, 3) == 0){
							if(current_tagbody == IDMEF_TAG_REFERENCE){	
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\t\tURL tag found (state=%d)!\n", state);
#endif
								state = IDMEF_PARSER_STATE_URL0;
							}else
								state = IDMEF_PARSER_STATE_IDLE;

							i = i + 3;			
						} else{
							i++;
							state = IDMEF_PARSER_STATE_IDLE;
						}
						break;
					}


					case IDMEF_PARSER_STATE_TAGEND2:{
						unsigned int current_tagbody;

						stack_peek(tags, (any_t *)&current_tagbody);		

						if(strncasecmp("IDMEF-Message", rbuff+i, 13) == 0){
							i = i + 13;	
							state = IDMEF_PARSER_STATE_TAGEND_MESSAGE;

						}else if(strncasecmp("Alert", rbuff+i, 5) == 0){
							if(current_tagbody == IDMEF_TAG_ALERT){
								stack_pop(tags, NULL);
								stack_pop(ptags, NULL);
								stack_pop(ptags_0, NULL);
							}
							i = i + 5;
							state = IDMEF_PARSER_STATE_IDLE;

						}else if(strncasecmp("Target", rbuff+i, 6) == 0){
							if(current_tagbody == IDMEF_TAG_TARGET){			
								stack_pop(tags, NULL);
								stack_pop(ptags, NULL);
								stack_pop(ptags_0, NULL);
							}
							i = i + 6;
							state = IDMEF_PARSER_STATE_IDLE;

						}else if(strncasecmp("Source", rbuff+i, 6) == 0){
							if(current_tagbody == IDMEF_TAG_SOURCE){		
								stack_pop(tags, NULL);
								stack_pop(ptags, NULL);
								stack_pop(ptags_0, NULL);
							}
							i = i + 6;
							state = IDMEF_PARSER_STATE_IDLE;

						}else if(strncasecmp("Node", rbuff+i, 4) == 0){
							if(current_tagbody == IDMEF_TAG_NODE){		
								stack_pop(tags, NULL);
								stack_pop(ptags, NULL);
								stack_pop(ptags_0, NULL);
							}
							i = i + 4;
							state = IDMEF_PARSER_STATE_IDLE;

						}else if(strncasecmp("Address", rbuff+i, 7) == 0){
							if(current_tagbody == IDMEF_TAG_ADDR){	
								stack_pop(tags, NULL);
								stack_pop(ptags, NULL);
								stack_pop(ptags_0, NULL);
							}
							i = i + 7;
							state = IDMEF_PARSER_STATE_IDLE;

						}else if(strncasecmp("Service", rbuff+i, 7) == 0){
							if(current_tagbody == IDMEF_TAG_SERVICE){	
								stack_pop(tags, NULL);
								stack_pop(ptags, NULL);
								stack_pop(ptags_0, NULL);
							}
							i = i +7;
							state = IDMEF_PARSER_STATE_IDLE;

						}else if(strncasecmp("Classification", rbuff+i, 14) == 0){
							if(current_tagbody == IDMEF_TAG_CLASSIFICATION){	
								stack_pop(tags, NULL);
								stack_pop(ptags, NULL);
								stack_pop(ptags_0, NULL);
							}
							i = i + 14;
							state = IDMEF_PARSER_STATE_IDLE;

						}else if(strncasecmp("Reference", rbuff+i, 9) == 0){
							if(current_tagbody == IDMEF_TAG_REFERENCE){		
								stack_pop(tags, NULL);
								stack_pop(ptags, NULL);
								stack_pop(ptags_0, NULL);
							}
							i = i +9;
							state = IDMEF_PARSER_STATE_IDLE;

						}else {
							i++;	
							state = IDMEF_PARSER_STATE_IDLE;
						}

						break;
					}
					case IDMEF_PARSER_STATE_TAGEND_MESSAGE:
                  //compute prev iov_len
						((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len-1].iov_len = (rbuff+i+1) - prev_iovbase;
						if(((idmef_t *)ctxt)->cbfunc != NULL) 	((idmef_t *)ctxt)->cbfunc();
							
						prev_iovbase = rbuff + i + 1;
						((idmef_t *)ctxt)->iov_len = 0;	
						((idmef_t *)ctxt)->iov_blob_len = 0;	
						gettimeofday(&tv, NULL);
						((idmef_t *)ctxt)->ts = tv.tv_usec;
						i++;
						state = IDMEF_PARSER_STATE_IDLE;
						break;

					case IDMEF_PARSER_STATE_ALERT0:
						if(strncasecmp("messageid", rbuff+i, 9) == 0){
#ifdef IDMEF_DEBUG
							fprintf(stdout, "\t\tmessageid attribute found (state=%d)!\n", state);
#endif
							//TODO:check with ctxt structure whether this attr is required to be read/modify; if yes, then
							//alloc a new (distinct)line within iov[] for this attribute and set related ctxt pointers to 
							//enable read/set attr operations.

							((idmef_t *)ctxt)->alert_tag->messageid = (unsigned char **) &( ((idmef_t *)ctxt)\
                        ->iov[((idmef_t *)ctxt)->iov_len].iov_base);
							((idmef_t *)ctxt)->alert_tag->messageid_len = (unsigned int *) &( ((idmef_t *)ctxt)\
                        ->iov[((idmef_t *)ctxt)->iov_len].iov_len);
                     //post-pone computation to the next attribute (safety):
							*( ((idmef_t *)ctxt)->alert_tag->messageid_len) = 0;	

							((idmef_t *)ctxt)->alert_tag->messageid_ts = ((idmef_t *)ctxt)->ts;
							i = i + 9;			
							state = IDMEF_PARSER_STATE_ALERT1;
						} else if(rbuff[i] == '>'){ //end of attrs list
							i++;
							state = IDMEF_PARSER_STATE_IDLE;
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d, rbuff[i]=%c) !\n", state, rbuff[i]);
							i++;
						}
						break;

					case IDMEF_PARSER_STATE_ALERT1:
						if(rbuff[i] == '='){
							i++;
							state = IDMEF_PARSER_STATE_ALERT2;
						} else { /*syntax error, give up current tag parsing*/
							/*
                     //compute prev iov_len:
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 
							prev_iovbase = rbuff + i;

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_IOV_LEN);
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = prev_iovbase; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i;  //default

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_IOV_LEN);
							*/
							state = IDMEF_PARSER_STATE_ALERT0;	//go for next attr.
						}
						break;

					case IDMEF_PARSER_STATE_ALERT2:
						if(rbuff[i] == '"'){
							i++;
							for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '"')	break;   //get value length

							if(i+j < rbytes){ 
	                     //compute prev iov_len
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase;

								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

								i = i + j;
								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i;   /*default*/

								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								prev_iovbase = rbuff + i;
								i++;
								state = IDMEF_PARSER_STATE_ALERT0;   //go for the next attr 
							}else{
								fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
								state = IDMEF_PARSER_STATE_IDLE;     //stop parsing current IDMEF message
							}
						} else { /*syntax error, give up current attr. parsing*/
							state = IDMEF_PARSER_STATE_ALERT0;      //go for next attr.
						}
						break;

					case	IDMEF_PARSER_STATE_ANALYZER0:
						if(strncasecmp("name", rbuff+i, 4) == 0){
#ifdef IDMEF_DEBUG
							fprintf(stdout, "\t\t\tname attribute found (state=%d)!\n", state);
#endif

							if( ((idmef_t *)ctxt)->alert_tag->analyzer_tag.en_attrs & IDMEF_ATTR_ANALYZER_NAME){
								((idmef_t *)ctxt)->alert_tag->analyzer_tag.name = (unsigned char **) &( ((idmef_t *)ctxt)->\
		                     iov[((idmef_t *)ctxt)->iov_len].iov_base);
								((idmef_t *)ctxt)->alert_tag->analyzer_tag.name_len = (unsigned int *) &( ((idmef_t *)ctxt)->\
                           iov[((idmef_t *)ctxt)->iov_len].iov_len);
                        //post-pone computation to the next attribute (safety)
								*( ((idmef_t *)ctxt)->alert_tag->analyzer_tag.name_len) = 0;
								((idmef_t *)ctxt)->alert_tag->analyzer_tag.name_ts = ((idmef_t *)ctxt)->ts; //mark as updated
								state = IDMEF_PARSER_STATE_ANALYZER1;
							} 
							i = i + 4;			
						} else if(rbuff[i] == '>'){ //end of attrs list
							i++;
							state = IDMEF_PARSER_STATE_IDLE;
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d) !\n", state);
							i++;
						}
						break;

					case IDMEF_PARSER_STATE_ANALYZER1:
						if(rbuff[i] == '='){
							i++;
							state = IDMEF_PARSER_STATE_ANALYZER2;
						} else { /*syntax error, give up current attribute parsing*/
							/*
                     //compute prev iov_len
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase;
							prev_iovbase = rbuff + i;

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_IOV_LEN);
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = prev_iovbase; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	//default

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_IOV_LEN);
							*/
							state = IDMEF_PARSER_STATE_ANALYZER0;	//go for next attr
						}
						break;

					case IDMEF_PARSER_STATE_ANALYZER2:
						if(rbuff[i] == '"'){
							i++;
							for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '"')	break;    //get value length

							if(i+j < rbytes){ 
                        //compute prev iov_len:
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase;

								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

								i = i + j;
								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i;  /*default*/

								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								prev_iovbase = rbuff + i;
								i++;
								state = IDMEF_PARSER_STATE_ANALYZER0;   //go for the next attr 
							}else{
								fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
								state = IDMEF_PARSER_STATE_IDLE;        //stop parsing current IDMEF tag
							}
						} else { /*syntax error, give up current attr. parsing*/
							state = IDMEF_PARSER_STATE_ANALYZER0;      //go for next attr.
						}
						break;

					case IDMEF_PARSER_STATE_CREATETIME0:
						if(strncasecmp("ntpstamp", rbuff+i, 8) == 0){
							fprintf(stdout, "\t\t\tntpstamp attribute found (state=%d)!\n", state);
/*
							if( ((idmef_t *)ctxt)->alert_tag->createtime_tag.en_attrs & IDMEF_ATTR_CREATETIME_NTPSTAMP){
								((idmef_t *)ctxt)->alert_tag->createtime_tag.body = (unsigned char **) &( ((idmef_t *)ctxt)->\
				               iov[((idmef_t *)ctxt)->iov_len].iov_base);
								((idmef_t *)ctxt)->alert_tag->createtime_tag.body_len = (unsigned int *) &( ((idmef_t *)ctxt)->\
		                     iov[((idmef_t *)ctxt)->iov_len].iov_len);
                        //post-pone computation to the next attribute (safety)
								*( ((idmef_t *)ctxt)->alert_tag->createtime_tag.body_len) = 0;
								state = IDMEF_PARSER_STATE_CREATETIME1;
							} 
*/
							i = i + 8;			
						} else if(rbuff[i] == '>'){ //end of attrs list
							i++;

							if( ((idmef_t *)ctxt)->alert_tag->createtime_tag.en_attrs & IDMEF_ATTR_CREATETIME_BODY){
								((idmef_t *)ctxt)->alert_tag->createtime_tag.body = (unsigned char **) &( ((idmef_t *)ctxt)->\
                           iov[((idmef_t *)ctxt)->iov_len].iov_base);
								((idmef_t *)ctxt)->alert_tag->createtime_tag.body_len = (unsigned int *) &( ((idmef_t *)ctxt)->
                           iov[((idmef_t *)ctxt)->iov_len].iov_len);
                        //post-pone computation to the next attribute (safety)
								*( ((idmef_t *)ctxt)->alert_tag->createtime_tag.body_len) = 0;
								((idmef_t *)ctxt)->alert_tag->createtime_tag.body_ts = ((idmef_t *)ctxt)->ts; //mark as updated

								state = IDMEF_PARSER_STATE_CREATETIME3;
							}else
								state = IDMEF_PARSER_STATE_IDLE;   //go for next tag
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d) !\n", state);
							i++;
						}
						break;

					case IDMEF_PARSER_STATE_CREATETIME1:
						if(rbuff[i] == '='){
							i++;
							state = IDMEF_PARSER_STATE_CREATETIME2;
						} else { /*syntax error, give up current attribute parsing*/
							state = IDMEF_PARSER_STATE_CREATETIME0;	//go for next attr
						}
						break;

					case IDMEF_PARSER_STATE_CREATETIME2:
						if(rbuff[i] == '"'){
							i++;
							for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '"')	break;   //get value length

							if(i+j < rbytes){ 
                        //compute prev iov_len
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase;

								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

								i = i + j;
								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i;   /*default*/

								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								prev_iovbase = rbuff + i;
								i++;
								state = IDMEF_PARSER_STATE_CREATETIME0;      //go for the next attr 
							}else{
								fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
								state = IDMEF_PARSER_STATE_IDLE;             //stop parsing current IDMEF tag
							}
						}else{ /*syntax error, give up current attr. parsing*/
								state = IDMEF_PARSER_STATE_CREATETIME0;      //go for next attr.
						}
						break;

					case IDMEF_PARSER_STATE_CREATETIME3:
						for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '<')	break;					//get value length

						if(i+j < rbytes){ 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 	//compute prev iov_len

							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

							i = i + j;
							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	/*default*/

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							prev_iovbase = rbuff + i;
							//i++;
						}else{
							fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
						}
						state = IDMEF_PARSER_STATE_IDLE;								//go for the end of the current tag
						break;

					case	IDMEF_PARSER_STATE_CLASSIFICATION0:
						if(strncasecmp("text", rbuff+i, 4) == 0){
#ifdef IDMEF_DEBUG
							fprintf(stdout, "\t\t\ttext attribute found (state=%d)!\n", state);
#endif

							//assert(((idmef_t *)ctxt)->alert_tag != NULL);
							((idmef_t *)ctxt)->alert_tag->classification_tag.text = (unsigned char **) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base);
							((idmef_t *)ctxt)->alert_tag->classification_tag.text_len = (unsigned int *) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len);
							*( ((idmef_t *)ctxt)->alert_tag->classification_tag.text_len) = 0;	//post-pone computation to the next attribute (safety)
							((idmef_t *)ctxt)->alert_tag->classification_tag.text_ts = ((idmef_t *)ctxt)->ts;	//mark as updated

							i = i + 4;			
							state = IDMEF_PARSER_STATE_CLASSIFICATION1;
						} else if(rbuff[i] == '>'){ //end of attrs list
							i++;
							state = IDMEF_PARSER_STATE_IDLE;
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d) !\n", state);
							i++;
						}
						break;

					case	IDMEF_PARSER_STATE_CLASSIFICATION1:
						if(rbuff[i] == '='){
							i++;
							state = IDMEF_PARSER_STATE_CLASSIFICATION2;
						} else { /*syntax error, give up current tag parsing*/
							state = IDMEF_PARSER_STATE_CLASSIFICATION0;		//go for next attr
						}
						break;

					case	IDMEF_PARSER_STATE_CLASSIFICATION2:
						if(rbuff[i] == '"'){
							i++;
							for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '"')	break;					//get value length

							if(i+j < rbytes){ 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 	//compute prev iov_len

								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

								i = i + j;
								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	/*default*/

								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								prev_iovbase = rbuff + i;
								i++;
								state = IDMEF_PARSER_STATE_CLASSIFICATION0; 		//go for the next attr 
							}else{
								fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
								state = IDMEF_PARSER_STATE_IDLE;						//stop parsing current IDMEF message
							}
						} else { /*syntax error, give up current attr. parsing*/
							state = IDMEF_PARSER_STATE_CLASSIFICATION0;			//go for next attr.
						}
						break;

					case IDMEF_PARSER_STATE_REFERENCE0:
					{
						void *current_parenttag = NULL;

						stack_peek(ptags, (any_t *)&current_parenttag);
						if(strncasecmp("origin", rbuff+i, 6) == 0){
#ifdef IDMEF_DEBUG
							fprintf(stdout, "\t\t\t\torigin attribute found (state=%d)!\n", state);
#endif
							
							((idmef_reference_t *)current_parenttag)->origin = (unsigned char **) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base);
							((idmef_reference_t *)current_parenttag)->origin_len = (unsigned int *) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len);
							*( ((idmef_reference_t *)current_parenttag)->origin_len) = 0;	//safety
							((idmef_reference_t *)current_parenttag)->origin_ts = ((idmef_t *)ctxt)->ts;	//mark as updated

							i = i + 6;	
							state = IDMEF_PARSER_STATE_REFERENCE1;
						} else if(rbuff[i] == '>'){ //end of attrs list
							i++;
							state = IDMEF_PARSER_STATE_IDLE;
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d) !\n", state);
							i++;
						}
						break;
					}
					case IDMEF_PARSER_STATE_REFERENCE1:
						if(rbuff[i] == '='){
							i++;
							state = IDMEF_PARSER_STATE_REFERENCE2;
						} else { /*syntax error, give up current tag parsing*/
							state = IDMEF_PARSER_STATE_REFERENCE0;		//go for next attr
						}
						break;

					case IDMEF_PARSER_STATE_REFERENCE2:
						if(rbuff[i] == '"'){
							i++;
							for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '"')	break;					//get value length

							if(i+j < rbytes){ 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 	//compute prev iov_len

								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

								i = i + j;
								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	/*default*/

								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								prev_iovbase = rbuff + i;
								i++;
								state = IDMEF_PARSER_STATE_REFERENCE0; 		//go for the next attr 
							}else{
								fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
								state = IDMEF_PARSER_STATE_IDLE;						//stop parsing current IDMEF message
							}
						} else { /*syntax error, give up current attr. parsing*/
							state = IDMEF_PARSER_STATE_REFERENCE0;				//go for next attr.
						}
						break;

					case IDMEF_PARSER_STATE_ADDRESS0:
						if(strncasecmp("category", rbuff+i, 8) == 0){
							void *current_parenttag = NULL;

							stack_peek(ptags, (any_t *)&current_parenttag);
							if( ((idmef_addr_t *)current_parenttag)->en_attrs & IDMEF_ATTR_ADDR_CATEGORY){
#ifdef IDMEF_DEBUG
								fprintf(stdout, "\t\t\t\t\tcategory attribute found(state=%d)!\n", state);
#endif							
								//((idmef_t *)ctxt)->alert_tag->target_tag[0]->node_tag->address_tag[0]->category = 

								((idmef_addr_t *)current_parenttag)->category = (unsigned char **) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base);
								((idmef_addr_t *)current_parenttag)->category_len = (unsigned int *) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len);
								*( ((idmef_addr_t *)current_parenttag)->category_len) = 0;
								((idmef_addr_t *)current_parenttag)->category_ts = ((idmef_t *)ctxt)->ts;	//mark as updated

								state = IDMEF_PARSER_STATE_ADDRESS1;	//go to get attribute's value
							}
							i = i + 8;	
						} else if(rbuff[i] == '>'){ //end of attrs list
							i++;
							state = IDMEF_PARSER_STATE_IDLE;			//go for next tag
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d) !\n", state);
							i++;
						}
						break;

					case IDMEF_PARSER_STATE_ADDRESS4:
						if(rbuff[i] == '>'){ //end of attrs list
							void *current_parenttag = NULL;

							stack_peek(ptags, (any_t *)&current_parenttag);
							if( ((idmef_addr_t *)current_parenttag)->en_attrs & IDMEF_ATTR_ADDR_ADDRESS){ 
								((idmef_addr_t *)current_parenttag)->address = (unsigned char **) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base);
								((idmef_addr_t *)current_parenttag)->address_len = (unsigned int *) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len);
								*(((idmef_addr_t *)current_parenttag)->address_len) = 0;	//post-pone its computation (safety)
								((idmef_addr_t *)current_parenttag)->address_ts = ((idmef_t *)ctxt)->ts;	//mark as updated

								state = IDMEF_PARSER_STATE_ADDRESS3;		//go to get address's value
							}else{
								state = IDMEF_PARSER_STATE_IDLE;			//go for next tag
							}
						}
						i++;
						break;

					case IDMEF_PARSER_STATE_ADDRESS1:
						if(rbuff[i] == '='){
							i++;
							state = IDMEF_PARSER_STATE_ADDRESS2;
						} else { /*syntax error, give up current tag parsing*/
							state = IDMEF_PARSER_STATE_ADDRESS0;		//go for next attr
						}
						break;

					case IDMEF_PARSER_STATE_ADDRESS2:
						if(rbuff[i] == '"'){
							i++;
							for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '"')	break;	//get value length of the current attribute

							if(i+j < rbytes){ 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 	//compute prev iov_len

								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

								i = i + j;
								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
								((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	/*default*/

								assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
								prev_iovbase = rbuff + i;
								i++;
								state = IDMEF_PARSER_STATE_ADDRESS0; 		//go for the next attr 
							}else{
								fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
								state = IDMEF_PARSER_STATE_IDLE;						//stop parsing current IDMEF message
							}
						} else { /*syntax error, give up current attr. parsing*/
							state = IDMEF_PARSER_STATE_ADDRESS0;				//go for next attr.
						}
						break;

					case IDMEF_PARSER_STATE_ADDRESS3:	//reached when within addr tag body
						for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '<')	break;	//get value length of the current tag's body

						if(i+j < rbytes){ 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 	//compute prev iov_len

							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

							i = i + j;
							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	/*default*/

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							prev_iovbase = rbuff + i;
							//i++;
						}else{
							fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
						}
						state = IDMEF_PARSER_STATE_IDLE;								//go for the end of the current tag
						break;
					
					case IDMEF_PARSER_STATE_NETMASK0:
						if(rbuff[i] == '>'){ //end of attrs list
							void *current_parenttag = NULL;

							stack_peek(ptags, (any_t *)&current_parenttag);
							i++;
							if( ((idmef_addr_t *)current_parenttag)->en_attrs & IDMEF_ATTR_ADDR_NETMASK){
								//((idmef_t *)ctxt)->alert_tag->target_tag[0]->node_tag->address_tag[0]->netmask = 

								((idmef_addr_t *)current_parenttag)->netmask = (unsigned char **) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base);
								((idmef_addr_t *)current_parenttag)->netmask_len = (unsigned int *) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len);
								*( ((idmef_addr_t *)current_parenttag)->netmask_len) = 0;	//post-pone computation to the next attribute (safety)
								((idmef_addr_t *)current_parenttag)->netmask_ts = ((idmef_t *)ctxt)->ts;	//mark as updated

								state = IDMEF_PARSER_STATE_NETMASK1;
							}else
								state = IDMEF_PARSER_STATE_IDLE;		//go for next tag
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d) !\n", state);
							i++;
						}
						break;

					case IDMEF_PARSER_STATE_NETMASK1:
						for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '<')	break;					//get value length

						if(i+j < rbytes){ 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 	//compute prev iov_len

							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

							i = i + j;
							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	/*default*/

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							prev_iovbase = rbuff + i;
							//i++;
						}else{
							fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
						}
						state = IDMEF_PARSER_STATE_IDLE;								//go for the end of the current tag
						break;

					case IDMEF_PARSER_STATE_PORT0:
						if(rbuff[i] == '>'){ //end of attrs list
							idmef_service_t *current_parenttag = NULL;

							stack_peek(ptags, (any_t *)&current_parenttag);	

							i++;
							//if( ((idmef_t *)ctxt)->alert_tag->target_tag[0]->service_tag->en_attrs & IDMEF_ATTR_SERVICE_PORT){
							if( current_parenttag->en_attrs & IDMEF_ATTR_SERVICE_PORT){
								current_parenttag->port = (unsigned char **) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base);
								current_parenttag->port_len = (unsigned int *) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len);
								*(current_parenttag->port_len) = 0;	//post-pone computation to the next attribute (safety)
								current_parenttag->port_ts = ((idmef_t *)ctxt)->ts;	//mark as updated

								state = IDMEF_PARSER_STATE_PORT1;
							}else
								state = IDMEF_PARSER_STATE_IDLE;		//go for next tag
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d) !\n", state);
							i++;
						}
						break;

					case IDMEF_PARSER_STATE_PORT1:
						for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '<')	break;					//get value length

						if(i+j < rbytes){ 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 	//compute prev iov_len

							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

							i = i + j;
							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	/*default*/

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							prev_iovbase = rbuff + i;
							//i++;
						}else{
							fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
						}
						state = IDMEF_PARSER_STATE_IDLE;								//go for the end of the current tag
						break;

					case IDMEF_PARSER_STATE_NAME0:
						if(rbuff[i] == '>'){ //end of attrs list
							idmef_reference_t *current_parenttag = NULL;

							i++;
							stack_peek(ptags, (any_t *)&current_parenttag);	
							if(current_parenttag->en_attrs & IDMEF_ATTR_REFERENCE_NAME){
								current_parenttag->name = (unsigned char **) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base);
								current_parenttag->name_len = (unsigned int *) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len);
								*(current_parenttag->name_len) = 0;	//post-pone computation to the next attribute (safety)
								current_parenttag->name_ts = ((idmef_t *)ctxt)->ts;	//mark as updated

								state = IDMEF_PARSER_STATE_NAME1;
							}else
								state = IDMEF_PARSER_STATE_IDLE;		//go for next tag
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d) !\n", state);
							i++;
						}
						break;

					case IDMEF_PARSER_STATE_NAME1:
						for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '<')	break;					//get value length

						if(i+j < rbytes){ 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 	//compute prev iov_len

							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

							i = i + j;
							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	/*default*/

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							prev_iovbase = rbuff + i;
							//i++;
						}else{
							fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
						}
						state = IDMEF_PARSER_STATE_IDLE;								//go for the end of the current tag
						break;

					case IDMEF_PARSER_STATE_URL0:
						if(rbuff[i] == '>'){ //end of attrs list
							idmef_reference_t *current_parenttag = NULL;

							i++;
							stack_peek(ptags, (any_t *)&current_parenttag);	
							if(current_parenttag->en_attrs & IDMEF_ATTR_REFERENCE_URL){
								current_parenttag->url = (unsigned char **) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base);
								current_parenttag->url_len = (unsigned int *) &( ((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len);
								*(current_parenttag->url_len) = 0;	//safety
								current_parenttag->url_ts = ((idmef_t *)ctxt)->ts;	//mark as updated

								state = IDMEF_PARSER_STATE_URL1;
							}else
								state = IDMEF_PARSER_STATE_IDLE;		//go for next tag
						} else{ /*unknown attr*/
							fprintf(stderr, "Unknown attribute(state=%d) !\n", state);
							i++;
						}
						break;

					case IDMEF_PARSER_STATE_URL1:
						for(j = 0; (i+j) < rbytes; j++)	if(rbuff[i+j] == '<')	break;					//get value length

						if(i+j < rbytes){ 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len - 1].iov_len = (rbuff+i) - prev_iovbase; 	//compute prev iov_len

							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = j; 

							i = i + j;
							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_base = rbuff + i; 
							((idmef_t *)ctxt)->iov[((idmef_t *)ctxt)->iov_len].iov_len = rbytes - i; 	/*default*/

							assert( ++(((idmef_t *)ctxt)->iov_len) < IDMEF_MAX_IOV_LEN);
							prev_iovbase = rbuff + i;
						}else{
							fprintf(stderr, "Syntax error while getting attribute value(state=%d) !\n", state);
						}
						state = IDMEF_PARSER_STATE_IDLE;								//go for the end of the current tag
						break;








					case IDMEF_PARSER_STATE_NODE:
					case IDMEF_PARSER_STATE_TARGET:
					case IDMEF_PARSER_STATE_SOURCE:
					case IDMEF_PARSER_STATE_SERVICE:
					case IDMEF_PARSER_STATE_MESSAGE:
						state = IDMEF_PARSER_STATE_IDLE;
						break;

					default:
							fprintf(stderr, "Unknown state reached(state=%d) !\n", state);
							abort();
					} //end of switch(state...

				} //end of for(...

			} //end of while(1)
		} //end of if(pid == 0

	}
	pthread_exit(NULL);		//never reached code line
}

