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

#ifndef __IDMEF_PLUGIN_H__
#define __IDMEF_PLUGIN_H__

#include <stdio.h>
#include <netinet/in.h>


#define IDMEF_PORT		8800

//tags are encoded on 8MSb and attrs on 24 LSb 
#define IDMEF_TAG_HEARTBEAT					0x01000000	
#define IDMEF_TAG_ALERT							0x02000000
#define IDMEF_TAG_ANALYZER						0x03000000	
#define IDMEF_TAG_CREATETIME					0x04000000
#define IDMEF_TAG_SOURCE						0x05000000
#define IDMEF_TAG_TARGET						0x06000000	
#define IDMEF_TAG_NODE							0x07000000		
#define IDMEF_TAG_CLASSIFICATION				0x08000000	
#define IDMEF_TAG_ADDR							0x09000000		
#define IDMEF_TAG_SERVICE						0x0a000000		
#define IDMEF_TAG_REFERENCE					0x0b000000		
#define IDMEF_TAG_MESSAGE						0x0c000000		


#define IDMEF_ATTR_ALL				 						0x00ffffff

#define IDMEF_ATTR_MESSAGE_XMLNS 						0x00000001
#define IDMEF_ATTR_MESSAGE_VER 							0x00000002	

#define IDMEF_ATTR_ALERT_MESSAGEID 						0x00000001

#define IDMEF_ATTR_ANALYZER_NAME							0x00000001

#define IDMEF_ATTR_CREATETIME_BODY						0x00000001

#define IDMEF_ATTR_CLASSIFICATION_TEXT					0x00000001

#define IDMEF_ATTR_ADDR_ADDRESS							0x00000001
#define IDMEF_ATTR_ADDR_NETMASK							0x00000002
#define IDMEF_ATTR_ADDR_CATEGORY							0x00000004

#define IDMEF_ATTR_SERVICE_PORT							0x00000001

#define IDMEF_ATTR_REFERENCE_ORIGIN						0x00000001
#define IDMEF_ATTR_REFERENCE_NAME						0x00000002
#define IDMEF_ATTR_REFERENCE_URL							0x00000004

#define IDMEF_MODE_IDLE										0
#define IDMEF_MODE_FILE										1
#define IDMEF_MODE_SOCK										2	
#define IDMEF_MODE_FS										3	


#ifdef __cplusplus
extern "C" {
#endif

typedef struct idmef_t idmef_t;

typedef struct{
	unsigned char **name;									//optional attribute 
	unsigned int  *name_len;								//TODO: attrs shall be nullyfied+lng:=0, always they are reseted 
	long int name_ts;

	unsigned int en_attrs;

	idmef_t *ctxt;
} idmef_analyzer_t;

typedef struct{
	unsigned char **body;									//mandatory attribute
	unsigned int  *body_len;
	long int body_ts;

	unsigned int en_attrs;									//max 24 attrs (idem for all subsequent)
	
	idmef_t *ctxt;
} idmef_createtime_t;

typedef struct idmef_node_t idmef_node_t;

typedef struct{
	unsigned char **ident;									//optional
	unsigned int  *ident_len;								//optional
	long int ident_ts;
	unsigned char **category;								//optional; default value is "unknown"
	unsigned int  *category_len;							//optional
	long int category_ts;
	unsigned char **vlan_name;								//idem
	unsigned int  *vlan_name_len;							//idem
	long int vlan_ts;
	unsigned char **vlan_num;
	unsigned int  *vlan_num_len;
	long int vlan_num_ts;

	unsigned char **address;								//mandatory
	unsigned int  *address_len;
	long int address_ts;
	unsigned char **netmask;								//0..1
	unsigned int  *netmask_len;
	long int netmask_ts;
	
	unsigned int en_attrs;

	idmef_t *ctxt;
	long int ts;
} idmef_addr_t;

#define IDMEF_MAX_ADDRS_NO									8

struct idmef_node_t {
	unsigned char **ident;									//optional attr
	unsigned int *ident_len;								//optional
	long int ident_ts;
	unsigned char **category;								//optional
	unsigned int *category_len;							//optional
	long int category_ts;

	unsigned int en_attrs;

	//idmef_location_t *location_tag;					//0..1
	//idmef_name_t *name_tag;								//0..1
	idmef_addr_t *address_tag[IDMEF_MAX_ADDRS_NO];	//0..*
	unsigned char addresses_no;							//# of elements written in the list (not allocated)

	idmef_t *ctxt;
	long int ts;
};

typedef struct{
	unsigned char **ident;									//optional
	unsigned int  *ident_len;
	long int ident_ts;
	unsigned char **ip_version;							//idem
	unsigned int  *ip_version_len;
	long int ip_version_ts;
	unsigned char **iana_protocol_number;			
	unsigned int  *iana_protocol_number_len;
	long int iana_protocol_number_ts;
	unsigned char **iana_protocol_name;					
	unsigned int  *iana_protocol_name_len;
	long int iana_protocol_name_ts;

	unsigned char **name;									//0..1
	unsigned int  *name_len;
	long int name_ts;
	unsigned char **port;									//0..1
	unsigned int  *port_len;
	long int port_ts;
	unsigned char **portlist;								//0..1
	unsigned int  *portlist_len;
	long int portlist_ts;
	unsigned char **protocol;								//0..1
	unsigned int  *protocol_len;
	long int protocol_ts;

	unsigned int en_attrs;

	idmef_t *ctxt;
	long int ts;
} idmef_service_t;

typedef struct{
	unsigned char **ident;									//opt.
	unsigned int  *ident_len;
	long int ident_ts;
	unsigned char **spoofed;								//opt.
	unsigned int  *spoofed_len;
	long int spoofed_ts;
	unsigned char **interface;								//opt.
	unsigned int  *interface_len;
	long int interface_ts;

	unsigned int en_attrs;

	idmef_node_t *node_tag;									//0..1
	idmef_service_t *service_tag;							//0..1

	idmef_t *ctxt;
	long int ts;
} idmef_source_t;

typedef struct{
	unsigned char **ident;									//optional attribute
	unsigned int  *ident_len;								//optional attribute
	long int ident_ts;
	unsigned char **interface;
	unsigned int  *interface_len;
	long int interface_ts;
	unsigned char **decoy;									//optional of type {"unknown", "yes", "no"}
	unsigned int  *decoy_len;								//optional of type {"unknown", "yes", "no"}
	long int decoy_ts;

	unsigned int en_attrs;

	idmef_node_t *node_tag;									//optional, 0..1
	idmef_service_t *service_tag;							//0..1

	idmef_t *ctxt;
	long int ts;
} idmef_target_t;

typedef struct{
	unsigned char **origin;											//required
	unsigned int *origin_len;
	long int origin_ts;
	unsigned char **meaning;										//optional
	unsigned int *meaning_len;
	long int meaning_ts;

	unsigned char **name;											//mandatory
	unsigned int *name_len;
	long int name_ts;
	unsigned char **url;												//idem
	unsigned int *url_len;
	long int url_ts;

	unsigned int en_attrs;

	idmef_t *ctxt;
	long int ts;
} idmef_reference_t;

#define IDMEF_MAX_REF_NO									16

typedef struct{
	unsigned char **ident;											//optional attribute
	unsigned int  *ident_len;
	long int ident_ts;
	unsigned char **text;											//required attribute
	unsigned int  *text_len;
	long int text_ts;

	unsigned int en_attrs;

	idmef_reference_t *reference_tag[IDMEF_MAX_REF_NO];			//0..*
	unsigned char references_no;

	idmef_t *ctxt;
} idmef_classification_t;

typedef struct {
	idmef_analyzer_t analyzer_tag;								//mandatory class
	idmef_createtime_t createtime_tag;							//mandatory

	unsigned int en_attrs;
}	idmef_heartbeat_t;

#define IDMEF_MAX_SOURCES_NO								16
#define IDMEF_MAX_TARGETS_NO								IDMEF_MAX_SOURCES_NO	

typedef struct{
	unsigned char **messageid;										//mandatory attribute
	unsigned int  *messageid_len;	
	long int messageid_ts;

	unsigned int en_attrs;

	idmef_analyzer_t analyzer_tag;								//mandatory class
	idmef_createtime_t createtime_tag;							//mandatory
	idmef_source_t *source_tag[IDMEF_MAX_SOURCES_NO];		//optional
	unsigned char sources_no;										//# of elements written in the list (not allocated)
	idmef_target_t *target_tag[IDMEF_MAX_TARGETS_NO];		//optional; MAX 16 targets
	unsigned char targets_no;										//# of elements written in the list (not allocated)
	idmef_classification_t classification_tag;				//mandatory

	idmef_t *ctxt;
	long int ts;
} idmef_alert_t;


#define IDMEF_MAX_IOV_LEN											128	

struct idmef_t {
	unsigned char **xmlns;											//mandatory
	unsigned int  *xmlns_len;
	long int xmlns_ts;
	unsigned char **version;										//mandatory
	unsigned int  *version_len;
	long int version_ts;

	unsigned int en_attrs;

	idmef_alert_t *alert_tag;
	idmef_heartbeat_t *heartbeat_tag;

	struct iovec *iov;
	unsigned char iov_len;											//corresp. to idmef tree
	unsigned char iov_blob_len;									//attrs' val temp. storage; at the end of iov[]

	long int ts;														//timestamp; to mark current updated attrs 

	unsigned char mode_in;
	unsigned char mode_out;
	int sd_in, fd_in;
	int sd_out, fd_out;
	FILE *fs_in, *fs_out;
	struct sockaddr_in remote_out;
	void (*cbfunc)(void);
};

typedef struct {
	unsigned char mode_in;
	unsigned char *filename_in;
	unsigned char *ipaddr_in;
	unsigned char mode_out;
	unsigned char *filename_out;
	unsigned char *ipaddr_out;
} idmef_ifs_t;



extern char idmef_new(idmef_ifs_t *, idmef_t **, void (*)(void));
extern char idmef_chcon(idmef_t *, idmef_ifs_t *);				
//extern char idmef_setcb(idmef_t *, void (*)(void));				

extern char idmef_message_addtag(idmef_t *, unsigned int, void **);	
extern void *idmef_message_gettag(idmef_t *, unsigned int);
//extern char idmef_message_setattr(idmef_t *, unsigned int);	//TODO: set some hooks by default(assoc w/ mandatory attrs)
//extern void idmef_message_wrattr(idmef_t *, unsigned int, unsigned char *, unsigned int);

extern char idmef_alert_addtag(idmef_alert_t *, unsigned int, void **); 	//TODO: check compatibility in between classes(RFC4765)
extern char idmef_alert_deltag(idmef_alert_t *, unsigned int, unsigned char); 
extern void *idmef_alert_gettag(idmef_alert_t *, unsigned int, unsigned char);
extern char idmef_alert_setattr(idmef_alert_t *, unsigned int);
extern char idmef_alert_rstattr(idmef_alert_t *, unsigned int);
extern void idmef_alert_wrattr(idmef_alert_t *, unsigned int, unsigned char *, unsigned int);
extern char idmef_alert_rdattr(idmef_alert_t *, unsigned int, unsigned char **, unsigned int *);

extern idmef_analyzer_t *idmef_analyzer_gettag(idmef_alert_t *);
extern char idmef_analyzer_rstattr(idmef_analyzer_t *, unsigned int);
extern void idmef_analyzer_wrattr(idmef_analyzer_t *, unsigned int, unsigned char *, unsigned int);
extern char idmef_analyzer_rdattr(idmef_analyzer_t *, unsigned int, unsigned char **, unsigned int *);

extern char idmef_createtime_setattr(idmef_createtime_t *, unsigned int);
extern char idmef_createtime_rstattr(idmef_createtime_t *, unsigned int);
extern void idmef_createtime_wrattr(idmef_createtime_t *, unsigned int, unsigned char *, unsigned int);
extern char idmef_createtime_rdattr(idmef_createtime_t *, unsigned int, unsigned char **, unsigned int *);

extern char idmef_source_addtag(idmef_source_t *, unsigned int, void **); 
extern char idmef_source_deltag(idmef_source_t *, unsigned int, unsigned char); 	
extern void *idmef_source_gettag(idmef_source_t *, unsigned int);
extern void idmef_source_wrattr(idmef_source_t *, unsigned int, unsigned char *, unsigned int);

extern char idmef_target_addtag(idmef_target_t *, unsigned int, void **); 
extern char idmef_target_deltag(idmef_target_t *, unsigned int, unsigned char); 	
extern void *idmef_target_gettag(idmef_target_t *, unsigned int);
extern void idmef_target_wrattr(idmef_target_t *, unsigned int, unsigned char *, unsigned int);

extern char idmef_classification_addtag(idmef_classification_t *, unsigned int, void **); 
extern char idmef_classification_deltag(idmef_classification_t *, unsigned int, unsigned char); 
extern void *idmef_classification_gettag(idmef_classification_t *, unsigned int, unsigned char);
extern void idmef_classification_wrattr(idmef_classification_t *, unsigned int, unsigned char *, unsigned int);
extern char idmef_classification_rdattr(idmef_classification_t *, unsigned int, unsigned char **, unsigned int *);

extern char idmef_node_addtag(idmef_node_t *, unsigned int, void **); 
extern char idmef_node_deltag(idmef_node_t *, unsigned int, unsigned char); 	
extern void *idmef_node_gettag(idmef_node_t *, unsigned int, unsigned char);
extern void idmef_node_wrattr(idmef_node_t *, unsigned int, unsigned char *, unsigned int);

extern idmef_addr_t *idmef_addr_gettag(idmef_node_t *, unsigned char);
extern char idmef_addr_setattr(idmef_addr_t *, unsigned int);
extern char idmef_addr_rstattr(idmef_addr_t *, unsigned int);
extern void idmef_addr_wrattr(idmef_addr_t *, unsigned int, unsigned char *, unsigned int);
extern char idmef_addr_rdattr(idmef_addr_t *, unsigned int, unsigned char **, unsigned int *);

extern char idmef_service_setattr(idmef_service_t *, unsigned int);
extern char idmef_service_rstattr(idmef_service_t *, unsigned int);
extern void idmef_service_wrattr(idmef_service_t *, unsigned int, unsigned char *, unsigned int);
extern char idmef_service_rdattr(idmef_service_t *, unsigned int, unsigned char **, unsigned int *);

extern idmef_reference_t *idmef_reference_gettag(idmef_classification_t *, unsigned char);
extern char idmef_reference_setattr(idmef_reference_t *, unsigned int);
extern char idmef_reference_rstattr(idmef_reference_t *, unsigned int);
extern void idmef_reference_wrattr(idmef_reference_t *, unsigned int, unsigned char *, unsigned int);
extern char idmef_reference_rdattr(idmef_reference_t *, unsigned int, unsigned char **, unsigned int *);


extern void idmef_compile(idmef_t *);			//tree --> iov[] conversion
extern void idmef_write(idmef_t *);
extern char idmef_loop(void);						//wait for the server's thread
extern char idmef_free(idmef_t *);				//release of common resources; e.g. IO descriptors 	



#ifdef __cplusplus
}
#endif



#endif

