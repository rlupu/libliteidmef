/* This sample program will remove node tag from the message received whenever 
 * 192.168.0.1 source address is notified. In order to enable access to any 
 * tag/attribute, they must be enabled for parsing before callback function is 
 * run. Note, each idmef_<tag>_gettag(.) function play two roles: as a tag's  
 * enabler and as a tag's reference access tool.
 *
 * Beware, to have always enabled the parsing of the tags/attrs which you intent 
 * to modify or remove (e.g. using idmef_<tag>_setattr(.) function). 
 */

#include <liteidmef.h>

#include <stdio.h>
#include <string.h>

idmef_t *hello = NULL;
void *addr = NULL;


void mycb(void){
	unsigned char *attr = NULL;
	unsigned int attrlen;
	void *tag = NULL; //desters

	fprintf(stdout, "\nNew alert received and parsed. Callback function running ...");

	//TBR--Begin
	idmef_alert_rdattr(idmef_message_gettag(hello, IDMEF_TAG_ALERT), IDMEF_ATTR_ALERT_MESSAGEID, &attr, &attrlen);
	fprintf(stdout, "\n\tMESSAGEID: ");
	fwrite(attr, sizeof(char), attrlen, stdout);

	tag = idmef_message_gettag(hello, IDMEF_TAG_ALERT);
	tag = idmef_alert_gettag(tag, IDMEF_TAG_ANALYZER, 0);
	idmef_analyzer_rdattr(tag, IDMEF_ATTR_ANALYZER_NAME, &attr, &attrlen);		
	fprintf(stdout, "\n\tANALYZER:");
	fwrite(attr, sizeof(char), attrlen, stdout);

	tag = idmef_message_gettag(hello, IDMEF_TAG_ALERT);
	tag = idmef_alert_gettag(tag, IDMEF_TAG_CREATETIME, 0);
	idmef_createtime_rdattr(tag, IDMEF_ATTR_CREATETIME_BODY, &attr, &attrlen);		
	fprintf(stdout, "\n\tCTIME: ");
	fwrite(attr, sizeof(char), attrlen, stdout);

	tag = idmef_message_gettag(hello, IDMEF_TAG_ALERT);
	tag = idmef_alert_gettag(tag, IDMEF_TAG_CLASSIFICATION, 0);
	idmef_classification_rdattr(tag, IDMEF_ATTR_CLASSIFICATION_TEXT, &attr, &attrlen);		
	fprintf(stdout, "\n\tCLS TEXT: ");
	fwrite(attr, sizeof(char), attrlen, stdout);

	tag = idmef_classification_gettag(tag, IDMEF_TAG_REFERENCE, 0);
	idmef_reference_rdattr(tag, IDMEF_ATTR_REFERENCE_ORIGIN, &attr, &attrlen);		
	fprintf(stdout, "\n\tREF ORIGIN: ");
	fwrite(attr, sizeof(char), attrlen, stdout);

	tag = idmef_message_gettag(hello, IDMEF_TAG_ALERT);
	tag = idmef_alert_gettag(tag, IDMEF_TAG_SOURCE, 0);
	tag = idmef_source_gettag(tag, IDMEF_TAG_NODE);
	tag = idmef_node_gettag(tag, IDMEF_TAG_SERVICE, 0);
	idmef_classification_rdattr(tag, IDMEF_ATTR_SERVICE_PORT, &attr, &attrlen);		
	fprintf(stdout, "\n\tSPORT: ");
	fwrite(attr, sizeof(char), attrlen, stdout);
	//TBR--End



	idmef_addr_rdattr(addr, IDMEF_ATTR_ADDR_ADDRESS, &attr, &attrlen);		
	fprintf(stdout, "\n\tSOURCE ADDRESS: ");
	fwrite(attr, sizeof(char), attrlen, stdout);

	fflush(stdout);

	if(!strcmp(attr, "192.168.0.1")){	//remove source IP address
		idmef_source_deltag(idmef_alert_gettag(idmef_message_gettag(hello, IDMEF_TAG_ALERT),\
									IDMEF_TAG_SOURCE, 0), IDMEF_TAG_NODE, 0);
		idmef_compile(hello);

		//re-enable the tag/attr which shall be readable later on
		addr = idmef_message_gettag(hello, IDMEF_TAG_ALERT);
		addr = idmef_source_gettag(idmef_alert_gettag(addr, IDMEF_TAG_SOURCE, 0), IDMEF_TAG_NODE); 
		addr = idmef_node_gettag(addr, IDMEF_TAG_ADDR, 0);
		idmef_addr_setattr(addr, IDMEF_ATTR_ADDR_ADDRESS);		//redundant, because address attr is mandatory
	}

	idmef_write(hello);	//optional
}


int main(void){
	idmef_ifs_t io;

	io.mode_in = IDMEF_MODE_SOCK;
	io.mode_out = IDMEF_MODE_FILE;
	io.filename_out = "console_4_out.idmef";

	idmef_new(&io, &hello, mycb);

	//enable parsing of source address tag and the related address attribute
	addr = idmef_message_gettag(hello, IDMEF_TAG_ALERT);
	addr = idmef_source_gettag(idmef_alert_gettag(addr, IDMEF_TAG_SOURCE, 0), IDMEF_TAG_NODE); 
	addr = idmef_node_gettag(addr, IDMEF_TAG_ADDR, 0);
	idmef_addr_setattr(addr, IDMEF_ATTR_ADDR_ADDRESS);	


	idmef_loop();


	return (0);
}
