/* This sample program will add reference tag within message received whenever 
 * 192.168.0.1 target address occur. 
 *
 * Beware, to have always enabled the parsing of the tags/attrs which you intent 
 * to modify or remove (e.g. using idmef_<tag>_setattr(.) function). 
 */

#include <liteidmef.h>

#include <stdio.h>
#include <string.h>

idmef_t *hello = NULL;
void *alert = NULL;


void mycb(void){
	unsigned char i = 0, *attr = NULL;
	unsigned int attrlen;
	void *tag = NULL; 

	fprintf(stdout, "\nNew alert received and parsed. Callback function running ...");

	while((tag = idmef_alert_gettag(alert, IDMEF_TAG_TARGET, i++)) != NULL){
		tag = idmef_node_gettag(idmef_target_gettag(tag, IDMEF_TAG_NODE), IDMEF_TAG_ADDR, 0);
		idmef_addr_rdattr(tag, IDMEF_ATTR_ADDR_ADDRESS, &attr, &attrlen);		

		fprintf(stdout, "\n\tTARGET ADDRESS: ");
		fwrite(attr, sizeof(char), attrlen, stdout);
		if(!strncmp(attr, "192.168.0.1", strlen("192.168.0.1"))){	
			//add Reference tag here
			fprintf(stdout, "\n\t\tNew Reference tag added. ");
			fflush(stdout);
			tag = idmef_alert_gettag(alert, IDMEF_TAG_CLASSIFICATION, 0);
			idmef_classification_addtag(tag, IDMEF_TAG_REFERENCE, &tag);
			idmef_compile(hello);

		}
	}
	fflush(stdout);

	idmef_write(hello);	//optional
}


int main(void){
	idmef_ifs_t io;
	void *tag = NULL; 

	io.mode_in = IDMEF_MODE_SOCK;
	io.mode_out = IDMEF_MODE_FILE;
	io.filename_out = "console_5_out.idmef";

	idmef_new(&io, &hello, mycb);

	//enable parsing of target address tag and the related address attribute
	alert = idmef_message_gettag(hello, IDMEF_TAG_ALERT);
	tag = idmef_target_gettag(idmef_alert_gettag(alert, IDMEF_TAG_TARGET, 0), IDMEF_TAG_NODE); 
	tag = idmef_node_gettag(tag, IDMEF_TAG_ADDR, 0);
	idmef_addr_setattr(tag, IDMEF_ATTR_ADDR_ADDRESS);	


	idmef_loop();	//wait for recv events

	return (0);
}
