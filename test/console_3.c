#include <liteidmef.h>

#include <stdio.h>
#include <string.h>

idmef_t *hello = NULL;
void *addr = NULL;


void mycb(void){
	unsigned char *attr;
	unsigned int attrlen;

	fprintf(stdout, "\nNew alert received and parsed. Callback function running ...");

	idmef_addr_rdattr(addr, IDMEF_ATTR_ADDR_ADDRESS, &attr, &attrlen);		
	fprintf(stdout, "\n\tSOURCE ADDRESS: ");
	fwrite(attr, sizeof(char), attrlen, stdout);

	idmef_write(hello);	
}


int main(void){
	idmef_ifs_t io;

	io.mode_in = IDMEF_MODE_SOCK;
	io.mode_out = IDMEF_MODE_FILE;
	io.filename_out = "console_3_out.idmef";

	idmef_new(&io, &hello, mycb);

	//enable parsing of source address tag and the related address attribute
	addr = idmef_message_gettag(hello, IDMEF_TAG_ALERT);
	addr = idmef_source_gettag(idmef_alert_gettag(addr, IDMEF_TAG_SOURCE, 0), IDMEF_TAG_NODE); 
	addr = idmef_node_gettag(addr, IDMEF_TAG_ADDR, 0);
	idmef_addr_setattr(addr, IDMEF_ATTR_ADDR_ADDRESS);	//enable parsing of source address tag


	idmef_loop();

	return (0);
}
