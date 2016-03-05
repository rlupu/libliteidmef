/* This sample program conveys two succesive alerts via socket to the peer
 * IDMEF agent(i.e. idmef_console_3).Each one shall notify a different source
 * IP address.
 */

#include <liteidmef.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
//#include <stdlib.h>


int main(void){
	unsigned int i;
	idmef_t *hello = NULL;
	idmef_alert_t *alert = NULL;
	void *tag = NULL;
	idmef_ifs_t io;

	fprintf(stdout, "\nSending alerts with IP source notification to 127.0.0.1 ...");

	io.mode_out = IDMEF_MODE_SOCK;
	io.ipaddr_out = "127.0.0.1";

	//build up alert structure
	idmef_new(&io, &hello, NULL);		//always NULL for cb function at sender side
	idmef_message_addtag(hello, IDMEF_TAG_ALERT, (void **)&alert);
	idmef_alert_addtag(alert, IDMEF_TAG_SOURCE, &tag);
	idmef_source_addtag(tag, IDMEF_TAG_NODE, &tag);
	idmef_node_addtag(tag, IDMEF_TAG_ADDR, &tag);

	idmef_compile(hello);

	//set some attrs.
	idmef_alert_wrattr(alert, IDMEF_ATTR_ALERT_MESSAGEID, "0x1234", strlen("0x1234"));
	idmef_addr_wrattr(tag, IDMEF_ATTR_ADDR_ADDRESS, "192.168.0.1", strlen("192.168.0.1"));
	idmef_analyzer_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_ANALYZER, 0),\
					  			IDMEF_ATTR_ANALYZER_NAME, "Yoda", strlen("Yoda"));
	idmef_createtime_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_CREATETIME, 0),\
								IDMEF_ATTR_CREATETIME_BODY, "2015-12-06T11:14:13+0200",\
								strlen("2015-12-06T11:14:13+0200"));
	idmef_classification_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_CLASSIFICATION, 0),\
								IDMEF_ATTR_CLASSIFICATION_TEXT, "This is a Jedi greeting!",\
								strlen("This is a Jedi greeting!"));
	idmef_write(hello);


	//then, fulfill the attributes's values for the second alert (same structure); only
	//those that have different values.
	idmef_alert_wrattr(alert, IDMEF_ATTR_ALERT_MESSAGEID, "0x1235", strlen("0x1235"));
	idmef_addr_wrattr(tag, IDMEF_ATTR_ADDR_ADDRESS, "172.16.0.1", strlen("172.16.0.1"));
	idmef_createtime_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_CREATETIME, 0),\
								IDMEF_ATTR_CREATETIME_BODY, "2015-12-06T11:24:03+0200",\
								strlen("2015-12-06T11:24:03+0200"));
	idmef_write(hello);
 

	fprintf(stdout, "Done.\n");

	return (0);
}
