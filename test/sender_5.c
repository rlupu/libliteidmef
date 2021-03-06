/* This sample program ... . 
 */

#include <liteidmef.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>


int main(void){
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

	idmef_alert_addtag(alert, IDMEF_TAG_TARGET, &tag);
	idmef_target_addtag(tag, IDMEF_TAG_NODE, &tag);
	idmef_node_addtag(tag, IDMEF_TAG_ADDR, &tag);
	idmef_addr_wrattr(tag, IDMEF_ATTR_ADDR_ADDRESS, "192.168.0.1", strlen("192.168.0.1"));


	idmef_alert_addtag(alert, IDMEF_TAG_TARGET, &tag);
	idmef_target_addtag(tag, IDMEF_TAG_NODE, &tag);
	idmef_node_addtag(tag, IDMEF_TAG_ADDR, &tag);
	idmef_addr_wrattr(tag, IDMEF_ATTR_ADDR_ADDRESS, "192.168.0.2", strlen("192.168.0.2"));



	idmef_compile(hello);

	//set some attrs.
	idmef_alert_wrattr(alert, IDMEF_ATTR_ALERT_MESSAGEID, "0x1234", strlen("0x1234"));
	idmef_analyzer_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_ANALYZER, 0),\
					  			IDMEF_ATTR_ANALYZER_NAME, "Yoda", strlen("Yoda"));
	idmef_createtime_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_CREATETIME, 0),\
								IDMEF_ATTR_CREATETIME_BODY, "2015-12-06T11:14:13+0200",\
								strlen("2015-12-06T11:14:13+0200"));
	idmef_classification_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_CLASSIFICATION, 0),\
								IDMEF_ATTR_CLASSIFICATION_TEXT, "This is another Jedi greeting!",\
								strlen("This is another Jedi greeting!"));
	idmef_write(hello);
 
	fprintf(stdout, "Done.\n");

	return (0);
}
