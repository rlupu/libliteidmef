/* ...write a minimal IDMEF alert with default values directly to the output 
 * file. Afterward, set values of the default attributes and then write 
 * it again to the same file.
 */

#include <liteidmef.h>

#include <string.h>


int main(void){
	idmef_t *hello = NULL;
	idmef_alert_t *alert = NULL;
	idmef_ifs_t io;
	
	fprintf(stdout, "\nSending basic alerts(default tags/attrs) to file ...");

	io.filename_out = "sender_1_out.idmef"; 
	io.mode_out = IDMEF_MODE_FILE;

	idmef_new(&io, &hello, NULL);		//always NULL for cb function at sender side
	idmef_message_addtag(hello, IDMEF_TAG_ALERT, NULL);

	idmef_compile(hello);
	idmef_write(hello);


	//Now, let's have assigned values to the default attributes
	alert = idmef_message_gettag(hello, IDMEF_TAG_ALERT);
	idmef_alert_wrattr(alert, IDMEF_ATTR_ALERT_MESSAGEID, "0x1234", strlen("0x1234"));
	idmef_analyzer_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_ANALYZER, 0),\
					  			IDMEF_ATTR_ANALYZER_NAME, "Yoda", strlen("Yoda"));
	idmef_createtime_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_CREATETIME, 0),\
								IDMEF_ATTR_CREATETIME_BODY, "2015-12-18T16:16:33+0200",\
								strlen("2015-12-18T16:16:33+0200"));
										
	idmef_classification_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_CLASSIFICATION, 0),\
								IDMEF_ATTR_CLASSIFICATION_TEXT, "Hello World!",\
								strlen("Hello World!"));




	idmef_write(hello);

	fprintf(stdout, "Done.\n");

	return (0);
}
