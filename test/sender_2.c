/* This sample program conveys three succesive alerts via socket to the peer
 * IDMEF agent(console).
 */

#include <liteidmef.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>


int main(void){
	unsigned int i;
	idmef_t *hello = NULL;
	idmef_alert_t *alert = NULL;
	idmef_ifs_t io;

	fprintf(stdout, "\nSending basic alerts(default tags/attrs) to 127.0.0.1 ...");

	io.mode_out = IDMEF_MODE_SOCK;
	io.ipaddr_out = "127.0.0.1";

	idmef_new(&io, &hello, NULL);		//always NULL for cb function at sender side
	idmef_message_addtag(hello, IDMEF_TAG_ALERT, (void **)&alert);
	//set some static attributes
	idmef_analyzer_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_ANALYZER, 0),\
					  			IDMEF_ATTR_ANALYZER_NAME, "Yoda", strlen("Yoda"));
	idmef_classification_wrattr(idmef_alert_gettag(alert, IDMEF_TAG_CLASSIFICATION, 0),\
								IDMEF_ATTR_CLASSIFICATION_TEXT, "Hello Jedi!",\
								strlen("Hello Jedi!"));

	idmef_compile(hello);

	for(i = 0; i < 3; i++){
		unsigned char buff[2], ASCII_alarm_time[32];
		struct timeval now;
		struct tm *ptm;

		//afterward, set the dynamic attributes
		sprintf(buff, "%d", i);
		idmef_alert_wrattr(alert, IDMEF_ATTR_ALERT_MESSAGEID, buff, strlen(buff));

		gettimeofday(&now, NULL);
		ptm = localtime(&now.tv_sec);
		strftime(ASCII_alarm_time, sizeof(ASCII_alarm_time), "%FT%T %z", ptm);
		idmef_createtime_wrattr( idmef_alert_gettag(alert, IDMEF_TAG_CREATETIME, 0),\
			IDMEF_ATTR_CREATETIME_BODY, ASCII_alarm_time, strlen(ASCII_alarm_time));

		idmef_write(hello);
		fprintf(stdout, ".");
		fflush(stdout);
		sleep(2);
	}

	fprintf(stdout, "Done.\n");

	return (0);
}
