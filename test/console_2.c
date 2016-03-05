#include <liteidmef.h>
#include <stdio.h>

idmef_t *hello = NULL;


void mycb(void){
	fprintf(stdout, "\nNew alert received and parsed. Callback function running ...");

	idmef_write(hello);

	fprintf(stdout, "Done.\n");
}


int main(void){
	idmef_ifs_t io;

	io.mode_in = IDMEF_MODE_SOCK;
	io.mode_out = IDMEF_MODE_FILE;
	io.filename_out = "console_2_out.idmef";

	idmef_new(&io, &hello, mycb);

	idmef_loop();

	return (0);
}
