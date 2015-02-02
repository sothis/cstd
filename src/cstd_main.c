#include "cstd.h"

int main(int argc, char* argv[], char* envp[])
{
	int logflags = LOG_PID | LOG_NDELAY | LOG_CONS | LOG_PERROR;

	openlog(application_name, logflags, LOG_DAEMON);
	/* TODO: make logmask configurable, also provide wrapper around
	 * setlogmask() */
	setlogmask(LOG_UPTO(LOG_DEBUG));

	application_name = argv[0];
	return cstd_main(argc, argv, envp);
}
