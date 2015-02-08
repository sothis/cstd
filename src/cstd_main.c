#include "cstd.h"

__constructor(_syslog_init)
{
	openlog(0, LOG_PID | LOG_NDELAY | LOG_CONS | LOG_PERROR, LOG_USER);
	//setlogmask(LOG_UPTO(LOG_DEBUG)); /* LOG_UPTO(LOG_DEBUG) is default */
}

int main(int argc, char* argv[], char* envp[])
{
	return cstd_main(argc, argv, envp);
}
