#include "cstd.h"


__constructor(__syslog_init)
{
	int logflags = LOG_PID | LOG_NDELAY | LOG_CONS | LOG_PERROR;

	/* TODO: make program name configurable */
	openlog("cstd", logflags, LOG_DAEMON);
	/* TODO: make logmask configurable, also provide wrapper around
	 * setlogmask() */
	setlogmask(LOG_UPTO(LOG_DEBUG));
}

void veprintf(int loglevel, char* format, va_list valist)
{
	vsyslog(loglevel, format, valist);
}

void eprintf(int loglevel, char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(loglevel, format, varargs);
	va_end(varargs);
}
