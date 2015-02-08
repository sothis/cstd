#include "cstd.h"

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

#if 0
#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */
#endif

void debug(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(LOG_DEBUG, format, varargs);
	va_end(varargs);
}

void info(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(LOG_INFO, format, varargs);
	va_end(varargs);
}


void notice(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(LOG_NOTICE, format, varargs);
	va_end(varargs);
}

void warning(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(LOG_WARNING, format, varargs);
	va_end(varargs);
}

void err(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(LOG_ERR, format, varargs);
	va_end(varargs);
}

void crit(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(LOG_CRIT, format, varargs);
	va_end(varargs);
}

void alert(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(LOG_ALERT, format, varargs);
	va_end(varargs);
}

void emerg(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(LOG_EMERG, format, varargs);
	va_end(varargs);
}
