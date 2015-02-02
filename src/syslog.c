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
