#ifndef _CONSTRUCTOR_H
#define _CONSTRUCTOR_H

#include <stdlib.h>

#if defined(_MSC_VER)
#pragma section(".CRT$XCU", read)
#define __constructor(f)			\
	static void __cdecl f(void);		\
	__declspec(allocate(".CRT$XCU"))	\
	void (__cdecl *f##_)(void) = f; 	\
	static void __cdecl f(void)
#else
#define __constructor(f)			\
	__attribute__((constructor))		\
	static void f(void)
#endif


#endif /* _CONSTRUCTOR_H */
