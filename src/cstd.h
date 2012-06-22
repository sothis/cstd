#ifndef _CSTD_H_
#define _CSTD_H_

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <syslog.h>

/* mode_t */
#include <sys/types.h>

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

extern const char* cstd_version_string(void);
extern uint32_t cstd_version(const char** extra, const char** git);
extern uint32_t cstd_version_major(void);
extern uint32_t cstd_version_minor(void);
extern uint32_t cstd_version_patchlevel(void);
extern void cstd_eprint_version(void);

extern void* xmalloc(size_t size);
extern void* xcalloc(size_t member, size_t size);
extern void* xrealloc(void* ptr, size_t size);
extern char* xstrdup(const char* string);
extern char* xrealpath(char* path, int free_path_afterwards);
extern const char* xstrerror(void);

extern void eprintf(int loglevel, char* format, ...);
extern void veprintf(int loglevel, char* format, va_list valist);
/* die() prints the format string onto log and terminates the process
 * immediately without calling any atexit() handlers */
extern void die(char* format, ...);

extern char* str_append(char* string1, const char* string2);
extern char* str_prepend(char* string1, const char* string2);

char* path_resolve(char* path, const char* subtree);
char* path_resolve_const(const char* path);

typedef struct proc {
	/* if redirect in proc_fork_and_wait() is set, use these
	 * filedescriptors as source/destination of standard I/O
	 * channels, set them to STDIN_FILENO, STDOUT_FILENO and
	 * STDERR_FILENO, if the child shall use the same files for
	 * standard I/O as the parent (i.e. the caller of
	 * proc_fork_and_wait() */
	int		stdin;
	int		stdout;
	int		stderr;
	/* 0-terminated array, the first member must contain the path
	 * to the program image (can be relative to the current working
	 * directory, can contain symlinks and doesn't need to be resolvable
	 * if the program image can be found via PATH environment),
	 * the program image can be a shebang-introduced scriptfile */
	char**		argv;
	/* 0-terminated array, which contains the environment for the child
	 * process, can be NULL in which case the child will operate with
	 * an empty environment */
	char**		envp;
	/* the umask for the child process */
	mode_t		umask;
	/* the working directory for the child process */
	const char*	wd;
} proc_t;

extern int proc_fork_and_wait(proc_t* args, int redirect);


#endif /* _CSTD_H_ */
