#ifndef _CSTD_H_
#define _CSTD_H_

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

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
/* pdie() is like die(), except that it prints out errno and strerror() */
extern void pdie(char* format, ...);

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

/* SDTL */
struct sdtl_parser;
typedef int (*action_t)(struct sdtl_parser* p, int byte);

typedef enum lvl0_state {
	lvl0_undefined		= 0x00,
	lvl0_assignment_start,
	lvl0_assignment_op,
	lvl0_assignment_end,
	lvl0_in_number,
	lvl0_introduce_string,
	lvl0_in_string,
	lvl0_terminate_string,
	lvl0_escape_character,
	lvl0_introduce_binary_stream,
	lvl0_introduce_struct,
	lvl0_terminate_struct,
	dimension_lvl0,
} lvl0_state_t;

typedef struct sdtl_parser {
	int64_t	struct_nesting_level;
	lvl0_state_t	state_lvl0;

	action_t	actions_after_undefined[256];
	action_t	actions_after_assignment_start[256];
	action_t	actions_after_assignment_op[256];
	action_t	actions_after_assignment_end[256];
	action_t	actions_after_in_number[256];
	action_t	actions_after_introduce_string[256];
	action_t	actions_after_in_string[256];
	action_t	actions_after_terminate_string[256];
	action_t	actions_after_escape_character[256];
	action_t	actions_after_introduce_struct[256];
	action_t	actions_after_terminate_struct[256];
} sdtl_parser_t;

extern int32_t
sdtl_init(sdtl_parser_t* p);

extern int32_t
sdtl_add_input_data(sdtl_parser_t* p, unsigned char* data, int32_t len);

#endif /* _CSTD_H_ */
