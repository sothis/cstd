#ifndef _CSTD_H_
#define _CSTD_H_

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

/* mode_t */
#include <sys/types.h>

const char* application_name;
extern int cstd_main(int argc, char* argv[], char* envp[]);

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

/* print onto syslog/stderr */
extern void eprintf(int loglevel, char* format, ...);
extern void veprintf(int loglevel, char* format, va_list valist);
extern void debug(char* format, ...);
extern void info(char* format, ...);
extern void warning(char* format, ...);
extern void notice(char* format, ...);
extern void err(char* format, ...);
extern void crit(char* format, ...);
extern void alert(char* format, ...);
extern void emerg(char* format, ...);

/* die() prints the format string onto log and terminates the process
 * immediately without calling any atexit() handlers */
extern void die(char* format, ...);
/* pdie() is like die(), except that it prints out additionally errno and
 * strerror() */
extern void pdie(char* format, ...);



typedef struct buffered_string {
	size_t	threshold;
	char*	mem;

	size_t	length;
	size_t	allocated;
} buffered_string_t;

extern int str_buffered_init(buffered_string_t* str, size_t alloc_threshold);
extern int str_buffered_append_byte(buffered_string_t* str, char byte);
extern char* str_buffered_finalize(buffered_string_t* str);

extern char* str_append(char* string1, const char* string2);
extern char* str_prepend(char* string1, const char* string2);

char* path_resolve(char* path, const char* subtree);
char* path_resolve_const(const char* path);

typedef struct proc_t {
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

typedef int (*slave_proc_t)(pid_t pid, pid_t pgid, void* data);

int proc_fork_slaves(pid_t cpid[], int nslaves, slave_proc_t proc, void* data);



extern int fs_delete_deep(const char* directory);



extern int file_create_rw_with_hidden_tmp
(const char* name, const char* parent_dir, mode_t mode);
void file_register_fd(int fd, char* path, char* name);

extern int file_set_userdata(int fd, void* userdata);
extern void* file_get_userdata(int fd);

extern int file_sync_and_close(int fd);
extern void file_sync_and_close_all(void);



#endif /* _CSTD_H_ */
