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

typedef enum entity_type {
	entity_is_unknown = 0,
	entity_is_identifier,
	entity_is_null,
	entity_is_string,
	entity_is_numeric,
	entity_is_struct,
	dimension_entity
} entity_type_t;

typedef struct entity {
	entity_type_t		type;
	char*			name;
	char*			data;
	int			struct_is_open;
	struct entity*	next_entity;
	struct entity*	prev_entity;
	struct entity*	child_entity;
} entity_t;

typedef struct sdtl_parser {
	int64_t	struct_nesting_level;
	lvl0_state_t	state_lvl0;
	int		first_byte_of_multibyte_token;
	int		has_empty_identifier;
	int		has_empty_value;
	int		stream_started;
	entity_type_t	current_type;
	char*		current_multibyte_token;
	buffered_string_t str_buffer;

	/* this limits the maximum struct nesting level */
	entity_t*	nesting_stack[256];
	size_t		stack_head;

	entity_t*	root_entity;
	entity_t*	curr_entity;

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

extern void
sdtl_parser_init(sdtl_parser_t* p);

extern void
sdtl_parser_free(sdtl_parser_t* p);

extern int
sdtl_parser_reset(sdtl_parser_t* p);

extern void
sdtl_parser_print(sdtl_parser_t* p, int use_whitespace);

extern int
sdtl_parser_add_data(sdtl_parser_t* p, unsigned char* data, size_t len);

extern const char*
sdtl_parser_get_data(sdtl_parser_t* p, const char* path);


struct sdtl_factory;
typedef int (*output_t)
(struct sdtl_factory* f, unsigned char* data, size_t len);

typedef struct sdtl_factory {
	int64_t	struct_nesting_level;
	output_t	put_data;

	size_t		next_byte;
	unsigned char	buffer[4096];
} sdtl_factory_t;

extern void
sdtl_factory_init(sdtl_factory_t* f, output_t put_data);

extern int
sdtl_factory_add_string(sdtl_factory_t* f, const char* key,
			const char* value);

extern int
sdtl_factory_add_num(sdtl_factory_t* f, const char* key,
			const char* value);

extern int
sdtl_factory_start_struct(sdtl_factory_t* f, const char* key);

extern int
sdtl_factory_end_struct(sdtl_factory_t* f);

extern int
sdtl_factory_flush(sdtl_factory_t* f);










extern int fs_delete_deep(const char* directory);



#endif /* _CSTD_H_ */
