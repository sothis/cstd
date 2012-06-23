#include "cstd.h"

#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

static void proc_null_redirect(proc_t* args)
{
	int rfd, wfd;
	const char* f = "/dev/null";

	rfd = open(f, O_RDONLY, 0);
	if (rfd < 0)
		pdie("open() on '%s'", f);
	wfd = open(f, O_WRONLY, 0);
	if (wfd < 0)
		pdie("open() on '%s'", f);

	args->stdin = rfd;
	args->stdout = wfd;
	args->stderr = dup(wfd);
	if (args->stderr < 0)
		pdie("dup() on '%d'", wfd);
}

static void proc_replace_process_image(proc_t* args, int redirect)
{
	if (!redirect) {
		proc_null_redirect(args);
	}
	if (args->stdin != STDIN_FILENO) {
		if (dup2(args->stdin, STDIN_FILENO) < 0)
			pdie("dup2() on %d/STDIN_FILENO", args->stdin);
	}
	if (args->stdout != STDOUT_FILENO) {
		if (dup2(args->stdout, STDOUT_FILENO) < 0)
			pdie("dup2() on %d/STDOUT_FILENO", args->stdout);
	}
	if (args->stderr != STDERR_FILENO) {
		if (dup2(args->stderr, STDERR_FILENO) < 0)
			pdie("dup2() on %d/STDERR_FILENO", args->stderr);
	}

	/* umask and working directory are inherited by the
	 * process image which replaces our current image after
	 * execvpe() */
	if (chdir(args->wd)) {
		pdie("chdir() to '%s'", args->wd);
	}
	umask(args->umask);
	if (execvpe(args->argv[0], args->argv, args->envp)) {
		pdie("execvpe() on '%s'", args->argv[0]);
	}
}

int proc_fork_and_wait(proc_t* args, int redirect)
{
	pid_t pid;
	int stat;
	int e;

	pid = fork();
	if (pid < 0)
		pdie("fork()");

	if (pid) {
		/* parent process, pid contains the child's pid */
		do {
			if (waitpid(pid, &stat, 0) < 0)
				pdie("waitpid()");
		} while (!WIFEXITED(stat));
		e = WEXITSTATUS(stat);
		return e;
	}

	/* child process */
	proc_replace_process_image(args, redirect);
	/* never happens */
	return 0;
}