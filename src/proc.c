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
		die("open() on '%s': %s (errno %d)\n", f, xstrerror(), errno);
	wfd = open(f, O_WRONLY, 0);
	if (wfd < 0)
		die("open() on '%s': %s (errno %d)\n", f, xstrerror(), errno);

	args->stdin = rfd;
	args->stdout = wfd;
	args->stderr = dup(wfd);
	if (args->stderr < 0)
		die("dup() on '%d': %s (errno %d)\n", wfd, xstrerror(), errno);
}

static void proc_replace_process_image(proc_t* args, int redirect)
{
	if (!redirect) {
		proc_null_redirect(args);
	}
	if (args->stdin != STDIN_FILENO) {
		if (dup2(args->stdin, STDIN_FILENO) < 0)
			die("dup2() on args->stdin: %s (errno %d)\n",
				xstrerror(), errno);
	}
	if (args->stdout != STDOUT_FILENO) {
		if (dup2(args->stdout, STDOUT_FILENO) < 0)
			die("dup2() on args->stdout: %s (errno %d)\n",
				xstrerror(), errno);
	}
	if (args->stderr != STDERR_FILENO) {
		if (dup2(args->stderr, STDERR_FILENO) < 0)
			die("dup2() on args->stderr: %s (errno %d)\n",
				xstrerror(), errno);
	}

	/* umask and working directory are inherited by the
	 * process image which replaces our current image after
	 * execvpe() */
	umask(args->umask);
	if (chdir(args->wd)) {
		die("chdir() to '%s': %s (errno %d)\n", args->wd,
			xstrerror(), errno);
	}
	if (execvpe(args->argv[0], args->argv, args->envp))
		die("execvpe() on '%s': %s (errno %d)\n", args->argv[0],
			xstrerror(), errno);
}

int proc_fork_and_wait(proc_t* args, int redirect)
{
	pid_t pid;
	int stat;
	int e;

	pid = fork();
	if (pid < 0)
		die("fork(): %s (errno %d)\n", xstrerror(), errno);

	if (pid) {
		/* parent process, pid contains the child's pid */
		do {
			if (waitpid(pid, &stat, 0) < 0)
				die("waitpid(): %s (errno %d)\n", xstrerror(),
					errno);
		} while (!WIFEXITED(stat));
		e = WEXITSTATUS(stat);
		return e;
	}

	/* child process */
	proc_replace_process_image(args, redirect);
	/* never happens */
	return 0;
}
