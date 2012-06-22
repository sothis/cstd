#include "cstd.h"

#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

static void proc_replace_process_image(proc_t* args)
{
	int nullfd;

	/* close standard i/o channels and redirect them to/from
	 * /dev/null, we don't support data transfer via these
	 * channels here */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	nullfd = open("/dev/null", O_RDWR, 0);
	while (nullfd != -1 && nullfd < STDERR_FILENO)
		nullfd = dup(nullfd);
	if (nullfd < 0)
		die("open(): %s (errno %d)\n",
			strerror(errno), errno);
	if (nullfd > STDERR_FILENO)
		close(nullfd);

	/* umask and working directory are inherited by the
	 * process image which replaces our current image after
	 * execve() */
	umask(args->umask);
	if (chdir(args->wd))
		die("chdir(): %s (errno %d)\n",
			strerror(errno), errno);
	if (execve(args->argv[0], args->argv, args->envp))
		die("execvp(): %s (errno %d)\n",
			strerror(errno), errno);
}

int proc_fork_and_wait(proc_t* args)
{
	pid_t pid;
	int stat;
	int e;

	pid = fork();
	if (pid < 0)
		die("fork(): %s (errno %d)\n", strerror(errno), errno);

	if (pid) {
		/* parent process, pid contains the child's pid */
		do {
			if (waitpid(pid, &stat, 0) < 0)
				die("waitpid(): %s (errno %d)\n",
					strerror(errno), errno);
		} while (!WIFEXITED(stat));
		e = WEXITSTATUS(stat);
		return e;
	}

	/* child process */
	proc_replace_process_image(args);
	/* never happens */
	return 0;
}
