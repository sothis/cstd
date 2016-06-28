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

static inline int get_online_cpu_count(void)
{
	int ncpus;

	if ((ncpus = sysconf(_SC_NPROCESSORS_ONLN)) == -1)
		ncpus = 1;

	return ncpus;
}

slave_t* slaves = 0;

static inline slave_t* add_new_slave(slave_proc_t proc, void* data)
{
	slave_t* new_slave;

	new_slave = calloc(1, sizeof(struct slave_t));
	if (!new_slave)
		return 0;

	new_slave->param.proc = proc;
	new_slave->param.data = data;

	new_slave->next = slaves;
	slaves = new_slave;

	return new_slave;
}

int proc_fork_slaves(pid_t spid[], int* nslaves, slave_proc_t proc, void* data)
{
	pid_t fpid;
	pid_t child_pid;
	pid_t child_pgid;
	int r = 0, c = 0;
	int cmdpipe[2];

	if (!spid || !proc || !nslaves)
		return -1;

	if (!*nslaves)
		*nslaves = get_online_cpu_count();

	for (int i = 0; i < *nslaves; ++i) {
		/* read side for slave process : cmdpipe[0] */
		/* write side for master process : cmdpipe[1] */
		pipe(cmdpipe);
		fpid = fork();
		if (fpid < 0) {
			err("fork(): %s", strerror(errno));
			r++;
			spid[i] = -1;
		}
		if (fpid == 0) {
			/* child process */
			child_pgid = setsid();
			if (child_pgid < 0) {
				/* end child process */
				err("setsid(): %s", strerror(errno));
				return -1;
			}
			child_pid = getpid();
			umask(0);
			return proc(child_pid, child_pgid, data);
		}
		if (fpid > 0) {
			/* parent process */
			c++;
			spid[i] = fpid;
		}
	}

	if (r)
		r = -1;

	info("proc_fork_slaves(): forked %d slave processes", c);

	return r;
}

int proc_terminate_slaves(pid_t spid[], int nslaves)
{
	int r = 0;

	for (int i = 0; i < nslaves; ++i) {
		if (spid[i] < 0)
			continue;
		if (kill(spid[i], SIGTERM)) {
			err("kill(): %s", strerror(errno));
			r = -1;
		}
	}

	if (waitpid(-1, 0, 0) < 0) {
		err("waitpid(): %s", strerror(errno));
		r = -1;
	}

	return r;
}
