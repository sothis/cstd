#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "cstd.h"
#include "socket/sio.h"

typedef struct slave_args_t {
	int	listen_fd;
} slave_args_t;

int slaveproc(pid_t pid, pid_t pgid, void* data)
{
	slave_args_t* slave_args = (slave_args_t*) data;

	if (!slave_args)
		return -1;

	info("slave [%d]: listen_fd %d", pid, slave_args->listen_fd);
	for (;;) {
		usleep(1000000);
		//printf("[slave %u]: tic\n", pid);
	}
	return 0;
}

int main(int argc, char* argv[], char* envp[])
{
	pid_t slave_pids[4];
	int pipes[4];
	int nslaves = 4;
	int r;
	int listen_fd;

	tcp_sock_opt_t sopt = {
		.interface	= 0,	/* bind any */
		.port		= 1337,
		.non_blocking	= 1,
		.reuse_address	= 1,
		.keep_alive	= 1,
	};

	listen_fd = sio_new_tcp_listening_socket(&sopt);
	if (listen_fd < 0) {
		pdie("sio_new_tcp_listening_socket()");
	}

	slave_args_t slave_args = {
		.listen_fd = listen_fd,
	};

//	proc_fork_slaves(slave_pids, pipes, &nslaves, &slaveproc, &slave_args);

#if 0
	for (;;) {
		usleep(1000000);
	}
#else
	getchar();
#endif

//	r = proc_terminate_slaves(slave_pids, nslaves);


	printf("finished: %d.\n", r);

	return 0;
}
