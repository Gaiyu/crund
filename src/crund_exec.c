#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const int CODE_SYS_ERR = 1;
static const int CODE_NO_PID = 2;

static struct namespace_file {
	int nstype;
	const char *name;
	int fd;
} namespace_files[] = {
	{ .nstype = CLONE_NEWUSER,  .name = "ns/user", .fd = -1 },
	{ .nstype = CLONE_NEWCGROUP,.name = "ns/cgroup", .fd = -1 },
	{ .nstype = CLONE_NEWIPC,   .name = "ns/ipc",  .fd = -1 },
	{ .nstype = CLONE_NEWUTS,   .name = "ns/uts",  .fd = -1 },
	{ .nstype = CLONE_NEWNET,   .name = "ns/net",  .fd = -1 },
	{ .nstype = CLONE_NEWPID,   .name = "ns/pid",  .fd = -1 },
	{ .nstype = CLONE_NEWNS,    .name = "ns/mnt",  .fd = -1 },
	{ .nstype = 0, .name = NULL, .fd = -1 }
};

static pid_t namespace_target_pid = 0;

static void open_target_fd(int *fd, const char *type, const char *path)
{
	char pathbuf[PATH_MAX];
	if (!path && namespace_target_pid) {
		snprintf(pathbuf, sizeof(pathbuf), "/proc/%u/%s", namespace_target_pid, type);
		path = pathbuf;
	}
	if (!path)
		return;
	if (*fd >= 0)
		close(*fd);
	*fd = open(path, O_RDONLY);
	if (*fd < 0)
		return;
}

static void open_namespace_fd(int nstype, const char *path)
{
	struct namespace_file *nsfile;

	for (nsfile = namespace_files; nsfile->nstype; nsfile++) {
		if (nstype != nsfile->nstype)
			continue;
		open_target_fd(&nsfile->fd, nsfile->name, path);
		return;
	}
}

static int get_ns_ino(const char *path, ino_t *ino)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return -errno;
	*ino = st.st_ino;
	return 0;
}

void exit_err(int n)
{
	printf("%d\n", n);
	exit(EXIT_FAILURE);
}

static int is_same_namespace(pid_t a, pid_t b, const char *type)
{
	char path[PATH_MAX];
	ino_t a_ino = 0, b_ino = 0;

	snprintf(path, sizeof(path), "/proc/%u/%s", a, type);
	if (get_ns_ino(path, &a_ino) != 0)
		exit_err(CODE_SYS_ERR);

	snprintf(path, sizeof(path), "/proc/%u/%s", b, type);
	if (get_ns_ino(path, &b_ino) != 0)
		exit_err(CODE_SYS_ERR);

	return a_ino == b_ino;
}

int main(int argc, char *argv[])
{
	int namespaces = 0;
	struct namespace_file *nsfile;
	namespace_target_pid = atoi(argv[1]);
	if (!namespace_target_pid)
		exit_err(CODE_NO_PID);
	for (nsfile = namespace_files; nsfile->nstype; nsfile++) {
		if (nsfile->fd >= 0)
			continue;
		if (nsfile->nstype & CLONE_NEWUSER
				&& is_same_namespace(getpid(), namespace_target_pid, nsfile->name))
			continue;
		namespaces |= nsfile->nstype;
	}

	for (nsfile = namespace_files; nsfile->nstype; nsfile++)
		if (nsfile->nstype & namespaces)
			open_namespace_fd(nsfile->nstype, NULL);

	for (nsfile = namespace_files; nsfile->nstype; nsfile++) {
		if (nsfile->fd < 0)
			continue;
		namespaces |= nsfile->nstype;
	}

	int pass = 0;
	for (pass = 0; pass < 2; pass ++) {
		for (nsfile = namespace_files + 1 - pass; nsfile->nstype; nsfile++) {
			if (nsfile->fd <= 0)
				continue;

			if (setns(nsfile->fd, nsfile->nstype)) {
				if (pass != 0)
					exit_err(CODE_SYS_ERR);
				else
					continue;
			}

			close(nsfile->fd);
			nsfile->fd = -1;
		}
	}

	if ((0 != setgroups(0, NULL)) || (setgid(0) < 0) || (setuid(0) < 0))
		exit(0);
	return execvp(argv[2], &argv[2]);
}
