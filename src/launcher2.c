/*                                                                                                                                 
 *  Copyright (C) sunniwell.net All rights reserved.
 *  --------------------------------------------------------------
 *  Date        :   2021-04-29
 *  Author      :   Gaiyu
 *  --------------------------------------------------------------
 */
#define _GNU_SOURCE                                                                                                                
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <limits.h> 
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h> 
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>

typedef struct clone_arg {
	int (*fn)(void *);                                                                                                             
	void * arg;
} clone_arg;

typedef struct start_arg {
	int argc;
	char ** argv;
} start_arg;

typedef struct auto_dev {
	const char *name;
	mode_t mode;
	int major;
	int minor;
} auto_dev;

static const struct auto_dev auto_devs[] = {
	{ "null", S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 3 },
	{ "zero", S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 5 },
	{ "full", S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 7 },
	{ "urandom", S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 9 },
	{ "random", S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 1, 8 },
	{ "tty", S_IFCHR | S_IRWXU | S_IRWXG | S_IRWXO, 5, 0 },
	{ "console", S_IFCHR | S_IRUSR | S_IWUSR, 5, 1 },
};

static int do_clone(void *arg)
{
	struct clone_arg *clone_arg = arg;
	return clone_arg->fn(clone_arg->arg);
}

static pid_t __clone(int (*fn)(void *), void *arg)
{
	struct clone_arg clone_arg = {
		.fn = fn,
		.arg = arg,
	};

	size_t stack_size = sysconf(_SC_PAGESIZE);
	void * stack = alloca(stack_size);
	pid_t ret;

	const int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWNET;
	ret = clone(do_clone, stack + stack_size, flags | SIGCHLD, &clone_arg);
	if (ret < 0)
		printf("failed to clone (%#x): %s\n", flags, strerror(errno));
	return ret;
}

void set_map(char* file, int inside_id, int outside_id, int len)
{
	FILE* mapfd = fopen(file, "w");
	if (NULL == mapfd) {
		perror("open file error");
		return;
	}
	fprintf(mapfd, "%d %d %d", inside_id, outside_id, len);
	fclose(mapfd);
}
void set_uid_map(pid_t pid, int inside_id, int outside_id, int len)
{
	char file[256];
	sprintf(file, "/proc/%d/uid_map", pid);
	set_map(file, inside_id, outside_id, len);
}

void set_gid_map(pid_t pid, int inside_id, int outside_id, int len)
{
	char file[256];
	sprintf(file, "/proc/%d/gid_map", pid);
	set_map(file, inside_id, outside_id, len);
}

static int isdigitstr(char *str)
{
	return (strspn(str, "0123456789") == strlen(str));
}

static int pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}
/*
   static int sethostname(const char * name, size_t len)
   {
   return syscall(SYS_sethostname, name, len);
   }
 */
void help(const char* name)
{
	printf("Usage: %s [ OPTIONS ] -C [ container arg1 ... argN ]\n", name);
	printf("\teg: %s -r /xxx/xxx/ -e AAA=123 -C /bin/sh\n\n", name);
	printf("-C:\tStop parsing configuration options, and follow up content as container startup parameters.\n\n");
	printf("OPTIONS:\n");
	printf("\t-r\tSet rootfs path will be used.\n");
	printf("\t\teg: -r /xxx/xxx/rootfs/\n");
	printf("\t-e\tSet environment variables.\n");
	printf("\t\teg: -e AAA=123\n");
	printf("\t-d\tAdd a host device to the container.\n");
	printf("\t\teg: -d ttyUSB0\n");
	printf("\t-p\tSave container pid to a file.\n");
	printf("\t\teg: -p /xx/xx/pid\n");
	printf("\t-v\tBind mount a volume\n");
	printf("\t\teg: -v /xx/out/container:/xx/in/container\n");
}

int start_container(void * arg)
{
	struct start_arg *start_arg = arg;
	int argc = start_arg->argc;
	char** argv = start_arg->argv;
	static const char * DEV_SPLIT=",";
	static const char * VOL_SPLIT=":";
	static const struct option longopts[] = {
		{ "rootfs", required_argument, NULL, 'r' },
		{ "pid", no_argument, NULL, 'p' },
		{ "volume", required_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ "env", required_argument, NULL, 'e' },
		{ "device", required_argument, NULL, 'd' },
		{ "command", no_argument, NULL, 'C' },
		{ NULL, 0, NULL, 0 }
	};

	sethostname("CRUND", strlen("CRUND"));

	const char * put_old = "/old_rootfs";
	char * new_root = NULL;
	int c = 0;
	optind = 0;
	while ((c = getopt_long(argc, argv, "r:p:v:he:d:C", longopts, NULL)) != -1) {
		switch (c) {
			case 'r':
				new_root = optarg;
				break;
		}
	}

	printf("<1>\n");
	if ((1 == mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
			|| (-1 == mount(new_root, new_root, NULL, MS_BIND, NULL)))
		exit(EXIT_FAILURE);

	printf("<2>\n");
	umount("/proc");
	umount("/dev");
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", new_root, put_old);
	char proc_path[PATH_MAX];
	char dev_path[PATH_MAX];
	snprintf(proc_path, sizeof(proc_path), "%s/proc", new_root);
	snprintf(dev_path, sizeof(proc_path), "%s/dev", new_root);
	mkdir(proc_path, 0666);
	mkdir(dev_path, 0666);
	printf("<3>\n");
	mount("proc", proc_path, "proc", 0, NULL);
	mount("tmpfs", dev_path, "tmpfs", 0, NULL);
	printf("<4>\n");
/*
	char auto_dev_path[PATH_MAX];
	char host_dev_path[PATH_MAX];
	for (int i = 0; i < sizeof(auto_devs) / sizeof(auto_devs[0]); i++) {
		const struct auto_dev *d = &auto_devs[i];
		int ret = snprintf(auto_dev_path, PATH_MAX, "%s/dev/%s", new_root, d->name);
		if (ret < 0 || ret >= PATH_MAX)
			continue;
		dev_t dev = makedev(d->major, d->minor);
		printf("d->major = %d, d->minor = %d, errno = %s\n", d->major, d->minor, strerror(errno));
		ret = mknod(auto_dev_path, d->mode, dev);
		printf("auto_dev_path = %s, d->name = %s, ret = %d, errno = %s\n", auto_dev_path,d->name, ret, strerror(errno));
		if (ret && errno != EEXIST) {
			FILE * dev_file = NULL;
			ret = snprintf(host_dev_path, PATH_MAX, "/dev/%s", d->name);
			if (ret < 0 || ret >= PATH_MAX)
				continue;
			dev_file = fopen(auto_dev_path, "wb");
			if (!dev_file)
				continue;
			fclose(dev_file);
			mount(host_dev_path, auto_dev_path, NULL, MS_BIND, NULL);
		}
	}
*/
	printf("<5>\n");
	optind = 0;
	while ((c = getopt_long(argc, argv, "r:p:v:he:d:C", longopts, NULL)) != -1) {
		switch (c) {
			case 'v':
				{
					char vol_path[PATH_MAX];
					char * p = NULL;                                                                                               
					char * out = strtok_r(optarg, VOL_SPLIT, &p);
					if (!out)
						break;
					char * in = strtok_r(NULL, VOL_SPLIT, &p);
					if (!in)
						break;
					snprintf(vol_path, sizeof(vol_path), "%s/%s", new_root, in);
					mkdir(vol_path, 0666);
					mount(out, vol_path, NULL, MS_BIND, NULL);
				}
				break;
		}
	}

	printf("<6>\n");
	if ((-1 == mkdir(path, 0777))
			|| (-1 == pivot_root(new_root, path))
			|| (-1 == chdir("/"))
			|| (-1 == umount2(put_old, MNT_DETACH))
			|| (-1 == rmdir(put_old)))
		exit(EXIT_FAILURE);

	printf("<7>\n");
	clearenv();
	setenv("HOME", "/", 1);
	setenv("PWD", "/", 1);
	setenv("TERM", "linux", 1);
	setenv("POWERD_BY_CRUND", "Y", 1);
	putenv("TEST=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
	int rootfsfd = open("/", O_PATH | O_CLOEXEC);
	int devfd = openat (rootfsfd, "dev", O_RDONLY | O_DIRECTORY);
	optind = 0;

	char auto_dev_path[PATH_MAX];
    for (int i = 0; i < sizeof(auto_devs) / sizeof(auto_devs[0]); i++) {
        const struct auto_dev *d = &auto_devs[i];
        //int ret = snprintf(auto_dev_path, PATH_MAX, "%s/dev/%s", new_root, d->name);
        //if (ret < 0 || ret >= PATH_MAX)
        //    continue;
        dev_t dev = makedev(d->major, d->minor);
		mknodat(devfd, d->name, d->mode, dev);
	}

	while ((c = getopt_long(argc, argv, "r:p:v:he:d:C", longopts, NULL)) != -1) {
		switch (c) {
			case 'e':
				putenv(optarg);
				break;
			case 'd':
				do {
					/*device name,major number,minor number,device type*/
					char * p = NULL;
					char * dev_name = strtok_r(optarg, DEV_SPLIT, &p);
					if (!dev_name)
						break;

					char * token = NULL;
					token = strtok_r(NULL, DEV_SPLIT, &p);
					if (!isdigitstr(token))
						break;
					int major = atoi(token);

					token = strtok_r(NULL, DEV_SPLIT, &p);
					if (!isdigitstr(token))
						break;
					int minor = atoi(token);

					token = strtok_r(NULL, DEV_SPLIT, &p);
					if (0 == strcmp(token, "c")) {
						dev_t dev = makedev(major, minor);
						mknodat(devfd, dev_name, 0666 | S_IFCHR, dev);
					}
					else if (0 == strcmp(token, "b")) {
						dev_t dev = makedev(major, minor);
						mknodat(devfd, dev_name, 0666 | S_IFBLK, dev);
					}
				} while (0);
				break;
			case 'C':
				goto END;
				break;
		}
	}

END:
	printf("<E>\n");
	close(devfd);
	close(rootfsfd);
	if (optind < argc) {
		int ret = execvp(argv[optind], argv + optind);
		printf("container start error : %s\n", strerror(errno));
		return ret;
	}
	return EXIT_FAILURE;
}

int clone_new_pid(int argc, char** argv)
{
	static const struct option longopts[] = {
		{ "rootfs", required_argument, NULL, 'r' },
		{ "pid", no_argument, NULL, 'p' },
		{ "volume", required_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ "env", required_argument, NULL, 'e' },
		{ "device", required_argument, NULL, 'd' },
		{ "command", no_argument, NULL, 'C' },
		{ NULL, 0, NULL, 0 }
	};

	struct start_arg start_arg = {
		.argc = argc,
		.argv = argv,
	};

	const char * name = argv[0];
	FILE * pid_file = NULL;
	int status = 0;
	pid_t pid;
	int c = 0;
	while ((c = getopt_long(argc, argv, "r:p:v:he:d:C", longopts, NULL)) != -1) {
		switch (c) {
			case 'p':
				pid_file = fopen(optarg, "w");
				break;
			case 'h':
				help(name);
				exit(EXIT_FAILURE);
		}
	}

	const int gid = getgid();
	const int uid = getuid();
	pid = __clone(start_container, &start_arg);
	if (pid < 0) {
		printf("failed to clone\n");
		if (pid_file) {
			fclose(pid_file);
			pid_file = NULL;
		}
		return EXIT_FAILURE;
	}
	set_uid_map(pid, 0, uid, 1);
	set_gid_map(pid, 0, gid, 1);
	if (pid_file) {
		fprintf(pid_file, "%d\n", pid);
		fclose(pid_file);
		pid_file = NULL;
	}

	if (waitpid(pid, &status, 0) < 0) {
		printf("failed to wait for '%d', status:%d\n", pid, status);
		return EXIT_FAILURE;
	}

	return 0;
}

int main(int argc, char** argv)
{
	return clone_new_pid(argc, argv);
}	
