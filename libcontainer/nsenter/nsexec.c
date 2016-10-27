#define _GNU_SOURCE
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/types.h>

/* Get all of the CLONE_NEW* flags. */
#include "namespace.h"

/* Get the cmsg utilities. */
#include "cmsg.h"

/* Synchronisation values. */
enum sync_t {
	SYNC_USERMAP_PLS = 0x40, /* Request parent to map our users. */
	SYNC_USERMAP_ACK = 0x41, /* Mapping finished by the parent. */
	SYNC_RECVPID_PLS = 0x42, /* Tell parent we're sending the PID. */
	SYNC_RECVPID_SYN = 0x43, /* Tell init we're ready to receive the PID. */
	SYNC_RECVPID_ACK = 0x44, /* PID was correctly received by parent. */

	/* XXX: This doesn't help with segfaults and other such issues. */
	SYNC_ERR = 0xFF, /* Fatal error, no turning back. The error code follows. */
};

/* longjmp() arguments. */
#define JUMP_PARENT 0x00
#define JUMP_CHILD  0xA0
#define JUMP_INIT   0xA1

/* JSON buffer. */
#define JSON_MAX 4096

/* Assume the stack grows down, so arguments should be above it. */
struct clone_t {
	/*
	 * Reserve some space for clone() to locate arguments
	 * and retcode in this place
	 */
	char stack[4096] __attribute__ ((aligned(16)));
	char stack_ptr[0];

	/* There's two children. This is used to execute the different code. */
	jmp_buf *env;
	int jmpval;
};

struct nlconfig_t {
	/*
	 * Stores a pointer to the netlink data payload. All other pointers
	 * are inside this block. Free it with nl_free().
	 */
	char *data;

	/* Options sent from the bootstrap process. */
	uint32_t cloneflags;
	char *uidmap;
	size_t uidmap_len;
	char *gidmap;
	size_t gidmap_len;
	char *namespaces;
	size_t namespaces_len;
	uint8_t is_setgroup;
	int consolefd;

	/*
	 * Namespace uids and gids. If cloneflags doesn't contain
	 * CLONE_NEWUSER then these will be 0. host{uid,gid} are from the
	 * host's perspective and root{uid,gid} are from the container's
	 * perspective.
	 */
	uid_t hostuid;
	gid_t hostgid;
	uid_t rootuid;
	gid_t rootgid;

	/* The set of namespace types that we joined with .namespaces. */
	long joined;
};

/*
 * List of netlink message types sent to us as part of bootstrapping the init.
 * These constants are defined in libcontainer/message_linux.go.
 */
#define INIT_MSG		62000
#define CLONE_FLAGS_ATTR	27281
#define CONSOLE_PATH_ATTR	27282
#define NS_PATHS_ATTR		27283
#define UIDMAP_ATTR		27284
#define GIDMAP_ATTR		27285
#define SETGROUP_ATTR		27286

/*
 * Use the raw syscall for versions of glibc which don't include a function for
 * it, namely (glibc 2.12).
 */
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
#	define _GNU_SOURCE
#	include "syscall.h"
#	if !defined(SYS_setns) && defined(__NR_setns)
#		define SYS_setns __NR_setns
#	endif

#ifndef SYS_setns
#	error "setns(2) syscall not supported by glibc version"
#endif

int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}
#endif

/* XXX: This is ugly. */
static int syncfd = -1;

/* TODO(cyphar): Fix this so it correctly deals with syncT. */
// __COUNTER__ 有什么意义？
#define bail(fmt, ...)								\
	do {									\
		int ret = __COUNTER__ + 1;					\
		fprintf(stderr, "nsenter: " fmt ": %m\n", ##__VA_ARGS__);	\
		if (syncfd >= 0) {						\
			enum sync_t s = SYNC_ERR;				\
			if (write(syncfd, &s, sizeof(s)) != sizeof(s))		\
				fprintf(stderr, "nsenter: failed: write(s)");	\
			if (write(syncfd, &ret, sizeof(ret)) != sizeof(ret))	\
				fprintf(stderr, "nsenter: failed: write(ret)");	\
		}								\
		exit(ret);							\
	} while(0)

#define debug(fmt, ...)								\
	do {									\
		fprintf(stdout, "nsenter[%d][%d]: " fmt "\n",getpid(), getppid(), ##__VA_ARGS__);		\
	} while(0)

static int write_file(char *data, size_t data_len, char *pathfmt, ...)
{
	int fd, len, ret = 0;
	char path[PATH_MAX];

	va_list ap;
	va_start(ap, pathfmt);
	len = vsnprintf(path, PATH_MAX, pathfmt, ap);
	va_end(ap);
	if (len < 0)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		ret = -1;
		goto out;
	}

	len = write(fd, data, data_len);
	if (len != data_len) {
		ret = -1;
		goto out;
	}

out:
	close(fd);
	return ret;
}

enum policy_t {
	SETGROUPS_DEFAULT = 0,
	SETGROUPS_ALLOW,
	SETGROUPS_DENY,
};

/* This *must* be called before we touch gid_map. */
static void update_setgroups(int pid, enum policy_t setgroup)
{
	char *policy;

	switch (setgroup) {
		case SETGROUPS_ALLOW:
			policy = "allow";
			break;
		case SETGROUPS_DENY:
			policy = "deny";
			break;
		case SETGROUPS_DEFAULT:
			/* Nothing to do. */
			return;
	}

	if (write_file(policy, strlen(policy), "/proc/%d/setgroups", pid) < 0) {
		/*
		 * If the kernel is too old to support /proc/pid/setgroups,
		 * open(2) or write(2) will return ENOENT. This is fine.
		 */
		if (errno != ENOENT)
			bail("failed to write '%s' to /proc/%d/setgroups", policy, pid);
	}
}

static void update_uidmap(int pid, char *map, int map_len)
{
	if (map == NULL || map_len <= 0)
		return;

	if (write_file(map, map_len, "/proc/%d/uid_map", pid) < 0)
		bail("failed to update /proc/%d/uid_map", pid);
}

static void update_gidmap(int pid, char *map, int map_len)
{
	if (map == NULL || map_len <= 0)
		return;

	if (write_file(map, map_len, "/proc/%d/gid_map", pid) < 0)
		bail("failed to update /proc/%d/gid_map", pid);
}

static char *trim(char *str, char *end, bool space) {
	char *p = str;

	while (p != end && isspace(*p) == space)
		p++;
	if (p == end)
		return NULL;

	return p;
}

/*
 * Get the nth field from a space-separated map. Note that this only handles a
 * single map line (which is enough for libcontainer at the moment) but might
 * need to be expanded at a later point.
 *
 * TODO: Expand this to handle multiple-line /proc/self/???_map files.
 */
static int map_field(char *map, int map_len, int n)
{
	char *p = map;
	char *end = map + map_len;
	int i, value = 0;

	/* Advance *p to the field. */
	for (i = 0; i < n; i++) {
		/* Trim the spaces. */
		p = trim(p, end, true);
		if (!p)
			bail("unexpected end of map: '%s'", map);

		/* Now we can skip over the actual field content. */
		p = trim(p, end, false);
		if (!p)
			bail("unexpected end of map: '%s'", map);
	}

	/* We don't need to trim spaces, strtol(3) handles it fine. */
	value = strtol(p, &end, 10);
	if (p == end || !isspace(*end))
		bail("failed to parse field %d value: '%s'", n, map);

	return value;
}

// 为什么要分开写？？？？
/* A dummy function that just jumps to the given jumpval. */
static int child_func(void *arg) __attribute__ ((noinline));
static int child_func(void *arg)
{
	struct clone_t *ca = (struct clone_t *)arg;
	// 通过longjmp跳转到合适的位置，ca->jmpval局势setjmp的返回值
	longjmp(*ca->env, ca->jmpval);
}

static int clone_parent(jmp_buf *env, int jmpval) __attribute__ ((noinline));
static int clone_parent(jmp_buf *env, int jmpval)
{
	struct clone_t ca = {
		.env    = env,
		.jmpval = jmpval,
	};
	// CLONE_PARENT: 创建的子进程的父进程是调用者的父进程，新进程与创建它的进程成了“兄弟”而不是“父子”
	// SIGCHLD： flags的低字节包含了子进程死亡的时候发送给父进程的信号，如果信号指定了除了SIGCHLD之外的任何位，
	// 父进程在通过wait(2)等待子进程时，必须指定__WALL或者__WCLONE选项。
	// 如果没有指定信号，父进程在子进程终结的时候不会收到信号。
	// 子进程会执行函数child_func,并将&ca传递给函数child_func
	return clone(child_func, ca.stack_ptr, CLONE_PARENT | SIGCHLD, &ca);
}

/*
 * Gets the init pipe fd from the environment, which is used to read the
 * bootstrap data and tell the parent what the new pid is after we finish
 * setting up the environment.
 */
static int initpipe(void)
{
	int pipenum;
	char *initpipe, *endptr;

	initpipe = getenv("_LIBCONTAINER_INITPIPE");
	if (initpipe == NULL || *initpipe == '\0')
		return -1;

	pipenum = strtol(initpipe, &endptr, 10);
	if (*endptr != '\0')
		bail("unable to parse _LIBCONTAINER_INITPIPE");

	return pipenum;
}

/* Returns the clone(2) flag for a namespace, given the name of a namespace. */
static int nsflag(char *name)
{
	if (!strcmp(name, "cgroup"))
		return CLONE_NEWCGROUP;
	else if (!strcmp(name, "ipc"))
		return CLONE_NEWIPC;
	else if (!strcmp(name, "mnt"))
		return CLONE_NEWNS;
	else if (!strcmp(name, "net"))
		return CLONE_NEWNET;
	else if (!strcmp(name, "pid"))
		return CLONE_NEWPID;
	else if (!strcmp(name, "user"))
		return CLONE_NEWUSER;
	else if (!strcmp(name, "uts"))
		return CLONE_NEWUTS;

	/* If we don't recognise a name, fallback to 0. */
	return 0;
}

static uint32_t readint32(char *buf)
{
	return *(uint32_t *) buf;
}

static uint8_t readint8(char *buf)
{
	return *(uint8_t *) buf;
}

static void nl_parse(int fd, struct nlconfig_t *config)
{
	size_t len, size;
	struct nlmsghdr hdr;
	char *data, *current;

	/* Retrieve the netlink header. */
	len = read(fd, &hdr, NLMSG_HDRLEN);
	if (len != NLMSG_HDRLEN)
		bail("invalid netlink header length %lu", len);

	if (hdr.nlmsg_type == NLMSG_ERROR)
		bail("failed to read netlink message");

	if (hdr.nlmsg_type != INIT_MSG)
		bail("unexpected msg type %d", hdr.nlmsg_type);

	/* Retrieve data. */
	size = NLMSG_PAYLOAD(&hdr, 0);
	current = data = malloc(size);
	if (!data)
		bail("failed to allocate %zu bytes of memory for nl_payload", size);

	len = read(fd, data, size);
	if (len != size)
		bail("failed to read netlink payload, %lu != %lu", len, size);

	/* Parse the netlink payload. */
	config->data = data;
	config->consolefd = -1;
	while (current < data + size) {
		struct nlattr *nlattr = (struct nlattr *)current;
		size_t payload_len = nlattr->nla_len - NLA_HDRLEN;

		/* Advance to payload. */
		current += NLA_HDRLEN;

		/* Handle payload. */
		switch (nlattr->nla_type) {
		case CLONE_FLAGS_ATTR:
			config->cloneflags = readint32(current);
			break;
		case CONSOLE_PATH_ATTR:
			/*
			 * We open the console here because we currently evaluate console
			 * paths from the *host* namespaces.
			 */
			config->consolefd = open(current, O_RDWR);
			if (config->consolefd < 0)
				bail("failed to open console %s", current);
			break;
		case NS_PATHS_ATTR: {
				char *copy;
				char *namespace;
				char *saveptr = NULL;

				config->namespaces = current;
				config->namespaces_len = payload_len;

				/* We need a copy of the namespaces to parse .joined. */
				copy = strndup(config->namespaces, config->namespaces_len);
				if (!copy)
					bail("failed to allocate buffer for namespaces");

				/* Parse namespace string. */
				namespace = strtok_r(copy, ",", &saveptr);
				do {
					char *path;

					/* Split 'ns:path'. */
					path = strstr(namespace, ":");
					if (!path)
						bail("failed to parse %s", namespace);
					*path++ = '\0';

					/* Add the namespace cloneflag to joined. */
					config->joined |= nsflag(namespace);
				} while ((namespace = strtok_r(NULL, ",", &saveptr)) != NULL);
				free(copy);
			}
			break;
		case UIDMAP_ATTR:
			config->uidmap = current;
			config->uidmap_len = payload_len;

			/* The format: "<container> <host> <length>" */
			config->hostuid = map_field(config->uidmap, config->uidmap_len, 1);
			config->rootuid = map_field(config->uidmap, config->uidmap_len, 0);
			break;
		case GIDMAP_ATTR:
			config->gidmap = current;
			config->gidmap_len = payload_len;

			/* The format: "<container> <host> <length>" */
			config->hostgid = map_field(config->gidmap, config->gidmap_len, 1);
			config->rootgid = map_field(config->gidmap, config->gidmap_len, 0);
			break;
		case SETGROUP_ATTR:
			config->is_setgroup = readint8(current);
			break;
		default:
			bail("unknown netlink message type %d", nlattr->nla_type);
		}

		current += NLA_ALIGN(payload_len);
	}

	// 解析完成，为什么不能在这里释放？
}

static void nl_free(struct nlconfig_t *config)
{
	free(config->data);
}

static void join_namespaces(struct nlconfig_t *config)
{
	int num = 0, i;
	char *saveptr = NULL;
	char *namespace = strtok_r(config->namespaces, ",", &saveptr);
	struct namespace_t {
		int fd;
		int ns;
		char type[PATH_MAX];
		char path[PATH_MAX];
	} *namespaces = NULL;
	struct namespace_t *userns = NULL;

	if (!namespace || !strlen(namespace) || !strlen(config->namespaces))
		bail("ns paths are empty");

	/*
	 * We have to open the file descriptors first, since after
	 * we join the mnt namespace we might no longer be able to
	 * access the paths.
	 */
	do {
		int fd;
		char *path;
		struct namespace_t *ns;

		debug("child: namespace = %s", namespace);
		/* Resize the namespace array. */
		namespaces = realloc(namespaces, ++num * sizeof(struct namespace_t));
		if (!namespaces)
			bail("failed to reallocate namespace array");
		ns = &namespaces[num - 1];

		/* Split 'ns:path'. */
		path = strstr(namespace, ":");
		if (!path)
			bail("failed to parse %s", namespace);
		*path++ = '\0';

		fd = open(path, O_RDONLY);
		if (fd < 0)
			bail("failed to open %s", namespace);

		ns->fd = fd;
		ns->ns = nsflag(namespace);
		strncpy(ns->path, path, PATH_MAX);

		/* Cache the user namespace entry. */
		if (ns->ns == CLONE_NEWUSER || !strcmp(namespace, "user"))	// 一个判断就足够了
			userns = ns;
	} while ((namespace = strtok_r(NULL, ",", &saveptr)) != NULL);

	/*
	 * Before we join anything, we need to set our {uid,gid}. The ideal way of
	 * doing this would be to read /proc/<pid>/{uid,gid}_map, but we can't be
	 * sure if we have access to that (and we don't even know the PID in this
	 * context). Instead we can just get the owner of the namespace files we're
	 * joining (logically this should be the root user in the namespace).
	 *
	 * This all has to be done to avoid security issues with joining a
	 * namespace while also having euid=(kuid 0), since unprivileged processes
	 * inside the namespace have capabilities that are a bit worrying for a
	 * *real* root process.
	 */

	if (userns) {
		struct stat st = {0};

		/* Get the owner of /proc/<pid>/ns/user. */
		if (lstat(userns->path, &st) < 0)
			bail("failed to stat path: %s", userns->path);

		/* Switch groups first, the order is important. */
		if (setresgid(st.st_gid, st.st_gid, st.st_gid) < 0)
			bail("failed to set gid to st.st_gid of %s", userns->path);
		if (setresuid(st.st_uid, st.st_uid, st.st_uid) < 0)
			bail("failed to set uid to st.st_uid of %s", userns->path);
	}

	/*
	 * The ordering in which we join namespaces is important. We should
	 * always join the user namespace *first*. This is all guaranteed
	 * from the container_linux.go side of this, so we're just going to
	 * follow the order given to us.
	 */

	for (i = 0; i < num; i++) {
		struct namespace_t ns = namespaces[i];

		if (setns(ns.fd, ns.ns) < 0)
			bail("failed to setns to %s", ns.path);

		close(ns.fd);
	}

	free(namespaces);
}

void nsexec(void)
{
	int pipenum, arg = 0;
	jmp_buf env;
	struct nlconfig_t config = {0};

	/* This is used for communication with 0:PARENT (us). */
	int parentpipe[2] = {0};

	/*
	 * If we don't have an init pipe, just return to the go routine.
	 * We'll only get an init pipe for start or exec.
	 */
	pipenum = initpipe();	// 读取环境变量_LIBCONTAINER_INITPIPE的值，并将其转换为init
	debug("pipenum = %d", pipenum);
	if (pipenum == -1) {
		debug("just return to the go routine");
		return;
	}

	/* Parse all of the netlink configuration. */
	/* XXX: Make the {root,host}{uid,gid} = 0 explicit. */
	debug("parse all of the netlink configuration");
	nl_parse(pipenum, &config);

	/* clone(2) flags are mandatory. */
	if (config.cloneflags == -1)
		bail("missing cloneflags");

	/* Pipe so we can tell the child when we've finished setting up. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, parentpipe) < 0)
		bail("failed to setup sync pipe between parent and child");
	debug("parentpipe[0] = %d", parentpipe[0]);
	debug("parentpipe[1] = %d", parentpipe[1]);


	// 设置soc->sk->sk_flag中的SOCK_PASSCRED位。
	// 允许SCM_CREDENTIALS控制消息的接收。
	arg = 1;
	if (setsockopt(parentpipe[0], SOL_SOCKET, SO_PASSCRED, &arg, sizeof(arg)) < 0)
		bail("failed to setsockopt(SO_PASSCRED) on parentpipe[0]");
	if (setsockopt(parentpipe[1], SOL_SOCKET, SO_PASSCRED, &arg, sizeof(arg)) < 0)
		bail("failed to setsockopt(SO_PASSCRED) on parentpipe[1]");

	/* TODO: Currently we aren't dealing with child deaths properly. */

	/*
	 * Okay, so this is quite annoying.
	 *
	 * In order to make sure that deal with older kernels (when CLONE_NEWUSER
	 * wasn't guaranteed to be done first if you specify multiple namespaces in
	 * a clone(2) invocation) as well as with certain usecases like rootless
	 * containers, we cannot just dump all of the cloneflags into clone(2).
	 * However, if we unshare(2) the user namespace *before* we clone(2), then
	 * all hell breaks loose.
	 *
	 * The parent no longer has permissions to do many things (unshare(2) drops
	 * all capabilities in your old namespace), and the container cannot be set
	 * up to have more than one {uid,gid} mapping. This is obviously less than
	 * ideal. In order to fix this, we have to first clone(2) and then unshare.
	 *
	 * Unfortunately, it's not as simple as that. We have to fork to enter the
	 * PID namespace (the PID namespace only applies to children). Since we'll
	 * have to double-fork, this clone_parent() call won't be able to get the
	 * PID of the _actual_ init process (without doing more synchronisation than
	 * I can deal with at the moment). So we'll just get the parent to send it
	 * for us, the only job of this process is to update
	 * /proc/pid/{setgroups,uid_map,gid_map}.
	 *
	 * And as a result of the above, we also need to setns(2) in the first child
	 * because if we join a PID namespace in the topmost parent then our child
	 * will be in that namespace (and it will not be able to give us a PID value
	 * that makes sense without resorting to sending things with cmsg).
	 *
	 * In addition, we have to deal with the fact that zombies report to their
	 * parents, not to the "init inside a PID namespace" by default. This means
	 * that we also have to double-fork(2) inside the 2:INIT process, while
	 * also dealing with the fact that the "child PID" mentioned above is no
	 * longer valid and needs to be updated through yet another pipe. This is
	 * so much fun.
	 *
	 * This also deals with an older issue caused by dumping cloneflags into
	 * clone(2): On old kernels, CLONE_PARENT didn't work with CLONE_NEWPID, so
	 * we have to unshare(2) before clone(2) in order to do this. This was fixed
	 * in upstream commit 1f7f4dde5c945f41a7abc2285be43d918029ecc5, and was
	 * introduced by 40a0d32d1eaffe6aac7324ca92604b6b3977eb0e. As far as we're
	 * aware, the last mainline kernel which had this bug was Linux 3.12.
	 * However, we cannot comment on which kernels the broken patch was
	 * backported to.
	 *
	 * -- Aleksa "what has my life come to?" Sarai
	 */

	switch (setjmp(env)) {
	/*
	 * Stage 0: We're in the parent. Our job is just to create a new child
	 *          (stage 1: JUMP_CHILD) process and write its uid_map and
	 *          gid_map. That process will go on to create a new process, then
	 *          it will send us its PID which we will send to the bootstrap
	 *          process.
	 * 所做工作：创建子进程JUMP_CHILD，并写入它的uid_map 和 gid_map.JUMP_CHILD将会
	 *           创建新的子进程INIT，INIT子进程会将自己PID发送给JUMP_PARENT，
         *           最后由JUMP_PARENT将该PID发送给bootstrap进程
	 */
	case JUMP_PARENT: {
			int len;
			pid_t child;
			char buf[JSON_MAX];

			/* For debugging. */
			debug("parent: set the name of the calling thread to runc:[0:PARENT]");
			prctl(PR_SET_NAME, (unsigned long) "runc:[0:PARENT]", 0, 0, 0);

			/* Start the process of getting a container. */
			// 创建子进程，子进程通过longjmp，跳转到JUMP_CHILD处执行
			child = clone_parent(&env, JUMP_CHILD);
			debug("parent: create child process: child = %d", child);
			if (child < 0)
				bail("unable to fork: child_func");

			/* State machine for synchronisation with the children. */
			while (true) {
				enum sync_t s;

				/* This doesn't need to be global, we're in the parent. */
				int syncfd = parentpipe[1];

				debug("parent: read syncfd to sync with child: next state");
				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with child: next state");

				switch (s) {
				case SYNC_ERR: {
						debug("parent: get SYNC_ERR");
						/* We have to mirror the error code of the child. */
						int ret;

						if (read(syncfd, &ret, sizeof(ret)) != sizeof(ret))
							bail("failed to sync with child: read(error code)");

						exit(ret);
					}
					break;
				case SYNC_USERMAP_PLS:
					debug("parent: get SYNC_USERMAP_PLS");
					/* Enable setgroups(2) if we've been asked to. */
					if (config.is_setgroup)
						update_setgroups(child, SETGROUPS_ALLOW);

					/* Set up mappings. */
					update_uidmap(child, config.uidmap, config.uidmap_len);
					update_gidmap(child, config.gidmap, config.gidmap_len);

					s = SYNC_USERMAP_ACK;
					if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
						kill(child, SIGKILL);
						bail("failed to sync with child: write(SYNC_USERMAP_ACK)");
					}
					break;
				case SYNC_USERMAP_ACK:
					debug("parent: get SYNC_USERMAP_ACK");
					/* We should _never_ receive acks. */
					kill(child, SIGKILL);
					bail("failed to sync with child: unexpected SYNC_USERMAP_ACK");
					break;
				case SYNC_RECVPID_PLS: {
						debug("parent: get SYNC_RECVPID_PLS");
						pid_t old = child;

						/*
						 * Send SYN. This is necessary to make sure that the syscalls on the
						 * other end aren't reordered so that we hit a read at the wrong
						 * moment.
						 */
						s = SYNC_RECVPID_SYN;
						if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
							kill(old, SIGKILL);
							bail("failed to sync with child: write(SYNC_RECVPID_ACK)");
						}

						child = recvpid(syncfd);
						if (child < 0) {
							kill(old, SIGKILL);
							bail("failed to sync with child: read(childpid)");
						}

						/* Send ACK. */
						s = SYNC_RECVPID_ACK;
						if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
							kill(old, SIGKILL);
							kill(child, SIGKILL);
							bail("failed to sync with child: write(SYNC_RECVPID_ACK)");
						}
					}

					/* Leave the loop. */
					goto out;
				case SYNC_RECVPID_ACK:
					debug("parent: get SYNC_RECVPID_ACK");
					/* We should _never_ receive acks. */
					kill(child, SIGKILL);
					bail("failed to sync with child: unexpected SYNC_RECVPID_ACK");
					break;
				case SYNC_RECVPID_SYN:
					debug("parent: get SYNC_RECVPID_SYN");
					/* We should _never_ receive syns. */
					kill(child, SIGKILL);
					bail("failed to sync with child: unexpected SYNC_RECVPID_SYN");
					break;
				}
			}

		out:
			/* Send the init_func pid back to our parent. */
			debug("parent: send the init func pid[%d] back to our parent", child);
			len = snprintf(buf, JSON_MAX, "{\"pid\": %d}\n", child);
			if (len < 0) {
				kill(child, SIGKILL);
				bail("unable to generate JSON for child pid");
			}
			if (write(pipenum, buf, len) != len) {
				kill(child, SIGKILL);
				bail("unable to send child pid to bootstrapper");
			}

			exit(0);
		}

	/*
	 * Stage 1: We're in the first child process. Our job is to join any
	 *          provided user namespaces in the netlink payload. If we've been
	 *          asked to CLONE_NEWUSER, we will unshare the user namespace and
	 *          ask our parent (stage 0) to set up our user mappings for us.
	 *          Then, we unshare the rest of the requested namespaces and
	 *          create a new child (stage 2: JUMP_INIT).
         * 所做工作：首先根据netlink payload中的配置join namespace
	 *	    如果设置了CLONE_NEWUSER，我们将会unshare user namespace，并请求
	 *	     JUMP_PARENT 设置我们的 user mappings，然后我们unshare 其他namesapce
	 *	     并创建子进程JUMP_INIT
	 */
	case JUMP_CHILD: {
			enum sync_t s;

			/* We're in a child and thus need to tell the parent if we die. */
			syncfd = parentpipe[0];

			/* For debugging. */
			debug("child: set the name of the calling thread to runc:[1:CHILD]");
			prctl(PR_SET_NAME, (unsigned long) "runc:[1:CHILD]", 0, 0, 0);

			/*
			 * We need to setns first. We cannot do this earlier (in stage 0)
			 * because of the fact that we forked to get here (the PID of
			 * [stage 2: JUMP_INIT]) would be meaningless). We could send it
			 * using cmsg(3) but that's just annoying.
			 */
			if (config.namespaces) {
				debug("child: config.namespaces = %s", config.namespaces);
				join_namespaces(&config);
			}
			/*
			 * This needs to be done if we're about to create a user namespace.
			 * If we already joined a user namespace this is also fine (we do a
			 * similar operation in join_namespaces). There are some security
			 * issues with having an euid=(kuid 0) inside a user namespace.
			 */

			/* Switch groups first, the order is important. */
			if (setresgid(config.hostgid, config.hostgid, config.hostgid) < 0)
				bail("failed to set gid to host");
			if (setresuid(config.hostuid, config.hostuid, config.hostuid) < 0)
				bail("failed to set uid to host");

			/*
			 * Deal with user namespaces first. They are quite special, as they
			 * affect our ability to unshare other namespaces and are used as
			 * context for privilege checks.
			 */
			if (config.cloneflags & CLONE_NEWUSER) {
				/* Create a new user namespace. */
				if (unshare(CLONE_NEWUSER) < 0)
					bail("failed to unshare user namespace");

				/*
				 * We don't have the privileges to do any mapping here (see the
				 * clone_parent rant). So signal our parent to hook us up.
				 */
				debug("child: sync with parent:  write(SYNC_USERMAP_PLS)");
				s = SYNC_USERMAP_PLS;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: write(SYNC_USERMAP_PLS)");

				/* ... wait for mapping ... */

				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: read(SYNC_USERMAP_ACK)");
				if (s != SYNC_USERMAP_ACK)
					bail("failed to sync with parent: SYNC_USERMAP_ACK: got %u", s);
				debug("child: sync with parent: read(SYNC_USERMAP_ACK)");

				config.cloneflags &= ~CLONE_NEWUSER;
			}

			/*
			 * We need to do this before we set up any other namespaces, due to
			 * SELinux policies and other such security setups.
			 */

			/* Switch groups first, the order is important. */
			if (setresgid(config.rootgid, config.rootgid, config.rootgid) < 0)
				bail("failed to set gid to root");
			if (setresuid(config.rootuid, config.rootuid, config.rootuid) < 0)
				bail("failed to set uid to root");

			/*
			 * Now we can unshare the rest of the namespaces. We can't be sure if the
			 * current kernel supports clone(CLONE_PARENT | CLONE_NEWPID), so we'll
			 * just do it the long way anyway.
			 */
			if (unshare(config.cloneflags) < 0)
				bail("failed to unshare namespaces");

			/* TODO: What about non-namespace clone flags that we're dropping here? */
			if (clone_parent(&env, JUMP_INIT) < 0)
				bail("unable to fork: init_func");

			/*
			 * We don't need to handle anything else, as 2:INIT will send its
			 * own PID to 0:PARENT. Our only job was to mess around with user
			 * namespaces.
			 */
			exit(0);
		}

	/*
	 * Stage 2: We're the final child process, and the only process that will
	 *          actually return to the Go runtime. Our job is to just do the
	 *          final cleanup steps and then return to the Go runtime to allow
	 *          init_linux.go to run.
	 * 所作工作： 这是最后的child process。最后返回给go runtime的进程。
	 *	   主要做一些清理工作，并且返回到Go runtime，让init_linux.go继续执行
	 */
	case JUMP_INIT: {
			/*
			 * We're inside the child now, having jumped from the
			 * start_child() code after forking in the parent.
			 */
			int consolefd = config.consolefd;
			enum sync_t s;

			/* We're in a child and thus need to tell the parent if we die. */
			syncfd = parentpipe[0];

			/* For debugging. */
			debug("init: set the name of the calling thread to runc:[1:INIT]");
			prctl(PR_SET_NAME, (unsigned long) "runc:[2:INIT]", 0, 0, 0);

			/*
			 * If we're joining a PID namespace, we need to double-fork(2) in
			 * order to make sure that we are reparented to the init inside the
			 * container.  The first fork(2) places us inside the PID
			 * namespace, the second fork makes us an orphan. All of the other
			 * clone(2)s are with CLONE_PARENT so we have to do both fork(2)s
			 * here. See this LWN article for more background:
			 * https://lwn.net/Articles/532748/
			 */
			if (config.joined & CLONE_NEWPID) {
				debug("init: joining a PID namespace, we need to double-fork");
				pid_t first, second;

				/* Enter the PID namespace. */
				first = fork();
				if (first < 0) {
					bail("failed to fork first process");
				} else if (first > 0) {
					if (waitpid(first, NULL, 0) != first)
						bail("failed to wait for first process");
					exit(0);
				}

				debug("init: first fork");
				/* Orphan ourselves. */
				second = fork();
				if (second < 0)
					bail("failed to fork second process");
				else if (second > 0)
					exit(0);

				/* We are now reparented to the init inside the container. */
				debug("init: second fork");
			}

			/*
			 * We now need to send our PID to 0:PARENT. Since we're in a PID
			 * namespace we need to use SCM_CREDENTIALS. We don't really care
			 * about the {uid,gid} that we send, all that matters is that we're
			 * sending our PID.
			 */

			s = SYNC_RECVPID_PLS;
			if (write(syncfd, &s, sizeof(s)) != sizeof(s))
				bail("failed to sync with parent: write(SYNC_RECVPID_PLS)");
			if (read(syncfd, &s, sizeof(s)) != sizeof(s))
				bail("failed to sync with parent:  read(SYNC_RECVPID_SYN)");
			if (s != SYNC_RECVPID_SYN)
				bail("failed to sync with parent: SYNC_RECVPID_SYN: got %u", s);

			debug("init: send our pid");
			/* Send our PID. */
			if (sendpid(syncfd, getpid()) < 0)
				bail("failed to send PID to parent: sendmsg(pid)");

			/* ... wait for parent to receive PID ... */

			if (read(syncfd, &s, sizeof(s)) != sizeof(s))
				bail("failed to sync with parent: read(SYNC_RECVPID_ACK)");
			if (s != SYNC_RECVPID_ACK)
				bail("failed to sync with parent: SYNC_RECVPID_ACK: got %u", s);

			/* Now we can move on with the fun of setting up this container. */

			debug("init: setting up container, setsid setuid setgid setgroup");

			// creates a seeion and sets the process group ID
			if (setsid() < 0)
				bail("setsid failed");

			// set user identity
			if (setuid(0) < 0)
				bail("setuid failed");
			// set group identity
			if (setgid(0) < 0)
				bail("setgid failed");

			// set list of supplementary group IDs
			if (setgroups(0, NULL) < 0)
				bail("setgroups failed");

			// 如果用户指定了console，则进行相关设置
			if (consolefd != -1) {
				// 会话的首进程调用TIOCSCTTY为REQUEST的ioctl为会话期分配控制终端
				if (ioctl(consolefd, TIOCSCTTY, 0) < 0)
					bail("ioctl TIOCSCTTY failed");

				// duplicate a file descriptor
				// int dup3(int oldfd, int newfd, int flags);
				if (dup3(consolefd, STDIN_FILENO, 0) != STDIN_FILENO)
					bail("failed to dup stdin");
				if (dup3(consolefd, STDOUT_FILENO, 0) != STDOUT_FILENO)
					bail("failed to dup stdout");
				if (dup3(consolefd, STDERR_FILENO, 0) != STDERR_FILENO)
					bail("failed to dup stderr");
			}

			/* Close sync pipes. */
			debug("init: close sync pipes");
			close(parentpipe[0]);
			close(parentpipe[1]);

			/* Free netlink data. */ // 其实可以更早的释放
			debug("init: free netlink data");
			nl_free(&config);

			/* Finish executing, let the Go runtime take over. */
			return;
		}
	default:
		bail("unexpected jump value");
		break;
	}

	/* Should never be reached. */
	bail("should never be reached");
}
