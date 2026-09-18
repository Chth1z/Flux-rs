#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define FLUXRS_IOCTL_MAGIC 'F'

struct fluxrs_listeners {
	uint32_t v4_addr;
	uint16_t v4_port;
	uint16_t pad0;
	struct in6_addr v6_addr;
	uint16_t v6_port;
	uint16_t pad1;
};

struct fluxrs_uids {
	uint32_t count;
	uint32_t uids[64];
};

struct fluxrs_status {
	uint32_t live;
	uint32_t steal_ready;
	uint64_t selected_seen;
	uint64_t stolen;
	uint64_t miss_listener;
};

#define FLUXRS_SET_LISTENERS \
	_IOW(FLUXRS_IOCTL_MAGIC, 1, struct fluxrs_listeners)
#define FLUXRS_SET_UIDS _IOW(FLUXRS_IOCTL_MAGIC, 2, struct fluxrs_uids)
#define FLUXRS_GET_STATUS _IOR(FLUXRS_IOCTL_MAGIC, 4, struct fluxrs_status)

static const char payload[] = "fluxrs-st";

static void die_alarm(int sig)
{
	(void)sig;
	write(STDERR_FILENO, "ALRM\n", 5);
	_exit(3);
}

static int send_as_uid(const char *ip, uint16_t port, uid_t uid)
{
	pid_t pid = fork();
	int st, fd, rc;
	struct sockaddr_in a;

	if (pid < 0)
		return -errno;
	if (pid == 0) {
		if (uid != 0 && setuid(uid) != 0)
			_exit(4);
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0)
			_exit(5);
		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_port = htons(port);
		if (inet_pton(AF_INET, ip, &a.sin_addr) != 1)
			_exit(6);
		rc = sendto(fd, payload, sizeof(payload) - 1, 0,
			    (struct sockaddr *)&a, sizeof(a));
		_exit(rc < 0 ? 7 : 0);
	}
	if (waitpid(pid, &st, 0) < 0)
		return -errno;
	if (!WIFEXITED(st))
		return -EIO;
	if (WEXITSTATUS(st) == 0)
		return (int)(sizeof(payload) - 1);
	return -EPERM;
}

static int connect_tcp_as_uid(const char *ip, uint16_t port, uid_t uid)
{
	pid_t pid = fork();
	int st, fd, flags, rc;
	struct sockaddr_in a;

	if (pid < 0)
		return -errno;
	if (pid == 0) {
		if (uid != 0 && setuid(uid) != 0)
			_exit(4);
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			_exit(5);
		flags = fcntl(fd, F_GETFL, 0);
		if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
			_exit(5);
		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_port = htons(port);
		if (inet_pton(AF_INET, ip, &a.sin_addr) != 1)
			_exit(6);
		rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
		if (rc == 0 || errno == EINPROGRESS)
			_exit(0);
		_exit(7);
	}
	if (waitpid(pid, &st, 0) < 0)
		return -errno;
	if (!WIFEXITED(st))
		return -EIO;
	if (WEXITSTATUS(st) == 0)
		return 0;
	return -EPERM;
}

static int send_as_uid6(const char *ip, uint16_t port, uid_t uid)
{
	pid_t pid = fork();
	int st, fd, rc;
	struct sockaddr_in6 a;

	if (pid < 0)
		return -errno;
	if (pid == 0) {
		if (uid != 0 && setuid(uid) != 0)
			_exit(4);
		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if (fd < 0)
			_exit(5);
		memset(&a, 0, sizeof(a));
		a.sin6_family = AF_INET6;
		a.sin6_port = htons(port);
		if (inet_pton(AF_INET6, ip, &a.sin6_addr) != 1)
			_exit(6);
		rc = sendto(fd, payload, sizeof(payload) - 1, 0,
			    (struct sockaddr *)&a, sizeof(a));
		_exit(rc < 0 ? 7 : 0);
	}
	if (waitpid(pid, &st, 0) < 0)
		return -errno;
	if (!WIFEXITED(st))
		return -EIO;
	if (WEXITSTATUS(st) == 0)
		return (int)(sizeof(payload) - 1);
	return -EPERM;
}

static int connect_tcp_as_uid6(const char *ip, uint16_t port, uid_t uid)
{
	pid_t pid = fork();
	int st, fd, flags, rc;
	struct sockaddr_in6 a;

	if (pid < 0)
		return -errno;
	if (pid == 0) {
		if (uid != 0 && setuid(uid) != 0)
			_exit(4);
		fd = socket(AF_INET6, SOCK_STREAM, 0);
		if (fd < 0)
			_exit(5);
		flags = fcntl(fd, F_GETFL, 0);
		if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
			_exit(5);
		memset(&a, 0, sizeof(a));
		a.sin6_family = AF_INET6;
		a.sin6_port = htons(port);
		if (inet_pton(AF_INET6, ip, &a.sin6_addr) != 1)
			_exit(6);
		rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
		if (rc == 0 || errno == EINPROGRESS)
			_exit(0);
		_exit(7);
	}
	if (waitpid(pid, &st, 0) < 0)
		return -errno;
	if (!WIFEXITED(st))
		return -EIO;
	if (WEXITSTATUS(st) == 0)
		return 0;
	return -EPERM;
}

static void print_status(int ctl, const char *tag)
{
	struct fluxrs_status st;

	memset(&st, 0, sizeof(st));
	if (ioctl(ctl, FLUXRS_GET_STATUS, &st) != 0) {
		printf("%s ioctl_errno=%d\n", tag, errno);
		return;
	}
	printf("%s live=%u steal_ready=%u seen=%llu stolen=%llu miss=%llu\n",
	       tag, st.live, st.steal_ready,
	       (unsigned long long)st.selected_seen,
	       (unsigned long long)st.stolen,
	       (unsigned long long)st.miss_listener);
}

int main(int argc, char **argv)
{
	struct fluxrs_listeners lis;
	struct fluxrs_uids uids;
	uid_t uid;
	uint16_t dport;
	int ctl, rc;

	if (argc != 4 && argc != 8 && argc != 9) {
		fprintf(stderr,
			"usage: %s <uid> <v4_dest> <dport> "
			"[v4_listen v4_lport v6_listen v6_lport [v6_dest]]\n",
			argv[0]);
		return 2;
	}
	uid = (uid_t)atoi(argv[1]);
	dport = (uint16_t)atoi(argv[3]);
	if (uid == 0 || dport == 0) {
		fprintf(stderr, "uid/dport must be non-zero\n");
		return 2;
	}

	signal(SIGALRM, die_alarm);
	alarm(6);

	ctl = open("/dev/fluxrs", O_RDONLY);
	if (ctl < 0) {
		fprintf(stderr, "open /dev/fluxrs errno=%d\n", errno);
		return 1;
	}

	if (argc >= 8) {
		memset(&lis, 0, sizeof(lis));
		inet_pton(AF_INET, argv[4], &lis.v4_addr);
		lis.v4_port = htons((uint16_t)atoi(argv[5]));
		inet_pton(AF_INET6, argv[6], &lis.v6_addr);
		lis.v6_port = htons((uint16_t)atoi(argv[7]));
		if (ioctl(ctl, FLUXRS_SET_LISTENERS, &lis) != 0) {
			fprintf(stderr, "SET_LISTENERS errno=%d\n", errno);
			return 1;
		}
	}

	memset(&uids, 0, sizeof(uids));
	uids.count = 1;
	uids.uids[0] = (uint32_t)uid;
	if (ioctl(ctl, FLUXRS_SET_UIDS, &uids) != 0) {
		fprintf(stderr, "SET_UIDS errno=%d\n", errno);
		return 1;
	}
	print_status(ctl, "STATUS");

	rc = send_as_uid(argv[2], dport, uid);
	printf("SEND4 rc=%d\n", rc);
	if (rc < 0)
		return 1;
	print_status(ctl, "STATUS_SEND");

	if (argc >= 8) {
		rc = connect_tcp_as_uid(argv[2], dport, uid);
		printf("TCP4 rc=%d\n", rc);
		if (rc < 0)
			return 1;
		print_status(ctl, "STATUS_TCP4");
	}

	if (argc == 9) {
		rc = send_as_uid6(argv[8], dport, uid);
		printf("SEND6 rc=%d\n", rc);
		print_status(ctl, "STATUS_SEND6");
		rc = connect_tcp_as_uid6(argv[8], dport, uid);
		printf("TCP6 rc=%d\n", rc);
		if (rc < 0)
			return 1;
		print_status(ctl, "STATUS_TCP6");
	}

	rc = send_as_uid(argv[2], dport, 0);
	printf("SEND4_UID0 rc=%d\n", rc);
	print_status(ctl, "STATUS_END");
	close(ctl);
	return 0;
}
