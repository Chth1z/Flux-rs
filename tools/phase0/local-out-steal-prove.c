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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_setsockopt
#define __NR_setsockopt 208
#endif

/*
 * UAPI copy of kmod/fluxrs.h ioctl structs. Keep packing identical.
 */
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
	uint32_t uids[1024];
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

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif
#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR IP_RECVORIGDSTADDR
#endif
#ifndef IPV6_RECVORIGDSTADDR
#define IPV6_RECVORIGDSTADDR 74
#endif
#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75
#endif
#ifndef IPV6_ORIGDSTADDR
#define IPV6_ORIGDSTADDR IPV6_RECVORIGDSTADDR
#endif

static const char payload[] = "fluxrs-b3";

static int raw_setint(int fd, int level, int opt, int val)
{
	return (int)syscall(__NR_setsockopt, fd, level, opt, &val,
			    (socklen_t)sizeof(val));
}

static void die_alarm(int sig)
{
	(void)sig;
	write(STDERR_FILENO, "ALRM\n", 5);
	_exit(3);
}

static int bind_tproxy_v4(const char *addr, uint16_t port)
{
	struct sockaddr_in a;
	int fd, one = 1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket4 errno=%d\n", errno);
		return -1;
	}
	if (raw_setint(fd, IPPROTO_IP, IP_TRANSPARENT, one)) {
		fprintf(stderr, "IP_TRANSPARENT errno=%d\n", errno);
		close(fd);
		return -1;
	}
	if (raw_setint(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, one)) {
		fprintf(stderr, "IP_RECVORIGDSTADDR errno=%d\n", errno);
		close(fd);
		return -1;
	}
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons(port);
	if (inet_pton(AF_INET, addr, &a.sin_addr) != 1) {
		fprintf(stderr, "pton4\n");
		close(fd);
		return -1;
	}
	if (bind(fd, (struct sockaddr *)&a, sizeof(a))) {
		fprintf(stderr, "bind4 errno=%d\n", errno);
		close(fd);
		return -1;
	}
	return fd;
}

static int bind_tproxy_v6(const char *addr, uint16_t port)
{
	struct sockaddr_in6 a;
	int fd, one = 1;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket6 errno=%d\n", errno);
		return -1;
	}
	if (raw_setint(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, one)) {
		fprintf(stderr, "IPV6_TRANSPARENT errno=%d\n", errno);
		close(fd);
		return -1;
	}
	if (raw_setint(fd, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, one)) {
		fprintf(stderr, "IPV6_RECVORIGDSTADDR errno=%d\n", errno);
		close(fd);
		return -1;
	}
	if (raw_setint(fd, IPPROTO_IPV6, IPV6_V6ONLY, one)) {
		fprintf(stderr, "IPV6_V6ONLY errno=%d\n", errno);
		close(fd);
		return -1;
	}
	memset(&a, 0, sizeof(a));
	a.sin6_family = AF_INET6;
	a.sin6_port = htons(port);
	if (inet_pton(AF_INET6, addr, &a.sin6_addr) != 1 ||
	    bind(fd, (struct sockaddr *)&a, sizeof(a))) {
		close(fd);
		return -1;
	}
	return fd;
}

static int send_as_uid(int family, const char *ip, uint16_t port, uid_t uid)
{
	pid_t pid = fork();
	int st, fd, rc;

	if (pid < 0)
		return -errno;
	if (pid == 0) {
		if (setuid(uid) != 0)
			_exit(4);
		fd = socket(family, SOCK_DGRAM, 0);
		if (fd < 0)
			_exit(5);
		if (family == AF_INET) {
			struct sockaddr_in a;

			memset(&a, 0, sizeof(a));
			a.sin_family = AF_INET;
			a.sin_port = htons(port);
			if (inet_pton(AF_INET, ip, &a.sin_addr) != 1)
				_exit(6);
			rc = sendto(fd, payload, sizeof(payload) - 1, 0,
				    (struct sockaddr *)&a, sizeof(a));
		} else {
			struct sockaddr_in6 a;

			memset(&a, 0, sizeof(a));
			a.sin6_family = AF_INET6;
			a.sin6_port = htons(port);
			if (inet_pton(AF_INET6, ip, &a.sin6_addr) != 1)
				_exit(6);
			rc = sendto(fd, payload, sizeof(payload) - 1, 0,
				    (struct sockaddr *)&a, sizeof(a));
		}
		if (rc < 0)
			_exit(7);
		_exit(0);
	}
	if (waitpid(pid, &st, 0) < 0)
		return -errno;
	if (!WIFEXITED(st))
		return -EIO;
	if (WEXITSTATUS(st) == 0)
		return (int)(sizeof(payload) - 1);
	if (WEXITSTATUS(st) == 7)
		return -ECOMM;
	return -EPERM;
}

static int recv_origdst(int fd, int family, char *ip, size_t iplen,
			uint16_t *port)
{
	char buf[64], ctrl[128];
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	struct msghdr msg;
	struct cmsghdr *cmsg;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctrl;
	msg.msg_controllen = sizeof(ctrl);
	n = recvmsg(fd, &msg, 0);
	if (n < 0)
		return -errno;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (family == AF_INET && cmsg->cmsg_level == SOL_IP &&
		    cmsg->cmsg_type == IP_ORIGDSTADDR) {
			struct sockaddr_in *o =
				(struct sockaddr_in *)CMSG_DATA(cmsg);

			inet_ntop(AF_INET, &o->sin_addr, ip, (socklen_t)iplen);
			*port = ntohs(o->sin_port);
			return (int)n;
		}
		if (family == AF_INET6 && cmsg->cmsg_level == SOL_IPV6 &&
		    cmsg->cmsg_type == IPV6_ORIGDSTADDR) {
			struct sockaddr_in6 *o =
				(struct sockaddr_in6 *)CMSG_DATA(cmsg);

			inet_ntop(AF_INET6, &o->sin6_addr, ip,
				  (socklen_t)iplen);
			*port = ntohs(o->sin6_port);
			return (int)n;
		}
	}
	return -ENOMSG;
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
	char orig[64];
	uint16_t oport, port, destport;
	uid_t uid;
	int ctl, l4, l6, rc;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };

	if (argc != 8) {
		fprintf(stderr,
			"usage: %s <uid> <v4_listen> <v6_listen> "
			"<v4_dest> <v6_dest> <listen_port> <dest_port>\n",
			argv[0]);
		return 2;
	}
	uid = (uid_t)atoi(argv[1]);
	port = (uint16_t)atoi(argv[6]);
	destport = (uint16_t)atoi(argv[7]);
	if (uid == 0 || port == 0 || destport == 0) {
		fprintf(stderr, "uid/ports must be non-zero\n");
		return 2;
	}

	signal(SIGALRM, die_alarm);
	alarm(15);

	l4 = bind_tproxy_v4(argv[2], port);
	if (l4 < 0) {
		fprintf(stderr, "bind_v4 errno=%d\n", errno);
		return 1;
	}
	l6 = bind_tproxy_v6(argv[3], port);
	if (l6 < 0) {
		fprintf(stderr, "bind_v6 errno=%d\n", errno);
		close(l4);
		return 1;
	}
	setsockopt(l4, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(l6, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	ctl = open("/dev/fluxrs", O_RDONLY);
	if (ctl < 0) {
		fprintf(stderr, "open /dev/fluxrs errno=%d\n", errno);
		return 1;
	}

	memset(&lis, 0, sizeof(lis));
	inet_pton(AF_INET, argv[2], &lis.v4_addr);
	lis.v4_port = htons(port);
	inet_pton(AF_INET6, argv[3], &lis.v6_addr);
	lis.v6_port = htons(port);
	if (ioctl(ctl, FLUXRS_SET_LISTENERS, &lis) != 0) {
		fprintf(stderr, "SET_LISTENERS errno=%d\n", errno);
		return 1;
	}
	memset(&uids, 0, sizeof(uids));
	uids.count = 1;
	uids.uids[0] = (uint32_t)uid;
	if (ioctl(ctl, FLUXRS_SET_UIDS, &uids) != 0) {
		fprintf(stderr, "SET_UIDS errno=%d\n", errno);
		return 1;
	}
	print_status(ctl, "STATUS");

	rc = send_as_uid(AF_INET, argv[4], destport, uid);
	printf("SEND4 rc=%d\n", rc);
	if (rc < 0)
		return 1;
	memset(orig, 0, sizeof(orig));
	rc = recv_origdst(l4, AF_INET, orig, sizeof(orig), &oport);
	if (rc < 0) {
		printf("RECV4 fail errno=%d\n", -rc);
		print_status(ctl, "STATUS2");
		return 1;
	}
	printf("ORIGDST4 %s:%u bytes=%d\n", orig, oport, rc);

	rc = send_as_uid(AF_INET6, argv[5], destport, uid);
	printf("SEND6 rc=%d\n", rc);
	if (rc < 0)
		return 1;
	memset(orig, 0, sizeof(orig));
	rc = recv_origdst(l6, AF_INET6, orig, sizeof(orig), &oport);
	if (rc < 0) {
		printf("RECV6 fail errno=%d\n", -rc);
		print_status(ctl, "STATUS2");
		return 1;
	}
	printf("ORIGDST6 %s:%u bytes=%d\n", orig, oport, rc);
	print_status(ctl, "STATUS_END");

	rc = send_as_uid(AF_INET, argv[4], destport, 0);
	printf("SEND4_UID0 rc=%d\n", rc);
	rc = recv_origdst(l4, AF_INET, orig, sizeof(orig), &oport);
	printf("RECV4_UID0 %s\n", rc < 0 ? "none" : "UNEXPECTED");

	close(ctl);
	close(l4);
	close(l6);
	return 0;
}
