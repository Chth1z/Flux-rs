#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

/*
 * UDP sendto loop. Measures local stack + egress hooks, not radio RTT:
 * SOCK_DGRAM sendto returns after ip_local_out / qdisc, not after ACK.
 */

int main(int argc, char **argv)
{
	struct sockaddr_in dst;
	struct timespec t0, t1;
	char byte = 0;
	int fd, n, i, warmup, port;
	long ns;

	if (argc != 4) {
		fprintf(stderr, "usage: %s <ipv4> <port> <count>\n", argv[0]);
		return 2;
	}
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	port = atoi(argv[2]);
	n = atoi(argv[3]);
	if (port <= 0 || n <= 0) {
		fprintf(stderr, "port and count must be positive\n");
		return 2;
	}
	dst.sin_port = htons((unsigned short)port);
	if (inet_pton(AF_INET, argv[1], &dst.sin_addr) != 1) {
		fprintf(stderr, "bad ipv4\n");
		return 2;
	}
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket errno=%d\n", errno);
		return 1;
	}
	warmup = n > 2000 ? 1000 : 100;
	for (i = 0; i < warmup; i++)
		(void)sendto(fd, &byte, 1, 0, (struct sockaddr *)&dst,
			     sizeof(dst));
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < n; i++) {
		if (sendto(fd, &byte, 1, 0, (struct sockaddr *)&dst,
			   sizeof(dst)) < 0) {
			fprintf(stderr, "sendto errno=%d after %d\n", errno, i);
			close(fd);
			return 1;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	close(fd);
	ns = (t1.tv_sec - t0.tv_sec) * 1000000000L +
	     (t1.tv_nsec - t0.tv_nsec);
	printf("count=%d ns=%ld ns_per_pkt=%ld\n", n, ns, ns / n);
	return 0;
}
