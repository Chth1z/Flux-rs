#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_finit_module
#define __NR_finit_module 273
#endif
#ifndef __NR_delete_module
#define __NR_delete_module 106
#endif

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "load") == 0) {
		int fd = open(argv[2], O_RDONLY);
		long rc;
		int saved;

		if (fd < 0) {
			perror("open");
			return 1;
		}
		rc = syscall(__NR_finit_module, fd, "", 0);
		saved = errno;
		close(fd);
		if (rc != 0 && saved != EEXIST) {
			errno = saved;
			perror("finit_module");
			return 1;
		}
		return 0;
	}
	if (argc == 3 && strcmp(argv[1], "unload") == 0) {
		if (syscall(__NR_delete_module, argv[2], 0) != 0) {
			perror("delete_module");
			return 1;
		}
		return 0;
	}
	fprintf(stderr, "usage: %s load <ko> | unload <name>\n", argv[0]);
	return 2;
}
