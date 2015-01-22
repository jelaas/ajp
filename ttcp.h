#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

int tconnect(int sockfd, const struct sockaddr *addr,
	     socklen_t addrlen, long timeout_ms);
ssize_t tread(int fd, void *buf, size_t count, long timeout_ms);
