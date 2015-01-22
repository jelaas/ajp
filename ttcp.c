#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include "ttcp.h"

static void ntimediff(struct timespec *diff,
		      struct timespec *start,
		      struct timespec *stop)
{
	diff->tv_sec = stop->tv_sec - start->tv_sec;
	diff->tv_nsec = stop->tv_nsec - start->tv_nsec;
	if(diff->tv_nsec < 0)
	{
		diff->tv_sec--;
		start->tv_nsec -= stop->tv_nsec;
		diff->tv_nsec = 1000000000-start->tv_nsec;
	}
}


int tconnect(int sockfd, const struct sockaddr *addr,
	     socklen_t addrlen, long timeout_ms)
{
	struct pollfd ufd;
	struct timespec timeout, timeleft, timenow;
	int rc;
	int flags;
	uint64_t ms;
	
	if(timeout_ms)
	{
		flags = fcntl(sockfd, F_GETFL);
		fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	}
	
	ufd.fd = sockfd;
	ufd.events = POLLOUT;
	
	/* when do we timeout? */
	if(clock_gettime(CLOCK_MONOTONIC, &timeout)) {
		rc = -1;
		goto out;
	}
	timeout.tv_nsec += (timeout_ms * (uint64_t) 1000000);
	while(timeout.tv_nsec >= (uint64_t) 1000000000)
	{
		timeout.tv_sec++;
		timeout.tv_nsec -= (uint64_t) 1000000000;
	}
	
try_connect:
	if(clock_gettime(CLOCK_MONOTONIC, &timenow)) {
		rc = -1;
		goto out;
	}
	ntimediff(&timeleft, &timenow, &timeout);
	ms = (timeleft.tv_sec*1000) + (timeleft.tv_nsec/1000000) ;
	rc = connect(sockfd, addr, addrlen);
	
	if( (rc < 0) && (errno != EISCONN) )
	{
		if(ms <= 0) return -1;
		if( (errno == EALREADY) || (errno == EINPROGRESS) || (errno == EINTR))
		{
			if(errno != EINTR)
			{
				if(clock_gettime(CLOCK_MONOTONIC, &timenow)) {
					rc = -1;
					goto out;
				}
				ntimediff(&timeleft, &timenow, &timeout);
				ms = (timeleft.tv_sec*1000) + (timeleft.tv_nsec/1000000) ;
				rc = poll(&ufd, 1, ms);
				if( ((rc == -1) && (errno != EINTR)) ||
				    ((rc > 0) && (ufd.revents & POLLERR)) )
				{
					rc = -1;
					goto out;
				}
			}
			
			/* calculate time left */
			goto try_connect;
		}
		
		/* catch all other errors like ETIMEDOUT etc */
		rc = -1;
		goto out;
	}
	
out:
	/* turn off NONBLOCKING mode */
	if(timeout_ms >= 0)
	{
		flags = fcntl(sockfd, F_GETFL);
		fcntl(sockfd, F_SETFL, flags & (~ O_NONBLOCK));
	}
	return rc;
}

ssize_t tread(int fd, void *buf, size_t count, long timeout_ms)
{
	ssize_t rc;
	int flags;
	struct pollfd ufd;
	struct timespec timeout, timeleft, timenow;
	uint64_t ms;
	
	if(timeout_ms) {
		flags = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	}

	ufd.fd = fd;
	ufd.events = POLLIN;
	
	/* when do we timeout? */
	if(clock_gettime(CLOCK_MONOTONIC, &timeout)) {
		rc = -1;
		goto out;
	}
	timeout.tv_nsec += (timeout_ms * (uint64_t) 1000000);
	while(timeout.tv_nsec >= (uint64_t) 1000000000) {
		timeout.tv_sec++;
		timeout.tv_nsec -= (uint64_t) 1000000000;
	}

try_read:
	if(clock_gettime(CLOCK_MONOTONIC, &timenow)) {
		rc = -1;
		goto out;
	}
	ntimediff(&timeleft, &timenow, &timeout);
	ms = (timeleft.tv_sec*1000) + (timeleft.tv_nsec/1000000) ;
	rc = read(fd, buf, count);

	if(rc < 0) {
		if(ms <= 0) return -1;
		if( (errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
			if(errno != EINTR) {
				if(clock_gettime(CLOCK_MONOTONIC, &timenow)) {
					rc = -1;
					goto out;
				}
				ntimediff(&timeleft, &timenow, &timeout);
				ms = (timeleft.tv_sec*1000) + (timeleft.tv_nsec/1000000) ;
				rc = poll(&ufd, 1, ms);
				if( ((rc == -1) && (errno != EINTR)) ||
				    ((rc > 0) && (ufd.revents & POLLERR)) )
				{
					rc = -1;
					goto out;
				}
			}
			
			/* calculate time left */
			goto try_read;
		}
		
		/* catch all other errors */
		rc = -1;
		goto out;
	}
	
out:
	if(timeout_ms >= 0) {
		flags = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, flags & (~ O_NONBLOCK));
	}

	return rc;
}
