#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include "ttcp.h"

static void ntimediff(struct timespec *diff, /* left */
		      const struct timespec *start, /* now */
		      const struct timespec *stop) /* timeout */
{
	diff->tv_sec = stop->tv_sec - start->tv_sec;
	diff->tv_nsec = stop->tv_nsec - start->tv_nsec;
	if(diff->tv_nsec < 0)
	{
		diff->tv_sec--;
		diff->tv_nsec += 1000000000;
	}
}


int tconnect(int sockfd, const struct sockaddr *addr,
	     socklen_t addrlen, long timeout_ms)
{
	struct pollfd ufd;
	struct timespec timeout, timeleft, timenow;
	int rc;
	int flags;
	int64_t ms, tmp;
	
	if(timeout_ms >= 0)
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
	tmp = timeout.tv_nsec;
	tmp += ((uint64_t) timeout_ms * (uint64_t) 1000000);
	while(tmp >= (uint64_t) 1000000000)
	{
		timeout.tv_sec++;
		tmp -= (uint64_t) 1000000000;
	}
	timeout.tv_nsec = tmp;
	
try_connect:
	if(clock_gettime(CLOCK_MONOTONIC, &timenow)) {
		rc = -1;
		goto out;
	}
	if((timenow.tv_sec > timeout.tv_sec) ||
	   ((timenow.tv_sec == timeout.tv_sec) && timenow.tv_nsec >= timeout.tv_nsec))
		ms = 0;
	else {
		ntimediff(&timeleft, &timenow, &timeout);
		ms = (timeleft.tv_sec*1000) + (timeleft.tv_nsec/1000000) ;
	}
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
				if((timenow.tv_sec > timeout.tv_sec) ||
				   ((timenow.tv_sec == timeout.tv_sec) && timenow.tv_nsec >= timeout.tv_nsec))
					ms = 0;
				else {
					ntimediff(&timeleft, &timenow, &timeout);
					ms = (timeleft.tv_sec*1000) + (timeleft.tv_nsec/1000000) ;
				}
				rc = poll(&ufd, 1, ms);
				if( ((rc == -1) && (errno != EINTR)) ||
				    ((rc > 0) && (ufd.revents & POLLERR)) )
				{
					rc = -1;
					goto out;
				}
			}
			
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

ssize_t tread(int fd, void *buf, size_t count, long timeout_ms, char **errstr)
{
	ssize_t rc;
	int flags;
	struct pollfd ufd;
	struct timespec timeout, timeleft, timenow;
	int64_t ms, tmp;
	
	if(timeout_ms >= 0) {
		flags = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	}

	ufd.fd = fd;
	ufd.events = POLLIN;
	
	/* when do we timeout? */
	if(clock_gettime(CLOCK_MONOTONIC, &timeout)) {
		if(errstr) *errstr = "clock_gettime failed";
		rc = -1;
		goto out;
	}
	tmp = timeout.tv_nsec;
	tmp += ((uint64_t) timeout_ms * (uint64_t) 1000000);
	while(tmp >= (uint64_t) 1000000000) {
		timeout.tv_sec++;
		tmp -= (uint64_t) 1000000000;
	}
	timeout.tv_nsec = tmp;

try_read:
	if(clock_gettime(CLOCK_MONOTONIC, &timenow)) {
		if(errstr) *errstr = "clock_gettime failed";
		rc = -1;
		goto out;
	}
	if((timenow.tv_sec > timeout.tv_sec) ||
	   ((timenow.tv_sec == timeout.tv_sec) && timenow.tv_nsec >= timeout.tv_nsec)) {
		ms = 0;
	} else {
		ntimediff(&timeleft, &timenow, &timeout);
		ms = (timeleft.tv_sec*1000) + (timeleft.tv_nsec/1000000);
	}
	rc = read(fd, buf, count);

	if(rc < 0) {
		if(ms <= 0) {
			static char buf[64];
			if(errstr) {
				sprintf(buf, "timed out [ms=%lld]", ms);
				*errstr = buf;
			}
			goto out;
		}
		if( (errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
			if(errno != EINTR) {
				if(clock_gettime(CLOCK_MONOTONIC, &timenow)) {
					if(errstr) *errstr = "clock_gettime failed";
					rc = -1;
					goto out;
				}
				if((timenow.tv_sec > timeout.tv_sec) ||
				   ((timenow.tv_sec == timeout.tv_sec) && timenow.tv_nsec >= timeout.tv_nsec)) {
					ms = 0;
				} else {
					ntimediff(&timeleft, &timenow, &timeout);
					ms = (timeleft.tv_sec*1000) + (timeleft.tv_nsec/1000000);
				}
				rc = poll(&ufd, 1, ms);
				if( ((rc == -1) && (errno != EINTR)) ||
				    ((rc > 0) && (ufd.revents & POLLERR)) )
				{
					if(errstr) *errstr = "POLLERR";
					rc = -1;
					goto out;
				}
			}
			
			/* calculate time left */
			goto try_read;
		}
		
		/* catch all other errors */
		if(errstr) *errstr = "other error";
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
