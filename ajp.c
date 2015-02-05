/*
 * File: ajp.c
 * Implements: ajp client
 *
 * Copyright: Jens Låås, Uppsala University, 2014
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <ctype.h>

#include "jelopt.h"
#include "jelist.h"
#include "skbuff.h"
#include "ttcp.h"

struct {
	int verbose;
	int timeout_ms;
} conf;

struct hdr {
	char *name, *value;
};

struct ajp {
	int type;
	int code;
	char *msg;
	int num_headers;
	struct jlhead *headers; /* list of struct hdr */
	int reuse;
};

struct reqinfo {
	char *URI;
	char *server_name;
	char *remote_addr, *remote_host;
	char *protocol;
	int server_port;
	int is_ssl;
	struct jlhead *attributes; /* list of struct hdr */
	struct jlhead *headers; /* list of struct hdr */
};

void hdr_destroy(void *item)
{
	struct hdr *hdr = item;
	if(hdr->name) free(hdr->name);
	if(hdr->value) free(hdr->value);
	free(hdr);
}
int ajp_destroy(struct ajp *ajp)
{
	if(ajp->msg) free(ajp->msg);
	jl_freefn(ajp->headers, hdr_destroy);
	ajp->msg = 0;
	ajp->headers = (void*)0;
	return 0;
}


/*
http://tomcat.apache.org/tomcat-3.3-doc/AJPv13.html

The web server can send the following messages to the servlet container:

Code Type of Packet Meaning
2 Forward Request Begin the request-processing cycle with the following data
7 Shutdown The web server asks the container to shut itself down.
8 Ping The web server asks the container to quickly respond with a Pong

The servlet container can send the following types of messages to the web server:

Code Type of Packet Meaning
3 Send Body Chunk Send a chunk of the body from the servlet container to the web server (and presumably, onto the browser).
4 Send Headers Send the response headers from the servlet container to the web server (and presumably, onto the browser).
5 End Response Marks the end of the response (and thus the request-handling cycle).
6 Get Body Chunk Get further data from the request if it hasn't all been transferred yet.
9 Pong Reply to a Ping request.

*/

/* server to container */
#define AJP13_FORWARD_REQUEST 2
#define AJP13_SHUTDOWN 7
#define AJP13_PING 10

/* container to server */
#define AJP13_SEND_BODY_CHUNK 3
#define AJP13_SEND_HEADERS 4
#define AJP13_END_RESPONSE 5
#define AJP13_GET_BODY_CHUNK 6
#define AJP13_PONG 9

/*
AJP13_FORWARD_REQUEST :=
    prefix_code      2
	method           (byte)
	protocol         (string)
	req_uri          (string)
	remote_addr      (string)
	remote_host      (string)
	server_name      (string)
	server_port      (integer)
	is_ssl           (boolean)
	num_headers      (integer)
	request_headers *(req_header_name req_header_value)

	?context       (byte string)
	?servlet_path  (byte string)
	?remote_user   (byte string)
	?auth_type     (byte string)
	?query_string  (byte string)
	?jvm_route     (byte string)
	?ssl_cert      (byte string)
	?ssl_cipher    (byte string)
	?ssl_session   (byte string)

	?attributes   *(attribute_name attribute_value)
	request_terminator (byte)

	req_header_name := 
	sc_req_header_name | (string)  [see below for how this is parsed]

	sc_req_header_name := 0xA0 (byte)

	req_header_value := (string)

	attribute_name := (string)

	attribute_value := (string)

	request_terminator := 0xFF
*/


#define OPTIONS      1
#define GET          2
#define HEAD         3
#define POST         4
#define PUT          5
#define DELETE       6
#define TRACE        7
#define PROPFIND     8
#define PROPPATCH    9
#define MKCOL       10
#define COPY        11
#define MOVE        12
#define LOCK        13
#define UNLOCK      14
#define ACL         15
#define REPORT      16
#define VERSION_CONTROL 17
#define CHECKIN     18
#define CHECKOUT    19
#define UNCHECKOUT  20
#define SEARCH      21
#define MKWORKSPACE 22
#define UPDATE 23
#define LABEL 24
#define MERGE 25
#define BASELINE_CONTROL 26
#define MKACTIVITY 27

char *http_method[28] = { "", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "ACL", "REPORT", "VERSION-CONTROL", "CHECKIN", "CHECKOUT", "UNCHECKOUT", "SEARCH", "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE_CONTROL", "MKACTIVITY" };

char *http_header_req[15] = { "", "accept", "accept-charset", "accept-encoding", "accept-language",
			  "authorization", "connection", "content-type", "content-length", "cookie",
			  "cookie2", "host", "pragma", "referer", "user-agent" };

char *http_header_resp[12] = { "", "Content-Type", "Content-Language", "Content-Length", "Date",
			       "Last-Modified", "Location", "Set-Cookie", "Set-Cookie2", "Servlet-Engine",
			       "Status", "WWW-Authenticate" };

char *ajp13_attributes[] = { "", "context", "servlet_path", "remote_user", "auth_type", "query_string",
			     "jvm_route", "ssl_cert", "ssl_cipher", "ssl_session", "req_attribute" };
#define AJP13_ATTRIBUTE_TERMINATOR 0xFF

/*
 ajp ping [ajp://]host[:port]


 */

int ajp_skb_putstr(struct sk_buff *skb, const char *s)
{
	int len = strlen(s);
	*(skb_put(skb, 1)) = len>>8;
	*(skb_put(skb, 1)) = len & 0xff;
	strcpy((char*)skb_put(skb, len+1), s);
	return 0;
}

int ajp_skb_putint(struct sk_buff *skb, int i)
{
	*(skb_put(skb, 1)) = i>>8;
	*(skb_put(skb, 1)) = i & 0xff;
	return 0;
}

int ajp_skb_pushint(struct sk_buff *skb, int i)
{
	*(skb_push(skb, 1)) = i & 0xff;
	*(skb_push(skb, 1)) = i>>8;
	return 0;
}

int ajp_skb_pullint(struct sk_buff *skb)
{
	int i;
	i = (*(char*)skb->data) << 8;
	i += *((unsigned char*)skb->data+1);
	skb_pull(skb, 2);
	return i;
}

int ajp_skb_pullstring(struct sk_buff *skb, char **msg)
{
	int len;
	len = ajp_skb_pullint(skb);
	if(skb_tailroom(skb) < len) {
		if(conf.verbose) fprintf(stderr, "ajp: malformed message: string overflow\n");
		return -1;
	}
	*msg = malloc(len+1);
	if(!*msg) return -1;
	strncpy(*msg, (char*)skb->data, len);
	*((*msg)+len) = 0;
	skb_pull(skb, len+1);
	return len;
}

int ajp_ping(int fd)
{
	uint8_t data[5];
	data[0] = 0x12;
	data[1] = 0x34;
	data[2] = 0;
	data[3] = 1;
	data[4] = AJP13_PING;
	write(fd, data, 5);
	return 0;
}

int ajp_get(int fd, const struct reqinfo *req)
{
	struct sk_buff *skb;
	struct hdr *attr, *hdr;

	skb = alloc_skb(8192);

	skb_reserve(skb, 4);
	
	*(skb_put(skb, 1)) = AJP13_FORWARD_REQUEST;
	*(skb_put(skb, 1)) = GET;
	ajp_skb_putstr(skb, req->protocol);
	ajp_skb_putstr(skb, req->URI);
	ajp_skb_putstr(skb, req->remote_addr); /* client IP */
	ajp_skb_putstr(skb, req->remote_host); /* client HOSTNAME */
	ajp_skb_putstr(skb, req->server_name);
	ajp_skb_putint(skb, req->server_port);
	*(skb_put(skb, 1)) = req->is_ssl; /* is_ssl */
	
	/* headers */
	if(conf.verbose > 1) fprintf(stderr, "sending %d headers\n", req->headers->len);
	ajp_skb_putint(skb, req->headers->len); /* num_headers */
	jl_foreach(req->headers, hdr) {
		int i, nr;
		if(conf.verbose > 1) fprintf(stderr, "req header: %s: %s ", hdr->name, hdr->value);
		nr=0;
		for(i=1;i<=14;i++) {
			if(strcasecmp(http_header_req[i], hdr->name)==0) {
				nr = i;
			}
		}
		if(nr) {
			if(conf.verbose > 1) fprintf(stderr, "compressed\n");
			ajp_skb_putint(skb, 0xA000+nr);
			ajp_skb_putstr(skb, hdr->value);
		} else {
			if(conf.verbose > 1) fprintf(stderr, "\n");
			ajp_skb_putstr(skb, hdr->name);
			ajp_skb_putstr(skb, hdr->value);
		}
	}
	
	/* attributes */
	jl_foreach(req->attributes, attr) {
		int i, nr;
		if(conf.verbose > 1) fprintf(stderr, "req attribute: %s=%s ", attr->name, attr->value);
		nr=0;
		for(i=1;i<=10;i++) {
			if(strcasecmp(ajp13_attributes[i], attr->name)) {
				nr = i;
				break;
			}
		}
		if(nr) {
			if(conf.verbose > 1) fprintf(stderr, "compressed\n");
			ajp_skb_putint(skb, nr);
			ajp_skb_putstr(skb, attr->value);
		} else {
			if(conf.verbose > 1) fprintf(stderr, "\n");
			ajp_skb_putint(skb, 0x0A);
			ajp_skb_putstr(skb, attr->name);
			ajp_skb_putstr(skb, attr->value);
		}
	}
	*(skb_put(skb, 1)) = AJP13_ATTRIBUTE_TERMINATOR;
	
	ajp_skb_pushint(skb, skb->len); /* data size */
	ajp_skb_pushint(skb, 0x1234); /* magic */
	
	write(fd, skb->data, skb->len);
	return 0;
}

int timeelapsed(struct timeval *elapsed, const struct timeval *start)
{
	struct timeval end;
	gettimeofday(&end, NULL);
	if(end.tv_usec < start->tv_usec) {
                end.tv_usec += 1000000;
                end.tv_sec--;
        }
	elapsed->tv_sec = end.tv_sec-start->tv_sec;
        elapsed->tv_usec = end.tv_usec-start->tv_usec;
	return 0;
}

int ajp_body_recv(struct ajp *ajp, int fd, size_t len)
{
	uint8_t data[5];
	char buf[256];
	ssize_t got;
	size_t datalen;

	got = tread(fd, data, 2, conf.timeout_ms);
	if(conf.verbose > 1) fprintf(stderr, "got %d\n", got);
	if(got != 2) return -1;
	datalen = data[0] << 8;
        datalen += data[1];
	len -= 2;
	
	if(datalen > len) return -1;
	if(conf.verbose > 1) fprintf(stderr, "datalen %d\n", datalen);
	while(datalen) {
		got = tread(fd, buf, (datalen <= sizeof(buf))?datalen:sizeof(buf), conf.timeout_ms);
		if(conf.verbose > 1) fprintf(stderr, "got %d\n", got);
		if(got > 0) {
			buf[got] = 0;
			printf("%s", buf);
			len -= got;
			datalen -= got;
		}
		if(got <= 0) return -1;
	}
	while(len) {
		got = tread(fd, buf, (len <= sizeof(buf))?len:sizeof(buf), conf.timeout_ms);
		if(conf.verbose > 1) fprintf(stderr, "got rest %d\n", got);
		if(got > 0) {
			len -= got;
		}
		if(got <= 0) return -1;
	}
	return 0;
}

int ajp_headers_recv(struct ajp *ajp, int fd, size_t len)
{
	struct sk_buff *skb;
	int i;
	ssize_t got;
	struct hdr *hdr;
	
        skb = alloc_skb(8192);
	
	/* read data */
	while(len) {
		if(skb_tailroom(skb) < len) return -1;
		got = tread(fd, skb->tail, len, conf.timeout_ms);
		if(conf.verbose > 1) fprintf(stderr, "got %d %u %u\n", got, skb->data[0], skb->data[1]);
		if(got > 0) {
			skb_put(skb, len);
			len -= got;
		}
		if(got <= 0) return -1;
	}
	
	/* status code */
	ajp->code = ajp_skb_pullint(skb);
	if(conf.verbose) fprintf(stderr, "ajp: status code = %d\n", ajp->code);
	
	if(ajp_skb_pullstring(skb, &ajp->msg) == -1)
		return -1;
	if(conf.verbose) fprintf(stderr, "ajp: status message = '%s'\n", ajp->msg);
	
	ajp->num_headers = ajp_skb_pullint(skb);
	ajp->headers = jl_new();
	for(i=0;i<ajp->num_headers;i++) {
		if(skb_tailroom(skb) < 4) {
			if(conf.verbose) fprintf(stderr, "ajp: malformed message: header overflow\n");
			return -1;
		}
		hdr = malloc(sizeof(struct hdr));
		if(*skb->data == 0xA0) {
			if(conf.verbose > 1) fprintf(stderr, "compressed header\n");
			skb_pull(skb, 1);
			if(conf.verbose) fprintf(stderr, "ajp: %s: ", http_header_resp[*skb->data]);
			hdr->name = strdup(http_header_resp[*skb->data]);
			skb_pull(skb, 1);
		} else {
			if(ajp_skb_pullstring(skb, &hdr->name)==-1)
				return -1;
			if(conf.verbose) fprintf(stderr, "ajp: %s: ", hdr->name);
		}
		if(ajp_skb_pullstring(skb, &hdr->value)==-1) {
			if(conf.verbose) fprintf(stderr, "ajp: malformed message: header value overflow\n");
			return -1;
		}
		if(conf.verbose) fprintf(stderr, "%s\n", hdr->value);
		jl_append(ajp->headers, hdr);
	}
	
	return 0;
}

int ajp_recv(struct ajp *ajp, int fd, struct timeval *t)
{
	uint8_t data[5];
	ssize_t got;
	size_t len;
	int type;
	struct timeval start;
	
	gettimeofday(&start, NULL);
	got = tread(fd, data, 5, conf.timeout_ms);
	timeelapsed(t, &start);
	if(got != 5) {
		printf("wrong count %d\n", got);
		return -1;
	}

	if( !((data[0] == 'A') &&
	      (data[1] == 'B')) ) {
		if(conf.verbose) fprintf(stderr, "ajp: response: wrong magic: '%c' '%c'\n", data[0], data[1] );
		return -1;
	}
	
	len = data[2] << 8;
	len += data[3];
	len--;
	if(conf.verbose > 1) fprintf(stderr, "len = %d\n", len);
	if(len > 8192) return -1;
	
	type = data[4];
	ajp->type = type;
	
	switch(type) {
	case AJP13_SEND_HEADERS:
		if(conf.verbose > 1) fprintf(stderr, "send headers\n");
		if(ajp_headers_recv(ajp, fd, len))
			return -1;
		break;
	case AJP13_SEND_BODY_CHUNK:
		if(conf.verbose > 1) fprintf(stderr, "send body chunk\n");
		if(ajp_body_recv(ajp, fd, len))
			return -1;
		break;
	case AJP13_END_RESPONSE:
		if(conf.verbose > 1) fprintf(stderr, "end response\n");
		got = tread(fd, data, 1, conf.timeout_ms);
		if(got < 0) return -1;
		ajp->reuse = (data[0] == 1);
		return 0;
		break;
	case AJP13_GET_BODY_CHUNK:
		if(conf.verbose > 1) fprintf(stderr, "get body chunk\n");
		return 0;
		break;
	default:
		if(conf.verbose > 1) fprintf(stderr, "default\n");
		return 0;
		break;
	}

	return 0;
}

int ajp_pong_recv(int fd, struct timeval *t)
{
	uint8_t data[5];
	ssize_t got;
	struct timeval start;
	
	gettimeofday(&start, NULL);
	got = tread(fd, data, 5, conf.timeout_ms);
	timeelapsed(t, &start);
	
	if(got == 5) {
		if( (data[0] == 'A') &&
		    (data[1] == 'B') &&
		    (data[2] == 0) &&
		    (data[3] == 1) &&
		    (data[4] == AJP13_PONG))
			return 0;

	}
	return 1;
}

struct addrinfo_linear {
	struct addrinfo ai;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} addr;
};

int lookup(struct addrinfo_linear *res, const char *name)
{
	struct addrinfo *adr = NULL, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; /* AF_INET6 */
	hints.ai_protocol = IPPROTO_TCP;

	if(getaddrinfo(name, NULL, &hints, &adr))
		return -1;
	if(!adr) return -1;
	
	memcpy(&res->addr, adr->ai_addr, sizeof(res->addr));
	memcpy(&res->ai, adr, sizeof(struct addrinfo));
	res->ai.ai_addr = (struct sockaddr*)&res->addr;
	res->ai.ai_next = NULL;
	
	freeaddrinfo(adr);
	return 0;
}

int req_hdr_set(struct reqinfo *req, const char *name, const char *value)
{
	struct hdr *hdr;

	jl_foreach(req->headers, hdr) {
		if(strcasecmp(hdr->name, name)==0) {
			hdr->value = strdup(value);
			return 0;
		}
	}
	hdr = malloc(sizeof(struct hdr));
	hdr->name = strdup(name);
	hdr->value = strdup(value);
	jl_append(req->headers, hdr);
	
	return 0;
}

int main(int argc, char **argv)
{
	int fd, rc=0;
	int err=0;
	int count=0;
	int port = 8009;
	char *host = "localhost";
	char *cmd = (void*)0;
	char *attr, *hdrarg, *server;
	struct reqinfo req;
	struct timeval elapsed;
	struct addrinfo_linear addr_linear;
	struct addrinfo *addr = (struct addrinfo *)&addr_linear;
	struct {
		struct jlhead *attributes;
	} deflt;

	conf.timeout_ms = 1000;

	req.server_name = "localhost";
	req.server_port = 80;
	
	req.remote_addr = "127.0.0.100";
	req.remote_host = "";
	
	req.is_ssl = 0;
	req.protocol = "HTTP/1.1";
	
	req.URI = "/";
	req.attributes = jl_new();
	
	deflt.attributes = jl_new();
	{
		struct hdr *hdr;
		hdr = malloc(sizeof(struct hdr));
		hdr->name = "jvm_route";
		hdr->value = "routename";
		jl_append(deflt.attributes, hdr);
	}
	req.headers = jl_new();
	req_hdr_set(&req, "host", "localhost");
	
	if(jelopt(argv, 'h', "help", 0, &err)) {
	usage:
		fprintf(rc?stderr:stdout, "ajp [-vh] CMD [[ajp://](FQDN|IP)[:PORT]] [URI]\n"
			" -v --verbose          increase verboseness\n"
			" -p --port N           port number to use [8009]\n"
			" -s --server SERVER_NAME[:PORT]\n"
			" -r --remote_addr      client address [127.0.0.100]\n"
			"    --remote_host      remote host []\n"
			"    --protocol         protocol [HTTP/1.1]\n"
			" -c --count N          number of requests to send\n"
			" -T --timeout MS       timeout in milliseconds [1000]\n"
			" -H --header NAME=VALUE\n"
			" -a --attribute NAME=VALUE\n"
			"                       Predefined attributes are:\n"
			"                       context, servlet_path, remote_user,\n"
			"                       auth_type, query_string, jvm_route,\n"
			"                       ssl_cert, ssl_cipher, ssl_session\n"
			" -S --ssl              Set is_ssl flag\n"
			"\n"
			" CMD:\n"
			" PING\n"
			" GET\n"
			"\n"
			"Examples:\n"
			" ajp ping ajp://ajp.host:8009\n"
			" ajp get ajp://ajp.host:8009 http://URL\n"
			);
		exit(rc);
	}
	while(jelopt_int(argv, 'p', "port", &port, &err));
	while(jelopt_int(argv, 'c', "count", &count, &err));
	while(jelopt_int(argv, 'T', "timeout", &conf.timeout_ms, &err));
	while(jelopt(argv, 'r', "remote_addr", &req.remote_addr, &err));
	while(jelopt(argv, 0, "remote_host", &req.remote_host, &err));
	while(jelopt(argv, 0, "protocol", &req.protocol, &err));
	while(jelopt(argv, 'H', "header", &hdrarg, &err)) {
		char *p;
		p = strchr(hdrarg, '=');
		if(p) {
			*p++ = 0;
			req_hdr_set(&req, hdrarg, p);
		}
	}
	while(jelopt(argv, 'a', "attribute", &attr, &err)) {
		struct hdr *hdr;
		char *p;
		p = strchr(attr, '=');
		if(p) {
			*p++ = 0;
			hdr = malloc(sizeof(struct hdr));
			hdr->name = strdup(attr);
			hdr->value = strdup(p);
			jl_append(req.attributes, hdr);
		}
	};
	while(jelopt(argv, 's', "server", &server, &err)) {
		char *p;
		p = strchr(attr, ':');
		if(p) {
			req.server_name = server;
			*p++ = 0;
			req.server_port = atoi(p);
		} else {
			req.server_name = server;
		}
	}
	while(jelopt(argv, 'S', "ssl", 0, &err)) req.is_ssl = 1;
	while(jelopt(argv, 'v', "verbose", 0, &err)) conf.verbose++;

	argc = jelopt_final(argv, &err);
	if(err) {
		fprintf(stderr, "netspray: Syntax error in options.\n");
		exit(2);
	}

	if(req.attributes->len == 0) {
		req.attributes = deflt.attributes;
	}
	
	if(argc < 2) {
		rc=1;
		goto usage;
	}
	cmd = argv[1];
	{
		char *p;
		for(p=cmd;*p;p++)
			*p = toupper(*p);
	}
	
	if(argc > 2)
		host = strdup(argv[2]);
	{
		char *p;
		if(strncmp("ajp://", host, 6)==0) {
			host += 6;
		}
		if( (p=strchr(host, ':')) ) {
			port = atoi(p+1);
			*p = 0;
		}
	}

	if(argc > 3) {
		/* parse req.host and req.URI from argv[3] */
		req.URI = argv[3];
		if(strncmp("ajp://", req.URI, 6)==0) {
			req.URI += 7;
		} else {
			if(strncmp("http://", req.URI, 7)==0) {
				req.URI += 7;
			} else {
				if(strncmp("https://", req.URI, 8)==0) {
					req.URI += 8;
				}
			}
		}
		
		if(*req.URI != '/') {
			char *p;
			char *host;
			if( (p=strchr(req.URI, '/')) ) {
				host = req.URI;
				req.URI = strdup(p);
				*p = 0;
				req_hdr_set(&req, "host", host);
			} else {
				req.URI = "/";
				req_hdr_set(&req, "host", "/");
			}
		}
	}
	
	if(lookup(&addr_linear, host)) {
		fprintf(stderr, "lookup failed\n");
		exit(2);
	}

	fd = socket(addr->ai_family, SOCK_STREAM, 0);
	if(fd == -1) {
		fprintf(stderr, "socket failed\n");
		exit(2);
	}
	
	if(addr->ai_family == AF_INET)
		addr_linear.addr.v4.sin_port = htons(port);
	if(addr->ai_family == AF_INET6)
		addr_linear.addr.v6.sin6_port = htons(port);
	if(tconnect(fd, addr->ai_addr, addr->ai_addrlen, conf.timeout_ms)) {
		fprintf(stderr, "connect failed\n");
		exit(1);
	}

	if(!strcmp(cmd, "PING")) {
		while(1) {
			ajp_ping(fd);
			if(ajp_pong_recv(fd, &elapsed)) {
				fprintf(stderr, "ping failed\n");
				exit(1);
			}
			printf("time=%lu.%03lu ms\n",
			       elapsed.tv_sec*1000 + elapsed.tv_usec/1000, elapsed.tv_usec%1000);
			if(count == 1) break;
			if(count) count--;
			sleep(1);
		}
		exit(0);
	}

	if(!strcmp(cmd, "GET")) {
		while(1) {
			struct ajp ajp;
			memset(&ajp, 0, sizeof(ajp));
			ajp_get(fd, &req);
			while(1) {
				if(ajp_recv(&ajp, fd, &elapsed)) {
					fprintf(stderr, "get failed\n");
					exit(1);
				}
				if(ajp.type == AJP13_END_RESPONSE) break;
			}
			ajp_destroy(&ajp);
			fprintf(stderr, "time=%lu.%03lu ms\n",
				elapsed.tv_sec*1000 + elapsed.tv_usec/1000, elapsed.tv_usec%1000);
			if(count) count--;
			if(count == 0) break;
			sleep(1);
		}
		exit(0);
	}

	rc=1; goto usage;
	return 0;
}
