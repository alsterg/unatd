/* Copyright 2014 - (See AUTHORS.txt) . All rights reserved. */

/* TODO:
	* Daemon
	* Configurability
	* IPv6
	* UPD
	* Protocol modularity
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>       /*  socket definitions        */
#include <sys/types.h>        /*  socket types              */
#include <arpa/inet.h>        /*  inet (3) funtions         */
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ev.h>

#define LOG // printf
#define UNATD_PORT (2002)
#define LISTEN_BACKLOG (1024)
#define BUFFER (32768)

struct ev_loop *loop;

int       unatd_sock;
short int unatd_port = UNATD_PORT;
struct    sockaddr_in unatd_addr;
ev_io     unatd_watcher;

struct    sockaddr nat_addr;
int nat_enabled = 0;

enum conn_state { CONN_CLOSED, CONN_OPEN };

struct conn {
	struct flow *flow;
	int sock;
	struct sockaddr addr;
	socklen_t addr_len;
	ev_io read_watcher;
	ev_io write_watcher;
	char buffer[BUFFER];
	size_t pending; // pending bytes on buffer for writting
	size_t written; // bytes on buffer already written
	int to_close; // boolean: set to indicate that it should be closed when buffer is flushed
	enum conn_state state;
};

enum flow_state { UNINITIALIZED, FLOW_HALFOPEN, FLOW_WAITING, FLOW_OPEN };

struct flow {
	struct conn ingress;
	struct conn egress;
	enum flow_state state;
};

static const char *addr_to_string(struct sockaddr *sa) {
	static char s[INET6_ADDRSTRLEN];
	if (sa->sa_family == AF_INET)
		return inet_ntop(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr), s, sizeof(s));
	return inet_ntop(AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr), s, sizeof(s));
}

static uint16_t get_port(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET)
		return ntohs(((struct sockaddr_in*)sa)->sin_port);
	return ntohs(((struct sockaddr_in6*)sa)->sin6_port);
}

static void read_cb(EV_P_ struct ev_io *w, int revents);
static void write_cb(EV_P_ struct ev_io *w, int revents);
static void tprox_cb(EV_P_ struct ev_io *w, int revents);

// XXX IPv6 support & check for errors
static int get_ifaddr(struct sockaddr *addr, const char *iface) {
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to iface */
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	memcpy(addr, &ifr.ifr_addr, sizeof(struct sockaddr));

	return 0;
}

static void cleanup_flow(struct flow *f) {
	LOG("cleanup_flow\n");

	assert(f);
	if (f->ingress.state == CONN_OPEN) {
		ev_io_stop(loop, &f->ingress.read_watcher);
		ev_io_stop(loop, &f->ingress.write_watcher);
		if(f->ingress.sock) close(f->ingress.sock);
	}
	if (f->egress.state == CONN_OPEN) {
		ev_io_stop(loop, &f->egress.read_watcher);
		ev_io_stop(loop, &f->egress.write_watcher);
		if(f->egress.sock) close(f->egress.sock);
	}
	free(f);
}

static void write_cb(EV_P_ struct ev_io *w, int revents) {
	LOG("write_cb\n");

	struct conn *c = (struct conn *) w->data;
	struct flow *f = c->flow;

	if (revents & EV_ERROR) {
		fprintf(stderr, "EV_ERROR encountered\n");
		cleanup_flow(f);
		return;
	}

	switch(f->state) {
		case FLOW_OPEN:
		{
			/* Direction-agnostic treatment of sockets */
			struct conn *c_other;
			if (c == &f->ingress)
				c_other = &f->egress;  // CB has been called to write bytes to client socket
			else 
				c_other = &f->ingress; // CB has been called to write bytes to server socket

			assert(c_other->pending);

			ssize_t n = c_other->written = write(c->sock, &c_other->buffer+(c_other->written), c_other->pending);
			if (n == c_other->pending) {
				c_other->written = c_other->pending = 0;
				if (c->to_close) {
					cleanup_flow(f);
				} else {
					ev_io_stop(loop, &c->write_watcher);
					ev_io_start(loop, &c_other->read_watcher);
				}
			} else {
				// XXX EOF?
				switch(errno) {
					case EAGAIN:
						// leave write_cb enabled
						return;
						break;
					default:
						cleanup_flow(f);
						break;
				}
			}
		}
		break;
		case FLOW_WAITING:
		{
			// ZZZ check for connection error 
			ev_io_stop(loop, &f->egress.write_watcher);
			ev_io_start(loop, &f->ingress.read_watcher);

			f->egress.read_watcher.data = (void *) &f->egress;
			ev_io_init(&f->egress.read_watcher, read_cb, f->egress.sock, EV_READ);
			ev_io_start(loop, &f->egress.read_watcher);

			f->ingress.write_watcher.data = (void *) &f->ingress;
			ev_io_init(&f->ingress.write_watcher, write_cb, f->ingress.sock, EV_WRITE);

			f->egress.state = CONN_OPEN;
			f->state = FLOW_OPEN;
		}
		break;
		default:
			fprintf(stderr, "Invalid flow state\n");
			exit(EXIT_FAILURE);
			break;
	}
}

static void read_cb(EV_P_ struct ev_io *w, int revents) {
	LOG("read_cb\n");

	struct conn *c = (struct conn *) w->data;
	struct flow *f = c->flow;

	if (revents & EV_ERROR) {
		fprintf(stderr, "EV_ERROR encountered\n");
		cleanup_flow(f);
		return;
	}

	switch (f->state) {
		case FLOW_HALFOPEN:
			{
				if ((f->egress.sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0) {
					fprintf(stderr, "Error creating listening socket: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}

				/* Enable sending packets from non-local IP addresses */
				int value = 1;
				if (setsockopt(f->egress.sock, SOL_IP, IP_TRANSPARENT, &value, sizeof(value)) < 0) {
					fprintf(stderr, "Error calling setsockopt(): %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}

				if(setsockopt(f->egress.sock, SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value)) < 0) {
					fprintf(stderr, "Error calling setsockopt(): %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}

				if(setsockopt(f->egress.sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) != 0) {
					fprintf(stderr, "Error calling setsockopt(): %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}

				if (nat_enabled) {
					if (bind(f->egress.sock, &nat_addr, sizeof(struct sockaddr)) < 0) {
						fprintf(stderr, "Error calling bind(): %s\n", strerror(errno));
						exit(EXIT_FAILURE);
					}
				} else {
					if (bind(f->egress.sock, &f->ingress.addr, sizeof(struct sockaddr)) < 0) {
						fprintf(stderr, "Error calling bind(): %s\n", strerror(errno));
						exit(EXIT_FAILURE);
					}
				}

				int res = connect(f->egress.sock, &f->egress.addr, sizeof(struct sockaddr));
				if (res < 0 && errno == EINPROGRESS) {
					f->egress.write_watcher.data = (void *) &f->egress;
					ev_io_init(&f->egress.write_watcher, write_cb, f->egress.sock, EV_WRITE);
					ev_io_start(loop, &f->egress.write_watcher);
					f->state = FLOW_WAITING;

					ev_io_stop(loop, &f->ingress.read_watcher);
				} else if (res < 0) {
					printf("Error calling connect(): %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				} else { // Connection established at once
					f->egress.read_watcher.data = (void *) &f->egress;
					ev_io_init(&f->egress.read_watcher, read_cb, f->egress.sock, EV_READ);
					ev_io_start(loop, &f->egress.read_watcher);

					f->ingress.write_watcher.data = (void *) &f->ingress;
					ev_io_init(&f->ingress.write_watcher, write_cb, f->ingress.sock, EV_WRITE);
					f->egress.write_watcher.data = (void *) &f->egress;
					ev_io_init(&f->egress.write_watcher, write_cb, f->egress.sock, EV_WRITE);

					f->egress.state = CONN_OPEN;
					f->state = FLOW_OPEN;
				}
			}
			break;
		case FLOW_OPEN:
			{
				/* Direction-agnostic treatment of sockets */
				struct conn *c_other;
				if (c == &f->ingress)
					c_other = &f->egress;  // CB has been called to read bytes from client socket
				else 
					c_other = &f->ingress; // CB has been called to read bytes from server socket

				ssize_t n = c->pending = read(c->sock, &c->buffer, BUFFER);
				if (n > 0) {
					ev_io_stop(loop, &c->read_watcher);
					ev_io_start(loop, &c_other->write_watcher);
				} else if (n == 0) { // EOF
				   if(c_other->pending == 0) {
						cleanup_flow(f);
						break;
					} else {
						ev_io_stop(loop, &c->read_watcher);
						ev_io_stop(loop, &c->write_watcher);
						if(c->sock) close(c->sock);
						c->state = CONN_CLOSED;
						c_other->to_close = 1;
					}
				} else {
					switch(errno) {
						case EAGAIN:
							// leave read_cb enabled
							return;
							break;
						default:
							cleanup_flow(f);
							break;
					}
				}
			}
			break;
		case FLOW_WAITING:
			break; // nothing to do
		default:
			fprintf(stderr, "Invalid flow state\n");
			exit(EXIT_FAILURE);
			break;
	}
}

static void unatd_cb(EV_P_ struct ev_io *w, int revents) {
	LOG("unatd_cb\n");

	if (revents & EV_ERROR) {
		fprintf(stderr, "EV_ERROR encountered\n");
		exit(EXIT_FAILURE);
	}

	struct flow *f = calloc(1, sizeof(struct flow));
	f->ingress.flow = f->egress.flow = f;

	/* Accept and save client IP address */
	f->ingress.addr_len = sizeof(struct sockaddr);
	if ((f->ingress.sock = accept4(unatd_sock, &f->ingress.addr, &f->ingress.addr_len, SOCK_NONBLOCK) ) < 0) {
		fprintf(stderr, "Error calling accept(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Save server IP address */
	f->egress.addr_len = f->ingress.addr_len;
	if (getsockname(f->ingress.sock, &f->egress.addr, &f->egress.addr_len) < 0) {
		fprintf(stderr, "Error calling getsockname(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	LOG("Client connection %s:%u->%s:%u\n", 
		addr_to_string(&f->ingress.addr),
		get_port(&f->ingress.addr),
		addr_to_string(&f->egress.addr),
		get_port(&f->egress.addr));

	// Since we use the ingress addr to bind for the server-side connection, we 
	// should set the port to zero, so that the OS will pick.
	if (f->ingress.addr.sa_family == AF_INET)
		((struct sockaddr_in *) (&f->ingress.addr))->sin_port = 0; // Any port
	else	
		((struct sockaddr_in6 *) (&f->ingress.addr))->sin6_port = 0; // Any port

	f->ingress.flow = f;
	f->ingress.read_watcher.data = (void *) &f->ingress;
	ev_io_init(&f->ingress.read_watcher, read_cb, f->ingress.sock, EV_READ);
	ev_io_start(loop, &f->ingress.read_watcher);
	f->ingress.state = CONN_OPEN;

	/* Don't handle opening of server-side connection here,
	 * to avoid adding delay to unatd_cb. Instead mark
	 * the incomplete state, and handle it in read_cb */
	f->state = FLOW_HALFOPEN;
}

static int start_unatd(void) {
	LOG("Proxy started\n");

	/*  Create the listening socket  */
	if ((unatd_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Error creating listening socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	int value = 1;
	if (setsockopt(unatd_sock, SOL_IP, IP_TRANSPARENT, &value, sizeof(value)) < 0) {
		fprintf(stderr, "Error calling setsockopt(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(setsockopt(unatd_sock, SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value)) < 0) {
		fprintf(stderr, "Error calling setsockopt(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(setsockopt(unatd_sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) != 0) {
		fprintf(stderr, "Error calling setsockopt(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	memset(&unatd_addr, 0, sizeof(unatd_addr));
	unatd_addr.sin_family      = AF_INET;
	unatd_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	unatd_addr.sin_port        = htons(unatd_port);

	if (bind(unatd_sock, (struct sockaddr *) &unatd_addr, sizeof(unatd_addr)) < 0) {
		fprintf(stderr, "Error calling bind(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (listen(unatd_sock, LISTEN_BACKLOG) < 0) {
		fprintf(stderr, "Error calling listen(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	ev_io_init(&unatd_watcher, unatd_cb, unatd_sock, EV_READ);
	ev_io_start(loop, &unatd_watcher);
}

int main(int argc, char **argv)
{
	int index;
	int c;

	while ((c = getopt (argc, argv, "p:n:")) != -1)
		switch (c)
		{
			case 'p':
				unatd_port = atoi(optarg);
				printf("Binding to port %d\n", unatd_port);
				break;
			case 'n':
				nat_enabled = 1;
				get_ifaddr(&nat_addr, optarg);
				((struct sockaddr_in *) &nat_addr)->sin_port = 0; // Any port
				printf("Using for SNAT interface %s and IP %s\n", optarg, inet_ntoa(((struct sockaddr_in *)&nat_addr)->sin_addr));
				break;
			case '?':
				if (optopt == 'c')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							"Unknown option character `\\x%x'.\n",
							optopt);
				return 1;
			default:
				abort ();
		}

	if (optind < argc) {
		fprintf(stderr, "Superfluous arguments\n");
		return 1;
	}

	loop = ev_default_loop(0);

	start_unatd();

	ev_loop(loop, 0); // Enter event-loop

	return 0;
}
