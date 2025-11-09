#ifndef NETWORK_H
#define NETWORK_H

#include "daemon.h"
#include <sys/types.h>
#include <sys/socket.h>

#define UDP_MAX_SIZE 65507
#define TCP_BACKLOG SOMAXCONN

/* Network function prototypes */
int create_tcp_socket(const char *bind_addr, uint16_t port, int use_ipv6);
int create_udp_socket(const char *bind_addr, uint16_t port, int use_ipv6);
int set_nonblocking(int sockfd);
int run_event_loop(struct daemon_state *state);
int handle_tcp_connection(struct daemon_state *state);
int handle_udp_datagram(struct daemon_state *state);
int tune_socket_buffers(int sockfd, int load_factor);

/* Protocol-specific helpers */
int process_request(int fd, char *buffer, ssize_t buflen,
                   int protocol, struct sockaddr *cliaddr,
                   socklen_t addrlen, struct daemon_state *state);

#endif /* NETWORK_H */