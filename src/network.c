#include "network.h"
#include "daemon.h"
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/select.h>
#include <time.h>

/**
 * Create and bind TCP socket
 */
int create_tcp_socket(const char *bind_addr, uint16_t port, int use_ipv6) {
    int sockfd;
    int optval = 1;
    struct addrinfo hints, *res, *rp;
    char port_str[16];
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = use_ipv6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    if (getaddrinfo(bind_addr, port_str, &hints, &res) != 0) {
        syslog(LOG_ERR, "getaddrinfo failed: %s", strerror(errno));
        return -1;
    }
    
    /* Try each address until we successfully bind */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) {
            continue;
        }
        
        /* Set socket options */
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                      &optval, sizeof(optval)) < 0) {
            syslog(LOG_WARNING, "setsockopt SO_REUSEADDR failed: %s",
                   strerror(errno));
        }
        
        /* Enable IPv6/IPv4 dual stack if IPv6 */
        if (rp->ai_family == AF_INET6) {
            int no = 0;
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
                          &no, sizeof(no)) < 0) {
                syslog(LOG_WARNING, "Could not enable dual-stack: %s",
                       strerror(errno));
            }
        }
        
        if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; /* Success */
        }
        
        close(sockfd);
    }
    
    freeaddrinfo(res);
    
    if (rp == NULL) {
        syslog(LOG_ERR, "Could not bind TCP socket");
        return -1;
    }
    
    /* Listen for connections */
    if (listen(sockfd, SOMAXCONN) < 0) {
        syslog(LOG_ERR, "listen failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    syslog(LOG_INFO, "TCP socket listening on %s:%d", bind_addr, port);
    return sockfd;
}

/**
 * Create and bind UDP socket
 */
int create_udp_socket(const char *bind_addr, uint16_t port, int use_ipv6) {
    int sockfd;
    int optval = 1;
    struct addrinfo hints, *res, *rp;
    char port_str[16];
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = use_ipv6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    if (getaddrinfo(bind_addr, port_str, &hints, &res) != 0) {
        syslog(LOG_ERR, "getaddrinfo failed: %s", strerror(errno));
        return -1;
    }
    
    /* Try each address until we successfully bind */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) {
            continue;
        }
        
        /* Set socket options */
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                      &optval, sizeof(optval)) < 0) {
            syslog(LOG_WARNING, "setsockopt SO_REUSEADDR failed: %s",
                   strerror(errno));
        }
        
        /* Enable IPv6/IPv4 dual stack if IPv6 */
        if (rp->ai_family == AF_INET6) {
            int no = 0;
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
                          &no, sizeof(no)) < 0) {
                syslog(LOG_WARNING, "Could not enable dual-stack: %s",
                       strerror(errno));
            }
        }
        
        if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; /* Success */
        }
        
        close(sockfd);
    }
    
    freeaddrinfo(res);
    
    if (rp == NULL) {
        syslog(LOG_ERR, "Could not bind UDP socket");
        return -1;
    }
    
    syslog(LOG_INFO, "UDP socket bound on %s:%d", bind_addr, port);
    return sockfd;
}

/**
 * Set socket to non-blocking mode
 */
int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * Main event loop using select() for I/O multiplexing
 */
int run_event_loop(struct daemon_state *state) {
    fd_set read_fds, master_fds;
    int max_fd;
    struct timeval timeout;
    int retval;
    
    FD_ZERO(&master_fds);
    FD_SET(state->tcp_listen_fd, &master_fds);
    FD_SET(state->udp_fd, &master_fds);
    
    max_fd = (state->tcp_listen_fd > state->udp_fd) ?
             state->tcp_listen_fd : state->udp_fd;
    
    syslog(LOG_INFO, "Entering main event loop");
    
    while (!state->graceful_shutdown) {
        /* Check for configuration reload */
        if (state->config_reload) {
            reload_configuration(state);
        }
        
        /* Copy master fd set */
        read_fds = master_fds;
        
        /* Set timeout for select */
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        retval = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (retval < 0) {
            if (errno == EINTR) {
                /* Interrupted by signal, continue */
                continue;
            }
            syslog(LOG_ERR, "select failed: %s", strerror(errno));
            return -1;
        }
        
        if (retval == 0) {
            /* Timeout, do periodic tasks */
            continue;
        }
        
        /* Check for TCP connection */
        if (FD_ISSET(state->tcp_listen_fd, &read_fds)) {
            handle_tcp_connection(state);
        }
        
        /* Check for UDP datagram */
        if (FD_ISSET(state->udp_fd, &read_fds)) {
            handle_udp_datagram(state);
        }
    }
    
    syslog(LOG_INFO, "Exiting main event loop");
    return 0;
}

/**
 * Handle incoming TCP connection
 */
int handle_tcp_connection(struct daemon_state *state) {
    int client_fd;
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    pid_t pid;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    
    /* Accept connection */
    client_fd = accept(state->tcp_listen_fd,
                      (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            syslog(LOG_ERR, "accept failed: %s", strerror(errno));
        }
        return -1;
    }
    
    /* Get client information */
    if (getnameinfo((struct sockaddr *)&client_addr, addr_len,
                    host, sizeof(host), service, sizeof(service),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        syslog(LOG_INFO, "TCP connection from %s:%s", host, service);
    }
    
    /* Check connection limit */
    if (state->active_connections >= state->config->max_connections) {
        syslog(LOG_WARNING, "Connection limit reached, rejecting connection");
        close(client_fd);
        return -1;
    }
    
    state->total_connections++;
    state->active_connections++;
    
    /* Fork child process to handle connection */
    pid = fork();
    
    if (pid < 0) {
        syslog(LOG_ERR, "fork failed: %s", strerror(errno));
        close(client_fd);
        state->active_connections--;
        return -1;
    }
    
    if (pid == 0) {
        /* Child process */
        close(state->tcp_listen_fd);
        close(state->udp_fd);
        
        /* Handle client request */
        handle_client_request(client_fd, (struct sockaddr *)&client_addr,
                            addr_len, IPPROTO_TCP, state);
        
        close(client_fd);
        exit(0);
    }
    
    /* Parent process */
    close(client_fd);
    
    /* Track child process */
    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (state->child_pids[i] == 0) {
            state->child_pids[i] = pid;
            state->child_count++;
            break;
        }
    }
    
    return 0;
}

/**
 * Handle incoming UDP datagram
 */
int handle_udp_datagram(struct daemon_state *state) {
    char buffer[UDP_MAX_SIZE];
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    ssize_t nread;
    char host[NI_MAXHOST];
    
    /* Receive datagram */
    nread = recvfrom(state->udp_fd, buffer, sizeof(buffer), 0,
                    (struct sockaddr *)&client_addr, &addr_len);
    
    if (nread < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            syslog(LOG_ERR, "recvfrom failed: %s", strerror(errno));
        }
        return -1;
    }
    
    /* Get client information */
    if (getnameinfo((struct sockaddr *)&client_addr, addr_len,
                    host, sizeof(host), NULL, 0, NI_NUMERICHOST) == 0) {
        syslog(LOG_DEBUG, "UDP datagram from %s (%zd bytes)", host, nread);
    }
    
    /* Fork child to handle request (optional for UDP) */
    /* For simplicity, we handle it in the parent process */
    handle_client_request(state->udp_fd, (struct sockaddr *)&client_addr,
                         addr_len, IPPROTO_UDP, state);
    
    return 0;
}

/**
 * Tune socket buffer sizes based on load
 */
int tune_socket_buffers(int sockfd, int load_factor) {
    int sndbuf, rcvbuf;
    socklen_t optlen = sizeof(int);
    
    /* Get current buffer sizes */
    if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) < 0 ||
        getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen) < 0) {
        return -1;
    }
    
    /* Adjust based on load (simple heuristic) */
    if (load_factor > 75) {
        /* High load - increase buffers */
        sndbuf *= 2;
        rcvbuf *= 2;
    } else if (load_factor < 25) {
        /* Low load - decrease buffers */
        sndbuf /= 2;
        rcvbuf /= 2;
    }
    
    /* Apply new buffer sizes */
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    
    syslog(LOG_DEBUG, "Tuned socket buffers: send=%d, recv=%d", sndbuf, rcvbuf);
    return 0;
}