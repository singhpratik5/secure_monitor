#include "protocol.h"
#include "daemon.h"
#include "monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/* Session management */
#define MAX_SESSIONS 100
#define SESSION_TIMEOUT 3600

struct session_info {
    uint32_t session_id;
    char username[MAX_USERNAME_LEN];
    uint32_t auth_level;
    time_t created;
    time_t last_access;
    int active;
};

static struct session_info sessions[MAX_SESSIONS];
static uint32_t next_session_id = 1;

/**
 * Initialize session management
 */
static void init_sessions(void) {
    static int initialized = 0;
    if (!initialized) {
        memset(sessions, 0, sizeof(sessions));
        initialized = 1;
    }
}

/**
 * Create new session
 */
static uint32_t create_session(const char *username, uint32_t auth_level) {
    init_sessions();
    
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active) {
            sessions[i].session_id = next_session_id++;
            strncpy(sessions[i].username, username, MAX_USERNAME_LEN - 1);
            sessions[i].auth_level = auth_level;
            sessions[i].created = time(NULL);
            sessions[i].last_access = sessions[i].created;
            sessions[i].active = 1;
            return sessions[i].session_id;
        }
    }
    
    return 0; /* No available session slots */
}

/**
 * Validate session
 */
static int validate_session(uint32_t session_id) {
    init_sessions();
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active && sessions[i].session_id == session_id) {
            if (now - sessions[i].last_access > SESSION_TIMEOUT) {
                sessions[i].active = 0;
                return 0; /* Session expired */
            }
            sessions[i].last_access = now;
            return 1; /* Valid session */
        }
    }
    
    return 0; /* Invalid session */
}

/**
 * Handle client request (protocol-agnostic)
 */
int handle_client_request(int fd, struct sockaddr *cliaddr,
                         socklen_t addrlen, int protocol,
                         struct daemon_state *state) {
    char buffer[4096];
    ssize_t nread;
    struct timeval timeout;
    
    /* Set timeout */
    timeout.tv_sec = state->config->connection_timeout;
    timeout.tv_usec = 0;
    
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                  &timeout, sizeof(timeout)) < 0) {
        syslog(LOG_WARNING, "Could not set receive timeout: %s",
               strerror(errno));
    }
    
    if (protocol == IPPROTO_TCP) {
        /* TCP: stream-oriented, handle multiple requests */
        while (1) {
            nread = recv(fd, buffer, sizeof(buffer), 0);
            
            if (nread < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    syslog(LOG_DEBUG, "Receive timeout");
                } else {
                    syslog(LOG_ERR, "recv failed: %s", strerror(errno));
                }
                break;
            }
            
            if (nread == 0) {
                /* Client closed connection */
                syslog(LOG_DEBUG, "Client closed connection");
                break;
            }
            
            /* Process request */
            if (process_request(fd, buffer, nread, protocol,
                              cliaddr, addrlen, state) < 0) {
                break;
            }
        }
    } else {
        /* UDP: datagram-oriented, single request */
        nread = recv(fd, buffer, sizeof(buffer), 0);
        
        if (nread > 0) {
            process_request(fd, buffer, nread, protocol,
                          cliaddr, addrlen, state);
        }
    }
    
    state->active_connections--;
    return 0;
}

/**
 * Process a single request
 */
static int process_request(int fd, char *buffer, ssize_t buflen,
                          int protocol, struct sockaddr *cliaddr,
                          socklen_t addrlen, struct daemon_state *state) {
    uint32_t cmd_type;
    
    if (buflen < sizeof(uint32_t)) {
        syslog(LOG_WARNING, "Request too small");
        return -1;
    }
    
    /* Extract command type */
    memcpy(&cmd_type, buffer, sizeof(uint32_t));
    cmd_type = ntohl(cmd_type);
    
    syslog(LOG_DEBUG, "Processing command type: %u", cmd_type);
    
    switch (cmd_type) {
    case CMD_AUTH:
        return handle_auth_request(fd, buffer, buflen, protocol,
                                  cliaddr, addrlen);
    
    case CMD_MONITOR_CPU:
    case CMD_MONITOR_MEM:
    case CMD_MONITOR_NET:
    case CMD_MONITOR_IO:
    case CMD_CUSTOM:
        return handle_monitor_request(fd, buffer, buflen, protocol,
                                     cliaddr, addrlen, state);
    
    case CMD_DISCONNECT:
        syslog(LOG_INFO, "Client requested disconnect");
        return -1; /* Close connection */
    
    default:
        syslog(LOG_WARNING, "Unknown command type: %u", cmd_type);
        return -1;
    }
}

/**
 * Authenticate client
 */
int authenticate_client(struct auth_request *req, struct auth_response *resp) {
    time_t now = time(NULL);
    
    /* Convert from network byte order */
    req->version = ntohl(req->version);
    req->timestamp = be64toh(req->timestamp);
    req->nonce = ntohl(req->nonce);
    
    /* Validate version */
    if (req->version != PROTOCOL_VERSION) {
        syslog(LOG_WARNING, "Invalid protocol version: %u", req->version);
        resp->status = htonl(1);
                return -1;
    }
    
    /* Validate timestamp (prevent replay attacks) */
    if (abs((long)(now - req->timestamp)) > 300) { /* 5 minute window */
        syslog(LOG_WARNING, "Timestamp out of range for user: %s", req->username);
        resp->status = htonl(2);
        return -1;
    }
    
    /* TODO: Implement actual authentication against user database */
    /* For demo purposes, we accept any request with valid format */
    
    /* Simple validation: username must not be empty */
    if (strlen(req->username) == 0) {
        syslog(LOG_WARNING, "Empty username");
        resp->status = htonl(3);
        return -1;
    }
    
    /* Create session */
    uint32_t session_id = create_session(req->username, 1);
    if (session_id == 0) {
        syslog(LOG_ERR, "Could not create session for user: %s", req->username);
        resp->status = htonl(4);
        return -1;
    }
    
    /* Build response */
    resp->status = htonl(0);
    resp->session_id = htonl(session_id);
    resp->expire_time = htobe64(now + SESSION_TIMEOUT);
    resp->auth_level = htonl(1);
    
    syslog(LOG_INFO, "User authenticated: %s (session: %u)",
           req->username, session_id);
    
    return 0;
}

/**
 * Handle authentication request
 */
static int handle_auth_request(int fd, char *buffer, ssize_t buflen,
                               int protocol, struct sockaddr *cliaddr,
                               socklen_t addrlen) {
    struct auth_request req;
    struct auth_response resp;
    
    if (buflen < sizeof(struct auth_request)) {
        syslog(LOG_WARNING, "Invalid auth request size");
        return -1;
    }
    
    memcpy(&req, buffer, sizeof(struct auth_request));
    memset(&resp, 0, sizeof(resp));
    
    /* Authenticate */
    authenticate_client(&req, &resp);
    
    /* Send response */
    if (protocol == IPPROTO_TCP) {
        return send_tcp_response(fd, &resp, sizeof(resp));
    } else {
        return send_udp_response(fd, &resp, sizeof(resp), cliaddr, addrlen);
    }
}

/**
 * Handle monitoring request
 */
static int handle_monitor_request(int fd, char *buffer, ssize_t buflen,
                                  int protocol, struct sockaddr *cliaddr,
                                  socklen_t addrlen,
                                  struct daemon_state *state) {
    struct monitor_cmd cmd;
    struct monitor_response *resp = NULL;
    int ret;
    
    if (buflen < sizeof(struct monitor_cmd)) {
        syslog(LOG_WARNING, "Invalid monitor request size");
        return -1;
    }
    
    memcpy(&cmd, buffer, sizeof(struct monitor_cmd));
    
    /* Convert from network byte order */
    cmd.cmd_type = ntohl(cmd.cmd_type);
    cmd.interval = ntohl(cmd.interval);
    cmd.auth_level = ntohl(cmd.auth_level);
    
    /* Process command */
    ret = process_monitor_command(&cmd, &resp, state);
    
    if (ret == 0 && resp != NULL) {
        /* Send response */
        size_t resp_size = sizeof(struct monitor_response) + ntohl(resp->data_length);
        
        if (protocol == IPPROTO_TCP) {
            ret = send_tcp_response(fd, resp, resp_size);
        } else {
            ret = send_udp_response(fd, resp, resp_size, cliaddr, addrlen);
        }
        
        free(resp);
    }
    
    return ret;
}

/**
 * Process monitoring command and generate response
 */
int process_monitor_command(struct monitor_cmd *cmd,
                           struct monitor_response **resp,
                           struct daemon_state *state) {
    struct system_stats stats;
    char *data_buffer;
    size_t data_size;
    int ret = 0;
    
    memset(&stats, 0, sizeof(stats));
    
    syslog(LOG_DEBUG, "Processing monitor command: %u", cmd->cmd_type);
    
    switch (cmd->cmd_type) {
    case CMD_MONITOR_CPU:
        ret = collect_cpu_stats(&stats);
        break;
        
    case CMD_MONITOR_MEM:
        ret = collect_memory_stats(&stats);
        break;
        
    case CMD_MONITOR_NET:
        ret = collect_network_stats(&stats);
        break;
        
    case CMD_MONITOR_IO:
        ret = collect_io_stats(&stats);
        break;
        
    case CMD_CUSTOM:
        /* Execute plugin */
        if (state->plugins) {
            for (int i = 0; i < state->plugins->num_plugins; i++) {
                if (strcmp(state->plugins->plugins[i].name, cmd->resource) == 0) {
                    ret = execute_plugin(&state->plugins->plugins[i], &stats);
                    break;
                }
            }
        }
        break;
        
    default:
        syslog(LOG_WARNING, "Unknown monitor command: %u", cmd->cmd_type);
        return -1;
    }
    
    if (ret < 0) {
        syslog(LOG_ERR, "Failed to collect statistics");
        return -1;
    }
    
    /* Serialize statistics */
    data_size = serialize_stats(&stats, &data_buffer);
    
    /* Allocate response */
    *resp = malloc(sizeof(struct monitor_response) + data_size);
    if (*resp == NULL) {
        syslog(LOG_ERR, "Failed to allocate response: %s", strerror(errno));
        free(data_buffer);
        return -1;
    }
    
    /* Build response */
    (*resp)->status = htonl(0);
    (*resp)->data_length = htonl(data_size);
    memcpy((*resp)->data, data_buffer, data_size);
    
    free(data_buffer);
    return 0;
}

/**
 * Serialize statistics to buffer
 */
static size_t serialize_stats(struct system_stats *stats, char **buffer) {
    /* Simple JSON serialization for demo */
    size_t size = 2048;
    *buffer = malloc(size);
    
    if (*buffer == NULL) {
        return 0;
    }
    
    snprintf(*buffer, size,
             "{"
             "\"cpu_usage\":%.2f,"
             "\"mem_total\":%lu,"
             "\"mem_free\":%lu,"
             "\"mem_available\":%lu,"
             "\"net_bytes_recv\":%lu,"
             "\"net_bytes_sent\":%lu,"
             "\"io_reads\":%lu,"
             "\"io_writes\":%lu,"
             "\"timestamp\":%ld"
             "}",
             stats->cpu_usage_percent,
             stats->mem_total,
             stats->mem_free,
             stats->mem_available,
             stats->net_bytes_recv,
             stats->net_bytes_sent,
             stats->io_reads,
             stats->io_writes,
             stats->collection_time);
    
    return strlen(*buffer);
}

/**
 * Send TCP response with proper error handling
 */
int send_tcp_response(int fd, void *data, size_t len) {
    ssize_t nwritten = 0;
    ssize_t total = 0;
    
    while (total < len) {
        nwritten = send(fd, (char *)data + total, len - total, MSG_NOSIGNAL);
        
        if (nwritten < 0) {
            if (errno == EINTR) {
                continue;
            }
            syslog(LOG_ERR, "send failed: %s", strerror(errno));
            return -1;
        }
        
        if (nwritten == 0) {
            syslog(LOG_WARNING, "Connection closed by peer");
            return -1;
        }
        
        total += nwritten;
    }
    
    syslog(LOG_DEBUG, "Sent %zd bytes via TCP", total);
    return 0;
}

/**
 * Send UDP response
 */
int send_udp_response(int fd, void *data, size_t len,
                     struct sockaddr *dest, socklen_t addrlen) {
    ssize_t nwritten;
    
    /* UDP has size limits */
    if (len > 65507) {
        syslog(LOG_WARNING, "UDP response too large: %zu bytes", len);
        return -1;
    }
    
    nwritten = sendto(fd, data, len, 0, dest, addrlen);
    
    if (nwritten < 0) {
        syslog(LOG_ERR, "sendto failed: %s", strerror(errno));
        return -1;
    }
    
    if (nwritten != len) {
        syslog(LOG_WARNING, "Partial UDP send: %zd of %zu bytes", nwritten, len);
        return -1;
    }
    
    syslog(LOG_DEBUG, "Sent %zd bytes via UDP", nwritten);
    return 0;
}