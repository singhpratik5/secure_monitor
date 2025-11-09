#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <sys/socket.h>
#include "daemon.h" 

#define PROTOCOL_VERSION 1
#define MAX_USERNAME_LEN 32
#define MAX_TOKEN_LEN 64
#define MAX_RESOURCE_LEN 32

/* Protocol message types */
typedef enum {
    CMD_AUTH = 1,
    CMD_MONITOR_CPU = 2,
    CMD_MONITOR_MEM = 3,
    CMD_MONITOR_NET = 4,
    CMD_MONITOR_IO = 5,
    CMD_CUSTOM = 6,
    CMD_DISCONNECT = 99
} cmd_type_t;

/* Authentication request */
struct auth_request {
    uint32_t version;
    char username[MAX_USERNAME_LEN];
    char token[MAX_TOKEN_LEN];
    uint64_t timestamp;
    uint32_t nonce;
} __attribute__((packed));

/* Authentication response */
struct auth_response {
    uint32_t status;
    uint32_t session_id;
    uint64_t expire_time;
    uint32_t auth_level;
} __attribute__((packed));

/* Monitoring command */
struct monitor_cmd {
    uint32_t cmd_type;
    uint32_t interval;
    char resource[MAX_RESOURCE_LEN];
    uint32_t auth_level;
} __attribute__((packed));

/* Monitoring response */
struct monitor_response {
    uint32_t status;
    uint32_t data_length;
    char data[0]; /* Flexible array member */
} __attribute__((packed));

/* Protocol handling functions */
int handle_client_request(int fd, struct sockaddr *cliaddr,
                         socklen_t addrlen, int protocol,
                         struct daemon_state *state);
int authenticate_client(struct auth_request *req, struct auth_response *resp);
int process_monitor_command(struct monitor_cmd *cmd, 
                           struct monitor_response **resp,
                           struct daemon_state *state);
int send_tcp_response(int fd, void *data, size_t len);
int send_udp_response(int fd, void *data, size_t len,
                     struct sockaddr *dest, socklen_t addrlen);

#endif /* PROTOCOL_H */