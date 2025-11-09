#ifndef DAEMON_H
#define DAEMON_H

#include <sys/types.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>

#define MAX_CHILDREN 100
#define CONFIG_FILE "/etc/secure_monitor.conf"
#define PID_FILE "/var/run/secure_monitor.pid"
#define LOG_FACILITY LOG_DAEMON

/* Daemon operation modes */
typedef enum {
    MODE_STANDALONE,
    MODE_INETD,
    MODE_UNKNOWN
} daemon_mode_t;

/* Daemon state management */
struct daemon_state {
    volatile sig_atomic_t config_reload;
    volatile sig_atomic_t graceful_shutdown;
    volatile sig_atomic_t child_count;
    
    pid_t child_pids[MAX_CHILDREN];
    int tcp_listen_fd;
    int udp_fd;
    
    struct monitor_config *config;
    struct plugin_manager *plugins;
    
    /* Statistics */
    uint64_t total_connections;
    uint64_t active_connections;
    time_t start_time;
};

/* Configuration structure */
struct monitor_config {
    uint16_t port;
    char bind_address[64];
    int max_connections;
    int connection_timeout;
    int rate_limit;
    char plugin_dir[256];
    char log_file[256];
    int debug_level;
    int use_ipv6;
    int use_tls;
    char cert_file[256];
    char key_file[256];
};

/* Function prototypes */
int secure_monitor_init(struct daemon_state *state);
int secure_monitor_inetd(struct daemon_state *state);
daemon_mode_t detect_operation_mode(int argc, char *argv[]);
int load_configuration(const char *config_file, struct monitor_config *config);
int reload_configuration(struct daemon_state *state);
void cleanup_daemon(struct daemon_state *state);

#endif /* DAEMON_H */