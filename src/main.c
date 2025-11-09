#include "daemon.h"
#include "network.h"
#include "plugin.h"
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Global daemon state */
static struct daemon_state g_state;

/* Function prototypes */
static void print_usage(const char *progname);
static int parse_arguments(int argc, char *argv[], struct monitor_config *config);
static int run_standalone_mode(struct daemon_state *state);
static int run_inetd_mode(struct daemon_state *state);

/**
 * Main entry point
 */
int main(int argc, char *argv[]) {
    daemon_mode_t mode;
    int ret = 0;
    
    /* Allocate configuration */
    g_state.config = malloc(sizeof(struct monitor_config));
    if (!g_state.config) {
        fprintf(stderr, "Failed to allocate configuration\n");
        return 1;
    }
    
    /* Load default configuration */
    if (load_configuration(CONFIG_FILE, g_state.config) < 0) {
        /* Continue with defaults */
    }
    
    /* Parse command-line arguments (may override config) */
    if (parse_arguments(argc, argv, g_state.config) < 0) {
        print_usage(argv[0]);
        free(g_state.config);
        return 1;
    }
    
    /* Detect operation mode */
    mode = detect_operation_mode(argc, argv);
    
    switch (mode) {
    case MODE_STANDALONE:
        ret = run_standalone_mode(&g_state);
        break;
        
    case MODE_INETD:
        ret = run_inetd_mode(&g_state);
        break;
        
    case MODE_UNKNOWN:
    default:
        fprintf(stderr, "Unknown operation mode. Use -standalone or -inetd\n");
        print_usage(argv[0]);
        free(g_state.config);
        return 1;
    }
    
    /* Cleanup */
    cleanup_daemon(&g_state);
    
    return ret;
}

/**
 * Run in standalone daemon mode
 */
static int run_standalone_mode(struct daemon_state *state) {
    int ret;
    
    printf("Starting secure monitoring daemon in standalone mode...\n");
    printf("Port: %d\n", state->config->port);
    printf("Bind address: %s\n", state->config->bind_address);
    printf("Max connections: %d\n", state->config->max_connections);
    
    /* Initialize daemon (double-fork) */
    if (secure_monitor_init(state) < 0) {
        fprintf(stderr, "Failed to initialize daemon\n");
        return 1;
    }
    
    /* From here on, we're running as a daemon */
    syslog(LOG_INFO, "Daemon started successfully");
    
    /* Initialize plugin manager */
    state->plugins = malloc(sizeof(struct plugin_manager));
    if (state->plugins) {
        init_plugin_manager(state->plugins, state->config->plugin_dir);
        load_monitoring_plugins(state->plugins);
    }
    
    /* Create network sockets */
    state->tcp_listen_fd = create_tcp_socket(state->config->bind_address,
                                             state->config->port,
                                             state->config->use_ipv6);
    if (state->tcp_listen_fd < 0) {
        syslog(LOG_ERR, "Failed to create TCP socket");
        return 1;
    }
    
    state->udp_fd = create_udp_socket(state->config->bind_address,
                                      state->config->port,
                                      state->config->use_ipv6);
    if (state->udp_fd < 0) {
        syslog(LOG_ERR, "Failed to create UDP socket");
        close(state->tcp_listen_fd);
        return 1;
    }
    
    syslog(LOG_INFO, "Network sockets created successfully");
    
    /* Run main event loop */
    ret = run_event_loop(state);
    
    return ret;
}

/**
 * Run in inetd-managed mode
 */
static int run_inetd_mode(struct daemon_state *state) {
    /* Initialize for inetd operation */
    if (secure_monitor_inetd(state) < 0) {
        syslog(LOG_ERR, "Failed to initialize inetd mode");
        return 1;
    }
    
    /* Initialize plugin manager */
    state->plugins = malloc(sizeof(struct plugin_manager));
    if (state->plugins) {
        init_plugin_manager(state->plugins, state->config->plugin_dir);
        load_monitoring_plugins(state->plugins);
    }
    
    /* Handle single connection on stdin/stdout */
    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    
    if (getpeername(STDIN_FILENO, (struct sockaddr *)&peer_addr, &peer_len) == 0) {
        handle_client_request(STDIN_FILENO,
                            (struct sockaddr *)&peer_addr,
                            peer_len,
                            IPPROTO_TCP,
                            state);
    }
    
    return 0;
}

/**
 * Parse command-line arguments
 */
static int parse_arguments(int argc, char *argv[], struct monitor_config *config) {
    int opt;
    struct option long_options[] = {
        {"standalone", no_argument, 0, 's'},
        {"inetd", no_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"bind", required_argument, 0, 'b'},
        {"config", required_argument, 0, 'c'},
        {"max-connections", required_argument, 0, 'm'},
        {"timeout", required_argument, 0, 't'},
        {"plugin-dir", required_argument, 0, 'P'},
        {"debug", no_argument, 0, 'd'},
        {"ipv6", no_argument, 0, '6'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "sip:b:c:m:t:P:d6h",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 's':
        case 'i':
            /* Mode is detected separately */
            break;
            
        case 'p':
            config->port = atoi(optarg);
            break;
            
        case 'b':
            strncpy(config->bind_address, optarg,
                   sizeof(config->bind_address) - 1);
            break;
            
        case 'c':
            load_configuration(optarg, config);
            break;
            
        case 'm':
            config->max_connections = atoi(optarg);
            break;
            
        case 't':
            config->connection_timeout = atoi(optarg);
            break;
            
        case 'P':
            strncpy(config->plugin_dir, optarg,
                   sizeof(config->plugin_dir) - 1);
            break;
            
        case 'd':
            config->debug_level = 1;
            break;
            
        case '6':
            config->use_ipv6 = 1;
            break;
            
        case 'h':
        default:
            return -1;
        }
    }
    
    return 0;
}

/**
 * Print usage information
 */
static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -s, --standalone          Run in standalone daemon mode\n");
    printf("  -i, --inetd               Run in inetd-managed mode\n");
    printf("  -p, --port PORT           Listen port (default: 8888)\n");
    printf("  -b, --bind ADDRESS        Bind address (default: 0.0.0.0)\n");
    printf("  -c, --config FILE         Configuration file\n");
    printf("  -m, --max-connections N   Maximum concurrent connections\n");
    printf("  -t, --timeout SECONDS     Connection timeout\n");
    printf("  -P, --plugin-dir DIR      Plugin directory\n");
    printf("  -d, --debug               Enable debug mode\n");
    printf("  -6, --ipv6                Enable IPv6 dual-stack\n");
    printf("  -h, --help                Show this help message\n");
}