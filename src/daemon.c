#include "daemon.h"
#include "network.h"
#include "monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>

/* Global daemon state (for signal handlers) */
static struct daemon_state *g_daemon_state = NULL;

/* Signal handler prototypes */
static void signal_handler(int signo);
static void sigchld_handler(int signo);
static void setup_signal_handlers(void);

/**
 * Initialize daemon using double-fork technique
 */
int secure_monitor_init(struct daemon_state *state) {
    pid_t pid;
    int i, fd0, fd1, fd2;
    struct rlimit rl;
    struct sigaction sa;
    
    /* Clear file creation mask */
    umask(0);
    
    /* Get maximum number of file descriptors */
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        perror("getrlimit");
        return -1;
    }
    
    /* First fork to ensure we're not a process group leader */
    if ((pid = fork()) < 0) {
        perror("fork");
        return -1;
    } else if (pid != 0) {
        /* Parent exits */
        exit(0);
    }
    
    /* Child continues - become session leader */
    if (setsid() < 0) {
        perror("setsid");
        return -1;
    }
    
    /* Ignore SIGHUP before second fork */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        perror("sigaction(SIGHUP)");
        return -1;
    }
    
    /* Second fork to ensure we can never acquire a controlling terminal */
    if ((pid = fork()) < 0) {
        perror("fork");
        return -1;
    } else if (pid != 0) {
        /* Parent exits */
        exit(0);
    }
    
    /* Change working directory to root */
    if (chdir("/") < 0) {
        perror("chdir");
        return -1;
    }
    
    /* Close all open file descriptors */
    if (rl.rlim_max == RLIM_INFINITY) {
        rl.rlim_max = 1024;
    }
    for (i = 0; i < rl.rlim_max; i++) {
        close(i);
    }
    
    /* Attach file descriptors 0, 1, and 2 to /dev/null */
    fd0 = open("/dev/null", O_RDWR);
    fd1 = dup(0);
    fd2 = dup(0);
    
    /* Initialize syslog */
    openlog("secure_monitor", LOG_CONS | LOG_PID, LOG_FACILITY);
    
    if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
        syslog(LOG_ERR, "Unexpected file descriptors: %d %d %d", fd0, fd1, fd2);
        return -1;
    }
    
    syslog(LOG_INFO, "Daemon initialized successfully (PID: %d)", getpid());
    
    /* Write PID file */
    FILE *pidfp = fopen(PID_FILE, "w");
    if (pidfp) {
        fprintf(pidfp, "%d\n", getpid());
        fclose(pidfp);
    } else {
        syslog(LOG_WARNING, "Could not write PID file: %s", strerror(errno));
    }
    
    /* Set up signal handlers */
    setup_signal_handlers();
    g_daemon_state = state;
    
    /* Initialize daemon state */
    state->config_reload = 0;
    state->graceful_shutdown = 0;
    state->child_count = 0;
    state->total_connections = 0;
    state->active_connections = 0;
    state->start_time = time(NULL);
    
    memset(state->child_pids, 0, sizeof(state->child_pids));
    
    return 0;
}

/**
 * Initialize daemon for inetd operation
 */
int secure_monitor_inetd(struct daemon_state *state) {
    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    
    /* Initialize syslog */
    openlog("secure_monitor", LOG_PID, LOG_FACILITY);
    syslog(LOG_INFO, "Starting in inetd mode");
    
    /* Set up signal handlers */
    setup_signal_handlers();
    g_daemon_state = state;
    
    /* Initialize state */
    state->config_reload = 0;
    state->graceful_shutdown = 0;
    state->child_count = 0;
    
    /* Get peer address (inetd passes connection on stdin/stdout) */
    if (getpeername(STDIN_FILENO, (struct sockaddr *)&peer_addr, &peer_len) < 0) {
        syslog(LOG_ERR, "getpeername failed: %s", strerror(errno));
        return -1;
    }
    
    /* Log connection */
    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&peer_addr, peer_len,
                    host, sizeof(host), NULL, 0, NI_NUMERICHOST) == 0) {
        syslog(LOG_INFO, "Connection from: %s", host);
    }
    
    return 0;
}

/**
 * Detect operation mode based on command-line arguments
 */
daemon_mode_t detect_operation_mode(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-standalone") == 0) {
            return MODE_STANDALONE;
        } else if (strcmp(argv[i], "-inetd") == 0) {
            return MODE_INETD;
        }
    }
    
    /* Auto-detect: if stdin is a socket, assume inetd mode */
    struct stat st;
    if (fstat(STDIN_FILENO, &st) == 0 && S_ISSOCK(st.st_mode)) {
        return MODE_INETD;
    }
    
    return MODE_UNKNOWN;
}

/**
 * Load configuration from file
 */
int load_configuration(const char *config_file, struct monitor_config *config) {
    FILE *fp;
    char line[256];
    char key[64], value[192];
    
    /* Set default values */
    config->port = 8888;
    strcpy(config->bind_address, "0.0.0.0");
    config->max_connections = 50;
    config->connection_timeout = 60;
    config->rate_limit = 100;
    strcpy(config->plugin_dir, "/usr/lib/secure_monitor/plugins");
    strcpy(config->log_file, "/var/log/secure_monitor.log");
    config->debug_level = 0;
    config->use_ipv6 = 1;
    config->use_tls = 0;
    config->cert_file[0] = '\0';
    config->key_file[0] = '\0';
    
    fp = fopen(config_file, "r");
    if (!fp) {
        syslog(LOG_WARNING, "Could not open config file %s, using defaults", 
               config_file);
        return 0; /* Not an error, use defaults */
    }
    
    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        if (sscanf(line, "%63s = %191s", key, value) == 2) {
            if (strcmp(key, "port") == 0) {
                config->port = atoi(value);
            } else if (strcmp(key, "bind_address") == 0) {
                strncpy(config->bind_address, value, sizeof(config->bind_address) - 1);
            } else if (strcmp(key, "max_connections") == 0) {
                config->max_connections = atoi(value);
            } else if (strcmp(key, "connection_timeout") == 0) {
                config->connection_timeout = atoi(value);
            } else if (strcmp(key, "rate_limit") == 0) {
                config->rate_limit = atoi(value);
            } else if (strcmp(key, "plugin_dir") == 0) {
                strncpy(config->plugin_dir, value, sizeof(config->plugin_dir) - 1);
            } else if (strcmp(key, "debug_level") == 0) {
                config->debug_level = atoi(value);
            } else if (strcmp(key, "use_ipv6") == 0) {
                config->use_ipv6 = atoi(value);
            } else if (strcmp(key, "use_tls") == 0) {
                config->use_tls = atoi(value);
            } else if (strcmp(key, "cert_file") == 0) {
                strncpy(config->cert_file, value, sizeof(config->cert_file) - 1);
            } else if (strcmp(key, "key_file") == 0) {
                strncpy(config->key_file, value, sizeof(config->key_file) - 1);
            }
        }
    }
    
    fclose(fp);
    syslog(LOG_INFO, "Configuration loaded from %s", config_file);
    return 0;
}

/**
 * Reload configuration (called on SIGHUP)
 */
int reload_configuration(struct daemon_state *state) {
    struct monitor_config new_config;
    
    syslog(LOG_INFO, "Reloading configuration...");
    
    if (load_configuration(CONFIG_FILE, &new_config) < 0) {
        syslog(LOG_ERR, "Failed to reload configuration");
        return -1;
    }
    
    /* Update configuration */
    memcpy(state->config, &new_config, sizeof(struct monitor_config));
    
    /* Reload plugins if plugin directory changed */
    if (state->plugins) {
        reload_plugins(state->plugins);
    }
    
    syslog(LOG_INFO, "Configuration reloaded successfully");
    state->config_reload = 0;
    
    return 0;
}

/**
 * Clean up daemon resources
 */
void cleanup_daemon(struct daemon_state *state) {
    syslog(LOG_INFO, "Cleaning up daemon resources...");
    
    /* Close network sockets */
    if (state->tcp_listen_fd >= 0) {
        close(state->tcp_listen_fd);
    }
    if (state->udp_fd >= 0) {
        close(state->udp_fd);
    }
    
    /* Unload plugins */
    if (state->plugins) {
        unload_plugins(state->plugins);
        free(state->plugins);
    }
    
    /* Free configuration */
    if (state->config) {
        free(state->config);
    }
    
    /* Remove PID file */
    unlink(PID_FILE);
    
    /* Close syslog */
    syslog(LOG_INFO, "Daemon shutting down");
    closelog();
}

/**
 * Generic signal handler
 */
static void signal_handler(int signo) {
    int saved_errno = errno;
    
    if (g_daemon_state == NULL) {
        errno = saved_errno;
        return;
    }
    
    switch (signo) {
    case SIGHUP:
        /* Configuration reload requested */
        g_daemon_state->config_reload = 1;
        break;
        
    case SIGTERM:
    case SIGINT:
        /* Graceful shutdown requested */
        g_daemon_state->graceful_shutdown = 1;
        break;
    }
    
    errno = saved_errno;
}

/**
 * SIGCHLD handler to prevent zombie processes
 */
static void sigchld_handler(int signo) {
    int saved_errno = errno;
    pid_t pid;
    int status;
    
    /* Reap all dead children */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* Remove from child list */
        if (g_daemon_state) {
            for (int i = 0; i < MAX_CHILDREN; i++) {
                if (g_daemon_state->child_pids[i] == pid) {
                    g_daemon_state->child_pids[i] = 0;
                    g_daemon_state->child_count--;
                    break;
                }
            }
            
            if (WIFEXITED(status)) {
                syslog(LOG_INFO, "Child %d exited with status %d",
                       pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                syslog(LOG_WARNING, "Child %d terminated by signal %d",
                       pid, WTERMSIG(status));
            }
        }
    }
    
    errno = saved_errno;
}

/**
 * Set up all signal handlers
 */
static void setup_signal_handlers(void) {
    struct sigaction sa;
    
    /* Set up SIGCHLD handler */
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    
    /* Set up SIGHUP handler */
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
    
    /* Set up SIGINT handler */
    sigaction(SIGINT, &sa, NULL);
    
    /* Ignore SIGPIPE (broken pipe) */
    signal(SIGPIPE, SIG_IGN);
}