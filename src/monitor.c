#include "monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>

// ADD THIS PROTOTYPE HERE
static uint32_t count_network_connections(void);
/**
 * Collect comprehensive system statistics
 */
int collect_system_stats(struct system_stats *stats) {
    memset(stats, 0, sizeof(struct system_stats));
    stats->collection_time = time(NULL);
    
    if (collect_cpu_stats(stats) < 0) {
        syslog(LOG_WARNING, "Failed to collect CPU stats");
    }
    
    if (collect_memory_stats(stats) < 0) {
        syslog(LOG_WARNING, "Failed to collect memory stats");
    }
    
    if (collect_network_stats(stats) < 0) {
        syslog(LOG_WARNING, "Failed to collect network stats");
    }
    
    if (collect_io_stats(stats) < 0) {
        syslog(LOG_WARNING, "Failed to collect I/O stats");
    }
    
    return 0;
}

/**
 * Collect CPU statistics from /proc/stat
 */
int collect_cpu_stats(struct system_stats *stats) {
    FILE *fp;
    char line[256];
    unsigned long user, nice, system, idle, iowait, irq, softirq;
    static unsigned long prev_total = 0, prev_idle = 0;
    unsigned long total, total_idle, diff_total, diff_idle;
    
    fp = fopen("/proc/stat", "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open /proc/stat: %s", strerror(errno));
        return -1;
    }
    
    /* Read first line (aggregate CPU stats) */
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    
    if (sscanf(line, "cpu %lu %lu %lu %lu %lu %lu %lu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq) != 7) {
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    
    stats->cpu_user_time = user + nice;
    stats->cpu_system_time = system + irq + softirq;
    stats->cpu_idle_time = idle + iowait;
    
    /* Calculate CPU usage percentage */
    total = user + nice + system + idle + iowait + irq + softirq;
    total_idle = idle + iowait;
    
    if (prev_total != 0) {
        diff_total = total - prev_total;
        diff_idle = total_idle - prev_idle;
        
        if (diff_total > 0) {
            stats->cpu_usage_percent = 100.0 * (1.0 - ((double)diff_idle / diff_total));
        }
    }
    
    prev_total = total;
    prev_idle = total_idle;
    
    return 0;
}

/**
 * Collect memory statistics from /proc/meminfo
 */
int collect_memory_stats(struct system_stats *stats) {
    FILE *fp;
    char line[256];
    char key[64];
    unsigned long value;
    
    fp = fopen("/proc/meminfo", "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open /proc/meminfo: %s", strerror(errno));
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63s %lu", key, &value) == 2) {
            if (strcmp(key, "MemTotal:") == 0) {
                stats->mem_total = value * 1024; /* Convert to bytes */
            } else if (strcmp(key, "MemFree:") == 0) {
                stats->mem_free = value * 1024;
            } else if (strcmp(key, "MemAvailable:") == 0) {
                stats->mem_available = value * 1024;
            } else if (strcmp(key, "Cached:") == 0) {
                stats->mem_cached = value * 1024;
            } else if (strcmp(key, "SwapTotal:") == 0) {
                stats->mem_swap_total = value * 1024;
            } else if (strcmp(key, "SwapFree:") == 0) {
                stats->mem_swap_free = value * 1024;
            }
        }
    }
    
    fclose(fp);
    return 0;
}

/**
 * Collect network statistics from /proc/net/dev
 */
int collect_network_stats(struct system_stats *stats) {
    FILE *fp;
    char line[256];
    char iface[32];
    unsigned long rx_bytes, rx_packets, tx_bytes;
    unsigned long dummy;
    
    fp = fopen("/proc/net/dev", "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open /proc/net/dev: %s", strerror(errno));
        return -1;
    }
    
    /* Skip header lines */
    (void)fgets(line, sizeof(line), fp);
    (void)fgets(line, sizeof(line), fp);
    
    /* Read interface statistics */
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%31[^:]: %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                   iface, &rx_bytes, &rx_packets, &dummy, &dummy, &dummy,
                   &dummy, &dummy, &dummy, &tx_bytes) >= 10) {
            
            /* Skip loopback interface */
            if (strcmp(iface, "lo") == 0) {
                continue;
            }
            
            stats->net_bytes_recv += rx_bytes;
            stats->net_packets_recv += rx_packets;
            stats->net_bytes_sent += tx_bytes;
        }
    }
    
    fclose(fp);
    
    /* Count active connections */
    stats->net_connections = count_network_connections();
    
    return 0;
}

/**
 * Count active network connections
 */
static uint32_t count_network_connections(void) {
    FILE *fp;
    char line[256];
    uint32_t count = 0;
    
    fp = fopen("/proc/net/tcp", "r");
    if (fp) {
        /* Skip header */
        fgets(line, sizeof(line), fp);
        
        while (fgets(line, sizeof(line), fp)) {
            count++;
        }
        fclose(fp);
    }
    
    /* Add IPv6 connections */
    fp = fopen("/proc/net/tcp6", "r");
    if (fp) {
        /* Skip header */
        fgets(line, sizeof(line), fp);
        
        while (fgets(line, sizeof(line), fp)) {
            count++;
        }
        fclose(fp);
    }
    
    return count;
}

/**
 * Collect I/O statistics from /proc/diskstats
 */
int collect_io_stats(struct system_stats *stats) {
    FILE *fp;
    char line[256];
    unsigned int major, minor;
    char device[32];
    unsigned long reads, read_sectors, writes, write_sectors;
    unsigned long dummy;
    
    fp = fopen("/proc/diskstats", "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open /proc/diskstats: %s", strerror(errno));
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%u %u %31s %lu %lu %lu %lu %lu %lu %lu",
                   &major, &minor, device, &reads, &dummy, &read_sectors,
                   &dummy, &writes, &dummy, &write_sectors) >= 10) {
            
            /* Skip partitions (only count whole disks) */
            if (strchr(device, 'p') != NULL || isdigit(device[strlen(device)-1])) {
                continue;
            }
            
            stats->io_reads += reads;
            stats->io_read_bytes += read_sectors * 512;
            stats->io_writes += writes;
            stats->io_write_bytes += write_sectors * 512;
        }
    }
    
    fclose(fp);
    return 0;
}

/**
 * Collect per-process statistics
 */
int collect_process_stats(pid_t pid, struct process_stats *stats) {
    char path[256];
    FILE *fp;
    
    memset(stats, 0, sizeof(struct process_stats));
    stats->pid = pid;
    
    /* Read /proc/[pid]/stat */
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    
    unsigned long utime, stime, vsize, rss;
    long num_threads;
    char state;
    
    if (fscanf(fp, "%*d %255s %c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
               "%lu %lu %*d %*d %*d %*d %ld %*d %*u %lu %ld",
               stats->name, &state, &utime, &stime, &num_threads,
               &vsize, &rss) >= 7) {
        
        stats->state = state;
        stats->cpu_percent = 0.0; /* Would need multiple samples */
        stats->mem_vms = vsize;
        stats->mem_rss = rss * sysconf(_SC_PAGESIZE);
        stats->num_threads = num_threads;
    }
    
    fclose(fp);
    return 0;
}

/**
 * Detect memory leaks by analyzing process memory trends
 */
int detect_memory_leak(struct process_stats *stats, int num_samples) {
    /* Simple heuristic: if RSS grows consistently across samples */
    static uint64_t prev_rss[1024] = {0};
    static int sample_count[1024] = {0};
    int pid_index = stats->pid % 1024;
    
    if (prev_rss[pid_index] > 0) {
        uint64_t growth = stats->mem_rss - prev_rss[pid_index];
        
        if (growth > (1024 * 1024)) { /* 1MB growth */
            sample_count[pid_index]++;
            
            if (sample_count[pid_index] >= num_samples) {
                syslog(LOG_WARNING,
                       "Potential memory leak detected in process %d (%s)",
                       stats->pid, stats->name);
                sample_count[pid_index] = 0;
                return 1;
            }
        } else {
            sample_count[pid_index] = 0;
        }
    }
    
    prev_rss[pid_index] = stats->mem_rss;
    return 0;
}