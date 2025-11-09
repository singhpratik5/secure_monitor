#ifndef MONITOR_H
#define MONITOR_H

#include <stdint.h>
#include <time.h>

/* System statistics structure */
struct system_stats {
    /* CPU statistics */
    double cpu_usage_percent;
    uint64_t cpu_user_time;
    uint64_t cpu_system_time;
    uint64_t cpu_idle_time;
    
    /* Memory statistics */
    uint64_t mem_total;
    uint64_t mem_free;
    uint64_t mem_available;
    uint64_t mem_cached;
    uint64_t mem_swap_total;
    uint64_t mem_swap_free;
    
    /* Network statistics */
    uint64_t net_bytes_recv;
    uint64_t net_bytes_sent;
    uint64_t net_packets_recv;
    uint64_t net_packets_sent;
    uint32_t net_connections;
    
    /* I/O statistics */
    uint64_t io_reads;
    uint64_t io_writes;
    uint64_t io_read_bytes;
    uint64_t io_write_bytes;
    
    time_t collection_time;
};

/* Process statistics */
struct process_stats {
    pid_t pid;
    char name[256];
    double cpu_percent;
    uint64_t mem_rss;
    uint64_t mem_vms;
    uint32_t num_threads;
    char state;
};

/* Monitoring functions */
int collect_system_stats(struct system_stats *stats);
int collect_process_stats(pid_t pid, struct process_stats *stats);
int collect_cpu_stats(struct system_stats *stats);
int collect_memory_stats(struct system_stats *stats);
int collect_network_stats(struct system_stats *stats);
int collect_io_stats(struct system_stats *stats);
int detect_memory_leak(struct process_stats *stats, int num_samples);

#endif /* MONITOR_H */