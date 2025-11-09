#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdint.h>
#include "monitor.h"
char* plugin_get_name(void) {
    return "Memory Monitor";
}

uint32_t* plugin_get_interval(void) {
    static uint32_t interval = 10; /* 10 seconds */
    return &interval;
}

int plugin_init(void) {
    syslog(LOG_INFO, "Memory Monitor plugin initialized");
    return 0;
}

int plugin_collect(struct system_stats *stats) {
    FILE *fp;
    char line[256];
    char key[64];
    unsigned long value;
    
    fp = fopen("/proc/meminfo", "r");
    if (!fp) {
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63s %lu", key, &value) == 2) {
            if (strcmp(key, "MemTotal:") == 0) {
                stats->mem_total = value * 1024;
            } else if (strcmp(key, "MemAvailable:") == 0) {
                stats->mem_available = value * 1024;
            }
        }
    }
    
    fclose(fp);
    
    double usage = 100.0 * (1.0 - ((double)stats->mem_available / stats->mem_total));
    syslog(LOG_DEBUG, "Memory usage: %.2f%%", usage);
    
    return 0;
}

int plugin_cleanup(void) {
    syslog(LOG_INFO, "Memory Monitor plugin cleaned up");
    return 0;
}