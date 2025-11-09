#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* Plugin interface - these symbols must be exported */

char* plugin_get_name(void) {
    return "CPU Monitor";
}

uint32_t* plugin_get_interval(void) {
    static uint32_t interval = 5; /* 5 seconds */
    return &interval;
}

int plugin_init(void) {
    syslog(LOG_INFO, "CPU Monitor plugin initialized");
    return 0;
}

int plugin_collect(struct system_stats *stats) {
    FILE *fp;
    char line[256];
    unsigned long user, nice, system, idle;
    
    fp = fopen("/proc/stat", "r");
    if (!fp) {
        return -1;
    }
    
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    
    if (sscanf(line, "cpu %lu %lu %lu %lu",
               &user, &nice, &system, &idle) == 4) {
        unsigned long total = user + nice + system + idle;
        if (total > 0) {
            stats->cpu_usage_percent = 100.0 * (1.0 - ((double)idle / total));
        }
    }
    
    fclose(fp);
    
    syslog(LOG_DEBUG, "CPU usage: %.2f%%", stats->cpu_usage_percent);
    return 0;
}

int plugin_cleanup(void) {
    syslog(LOG_INFO, "CPU Monitor plugin cleaned up");
    return 0;
}