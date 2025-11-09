#ifndef PLUGIN_H
#define PLUGIN_H

#include "monitor.h"

#define MAX_PLUGINS 16
#define MAX_PLUGIN_NAME 32

/* Plugin interface */
struct monitor_plugin {
    char name[MAX_PLUGIN_NAME];
    void *handle; /* dlopen handle */
    
    int (*init)(void);
    int (*collect)(struct system_stats *);
    int (*cleanup)(void);
    uint32_t interval;
    
    int enabled;
    time_t last_collection;
};

/* Plugin manager */
struct plugin_manager {
    struct monitor_plugin plugins[MAX_PLUGINS];
    int num_plugins;
    char plugin_dir[256];
};

/* Plugin management functions */
int init_plugin_manager(struct plugin_manager *pm, const char *plugin_dir);
int load_monitoring_plugins(struct plugin_manager *pm);
int unload_plugins(struct plugin_manager *pm);
int execute_plugin(struct monitor_plugin *plugin, struct system_stats *stats);
int reload_plugins(struct plugin_manager *pm);

#endif /* PLUGIN_H */