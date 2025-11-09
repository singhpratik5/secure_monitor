#include "plugin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <syslog.h>
#include <errno.h>

// ADD THIS PROTOTYPE
static int load_single_plugin(struct plugin_manager *pm, const char *path);
/**
 * Initialize plugin manager
 */
int init_plugin_manager(struct plugin_manager *pm, const char *plugin_dir) {
    memset(pm, 0, sizeof(struct plugin_manager));
    strncpy(pm->plugin_dir, plugin_dir, sizeof(pm->plugin_dir) - 1);
    
    syslog(LOG_INFO, "Initialized plugin manager (dir: %s)", plugin_dir);
    return 0;
}

/**
 * Load all monitoring plugins from directory
 */
int load_monitoring_plugins(struct plugin_manager *pm) {
    DIR *dir;
    struct dirent *entry;
    char plugin_path[512];
    
    dir = opendir(pm->plugin_dir);
    if (!dir) {
        syslog(LOG_ERR, "Failed to open plugin directory %s: %s",
               pm->plugin_dir, strerror(errno));
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL && pm->num_plugins < MAX_PLUGINS) {
        /* Only load .so files */
        if (strstr(entry->d_name, ".so") == NULL) {
            continue;
        }
        
        snprintf(plugin_path, sizeof(plugin_path), "%s/%s",
                pm->plugin_dir, entry->d_name);
        
        if (load_single_plugin(pm, plugin_path) == 0) {
            syslog(LOG_INFO, "Loaded plugin: %s", entry->d_name);
        }
    }
    
    closedir(dir);
    syslog(LOG_INFO, "Loaded %d plugins", pm->num_plugins);
    
    return 0;
}

/**
 * Load a single plugin
 */
static int load_single_plugin(struct plugin_manager *pm, const char *path) {
    void *handle;
    struct monitor_plugin *plugin;
    char *error;
    
    if (pm->num_plugins >= MAX_PLUGINS) {
        syslog(LOG_WARNING, "Maximum number of plugins reached");
        return -1;
    }
    
    /* Open shared library */
    handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        syslog(LOG_ERR, "Failed to load plugin %s: %s", path, dlerror());
        return -1;
    }
    
    /* Clear any existing errors */
    dlerror();
    
    plugin = &pm->plugins[pm->num_plugins];
    plugin->handle = handle;
    
    /* Load symbols */
    plugin->init = dlsym(handle, "plugin_init");
    if ((error = dlerror()) != NULL) {
        syslog(LOG_ERR, "Failed to find plugin_init: %s", error);
        dlclose(handle);
        return -1;
    }
    
    plugin->collect = dlsym(handle, "plugin_collect");
    if ((error = dlerror()) != NULL) {
        syslog(LOG_ERR, "Failed to find plugin_collect: %s", error);
        dlclose(handle);
        return -1;
    }
    
    plugin->cleanup = dlsym(handle, "plugin_cleanup");
    if ((error = dlerror()) != NULL) {
        syslog(LOG_WARNING, "Plugin has no cleanup function");
        plugin->cleanup = NULL;
    }
    
    /* Get plugin name */
    char *(*get_name)(void) = dlsym(handle, "plugin_get_name");
    if (get_name) {
        strncpy(plugin->name, get_name(), MAX_PLUGIN_NAME - 1);
    } else {
        /* Use filename as name */
        const char *filename = strrchr(path, '/');
        filename = filename ? filename + 1 : path;
        strncpy(plugin->name, filename, MAX_PLUGIN_NAME - 1);
        plugin->name[MAX_PLUGIN_NAME - 1] = '\0';
    }
    
    /* Get collection interval */
    uint32_t *(*get_interval)(void) = dlsym(handle, "plugin_get_interval");
    if (get_interval) {
        plugin->interval = *get_interval();
    } else {
        plugin->interval = 60; /* Default: 60 seconds */
    }
    
    /* Initialize plugin */
    if (plugin->init() < 0) {
        syslog(LOG_ERR, "Plugin initialization failed: %s", plugin->name);
        dlclose(handle);
        return -1;
    }
    
    plugin->enabled = 1;
    plugin->last_collection = 0;
    
    pm->num_plugins++;
    return 0;
}

/**
 * Unload all plugins
 */
int unload_plugins(struct plugin_manager *pm) {
    for (int i = 0; i < pm->num_plugins; i++) {
        struct monitor_plugin *plugin = &pm->plugins[i];
        
        if (plugin->cleanup) {
            plugin->cleanup();
        }
        
        if (plugin->handle) {
            dlclose(plugin->handle);
        }
        
        syslog(LOG_INFO, "Unloaded plugin: %s", plugin->name);
    }
    
    pm->num_plugins = 0;
    return 0;
}

/**
 * Execute a plugin's collection function
 */
int execute_plugin(struct monitor_plugin *plugin, struct system_stats *stats) {
    time_t now = time(NULL);
    
    if (!plugin->enabled) {
        return -1;
    }
    
    /* Check if it's time to collect */
    if (now - plugin->last_collection < plugin->interval) {
        return 0; /* Not yet time */
    }
    
    syslog(LOG_DEBUG, "Executing plugin: %s", plugin->name);
    
    int ret = plugin->collect(stats);
    
    if (ret == 0) {
        plugin->last_collection = now;
    } else {
        syslog(LOG_WARNING, "Plugin collection failed: %s", plugin->name);
    }
    
    return ret;
}

/**
 * Reload all plugins
 */
int reload_plugins(struct plugin_manager *pm) {
    syslog(LOG_INFO, "Reloading plugins...");
    
    unload_plugins(pm);
    return load_monitoring_plugins(pm);
}