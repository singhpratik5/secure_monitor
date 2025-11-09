#include "security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>
#include <pthread.h>

/* Rate limiter state */
static struct rate_limit_entry rate_limit_table[MAX_RATE_LIMIT_ENTRIES];
static pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;
static int rate_limiter_initialized = 0;

/* Blacklist state */
#define MAX_BLACKLIST_ENTRIES 100

struct blacklist_entry {
    char ip_address[46];
    time_t expiry;
    int active;
};

static struct blacklist_entry blacklist[MAX_BLACKLIST_ENTRIES];
static pthread_mutex_t blacklist_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Initialize rate limiter
 */
int init_rate_limiter(void) {
    pthread_mutex_lock(&rate_limit_mutex);
    
    if (!rate_limiter_initialized) {
        memset(rate_limit_table, 0, sizeof(rate_limit_table));
        rate_limiter_initialized = 1;
    }
    
    pthread_mutex_unlock(&rate_limit_mutex);
    return 0;
}

/**
 * Check if client IP is within rate limits
 */
int check_rate_limit(const char *client_ip) {
    if (!rate_limiter_initialized) {
        init_rate_limiter();
    }
    
    pthread_mutex_lock(&rate_limit_mutex);
    
    time_t now = time(NULL);
    int found = 0;
    int slot = -1;
    
    /* Find existing entry or empty slot */
    for (int i = 0; i < MAX_RATE_LIMIT_ENTRIES; i++) {
        if (strcmp(rate_limit_table[i].ip_address, client_ip) == 0) {
            found = 1;
            slot = i;
            break;
        }
        if (slot == -1 && rate_limit_table[i].ip_address[0] == '\0') {
            slot = i;
        }
    }
    
    /* If not found, use empty slot */
    if (!found && slot != -1) {
        strncpy(rate_limit_table[slot].ip_address, client_ip, 45);
        rate_limit_table[slot].window_start = now;
        rate_limit_table[slot].request_count = 1;
        rate_limit_table[slot].last_request = now;
        pthread_mutex_unlock(&rate_limit_mutex);
        return 0; /* Allowed */
    }
    
    if (slot == -1) {
        /* Table full - allow for now but log warning */
        pthread_mutex_unlock(&rate_limit_mutex);
        syslog(LOG_WARNING, "Rate limit table full");
        return 0;
    }
    
    struct rate_limit_entry *entry = &rate_limit_table[slot];
    
    /* Reset window if expired */
    if (now - entry->window_start >= RATE_LIMIT_WINDOW) {
        entry->window_start = now;
        entry->request_count = 1;
        entry->last_request = now;
        pthread_mutex_unlock(&rate_limit_mutex);
        return 0;
    }
    
    /* Increment request count */
    entry->request_count++;
    entry->last_request = now;
    
    /* Check limit (100 requests per minute by default) */
    if (entry->request_count > 100) {
        pthread_mutex_unlock(&rate_limit_mutex);
        syslog(LOG_WARNING, "Rate limit exceeded for IP: %s", client_ip);
        return -1; /* Rate limit exceeded */
    }
    
    pthread_mutex_unlock(&rate_limit_mutex);
    return 0;
}

/**
 * Cleanup rate limiter
 */
void cleanup_rate_limiter(void) {
    pthread_mutex_lock(&rate_limit_mutex);
    
    memset(rate_limit_table, 0, sizeof(rate_limit_table));
    rate_limiter_initialized = 0;
    
    pthread_mutex_unlock(&rate_limit_mutex);
}

/**
 * Validate input string
 */
int validate_input(const char *input, size_t max_len) {
    if (!input) {
        return -1;
    }
    
    size_t len = strlen(input);
    if (len == 0 || len > max_len) {
        return -1;
    }
    
    /* Check for valid characters */
    for (size_t i = 0; i < len; i++) {
        if (!isprint((unsigned char)input[i]) && input[i] != '\0') {
            return -1;
        }
    }
    
    return 0;
}

/**
 * Sanitize string by removing control characters
 */
int sanitize_string(char *str, size_t len) {
    if (!str) {
        return -1;
    }
    
    for (size_t i = 0; i < len && str[i] != '\0'; i++) {
        if (iscntrl((unsigned char)str[i]) && str[i] != '\0') {
            str[i] = '_';
        }
    }
    
    return 0;
}

/**
 * Verify timestamp is within acceptable range
 */
int verify_timestamp(uint64_t timestamp, uint64_t max_age) {
    time_t now = time(NULL);
    int64_t diff = (int64_t)now - (int64_t)timestamp;
    
    if (diff < 0) {
        diff = -diff;
    }
    
    if ((uint64_t)diff > max_age) {
        return -1; /* Timestamp too old or too far in future */
    }
    
    return 0;
}

/**
 * Generate cryptographically secure session token
 */
int generate_session_token(char *token, size_t len) {
    if (!token || len < 32) {
        return -1;
    }
    
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        return -1;
    }
    
    unsigned char random_bytes[16];
    if (fread(random_bytes, 1, sizeof(random_bytes), urandom) != sizeof(random_bytes)) {
        fclose(urandom);
        return -1;
    }
    fclose(urandom);
    
    /* Convert to hex string */
    for (int i = 0; i < 16; i++) {
        snprintf(token + (i * 2), 3, "%02x", random_bytes[i]);
    }
    token[32] = '\0';
    
    return 0;
}

/**
 * Hash password (simple SHA256 wrapper - should use bcrypt in production)
 */
int hash_password(const char *password, char *hash, size_t hash_len) {
    if (!password || !hash || hash_len < 65) {
        return -1;
    }
    
    /* In production, use bcrypt or argon2 */
    /* This is a placeholder implementation */
    
    FILE *fp = popen("echo -n \"password\" | sha256sum", "r");
    if (!fp) {
        return -1;
    }
    
    if (fgets(hash, hash_len, fp) == NULL) {
        pclose(fp);
        return -1;
    }
    
    pclose(fp);
    
    /* Remove trailing whitespace */
    hash[64] = '\0';
    return 0;
}

/**
 * Verify password against hash
 */
int verify_password(const char *password, const char *hash) {
    char computed_hash[65];
    
    if (hash_password(password, computed_hash, sizeof(computed_hash)) < 0) {
        return -1;
    }
    
    return strcmp(computed_hash, hash) == 0 ? 0 : -1;
}

/**
 * Check if IP address is blacklisted
 */
int is_ip_blacklisted(const char *ip_address) {
    pthread_mutex_lock(&blacklist_mutex);
    
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_BLACKLIST_ENTRIES; i++) {
        if (blacklist[i].active &&
            strcmp(blacklist[i].ip_address, ip_address) == 0) {
            
            /* Check if blacklist entry expired */
            if (blacklist[i].expiry > 0 && now > blacklist[i].expiry) {
                blacklist[i].active = 0;
                pthread_mutex_unlock(&blacklist_mutex);
                return 0; /* Not blacklisted (expired) */
            }
            
            pthread_mutex_unlock(&blacklist_mutex);
            return 1; /* Blacklisted */
        }
    }
    
    pthread_mutex_unlock(&blacklist_mutex);
    return 0; /* Not blacklisted */
}

/**
 * Add IP address to blacklist
 */
int blacklist_ip(const char *ip_address, time_t duration) {
    pthread_mutex_lock(&blacklist_mutex);
    
    time_t now = time(NULL);
    int slot = -1;
    
    /* Find empty slot */
    for (int i = 0; i < MAX_BLACKLIST_ENTRIES; i++) {
        if (!blacklist[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        pthread_mutex_unlock(&blacklist_mutex);
        syslog(LOG_WARNING, "Blacklist table full");
        return -1;
    }
    
    strncpy(blacklist[slot].ip_address, ip_address, 45);
    blacklist[slot].expiry = (duration > 0) ? (now + duration) : 0;
    blacklist[slot].active = 1;
    
    pthread_mutex_unlock(&blacklist_mutex);
    
    syslog(LOG_INFO, "IP blacklisted: %s (duration: %ld seconds)",
           ip_address, duration);
    
    return 0;
}

/**
 * Remove IP address from blacklist
 */
int whitelist_ip(const char *ip_address) {
    pthread_mutex_lock(&blacklist_mutex);
    
    for (int i = 0; i < MAX_BLACKLIST_ENTRIES; i++) {
        if (blacklist[i].active &&
            strcmp(blacklist[i].ip_address, ip_address) == 0) {
            blacklist[i].active = 0;
            pthread_mutex_unlock(&blacklist_mutex);
            
            syslog(LOG_INFO, "IP whitelisted: %s", ip_address);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&blacklist_mutex);
    return -1; /* Not found */
}