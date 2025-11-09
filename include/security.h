#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <time.h>

/* Security function prototypes */
int validate_input(const char *input, size_t max_len);
int sanitize_string(char *str, size_t len);
int check_rate_limit(const char *client_ip);
int verify_timestamp(uint64_t timestamp, uint64_t max_age);
int generate_session_token(char *token, size_t len);
int hash_password(const char *password, char *hash, size_t hash_len);
int verify_password(const char *password, const char *hash);

/* Rate limiting */
struct rate_limit_entry {
    char ip_address[46];  /* IPv6 max length */
    uint32_t request_count;
    time_t window;
    time_t window_start;
    time_t last_request;
};

#define MAX_RATE_LIMIT_ENTRIES 1000
#define RATE_LIMIT_WINDOW 60  /* seconds */

int init_rate_limiter(void);
int check_rate_limit(const char *client_ip);
void cleanup_rate_limiter(void);

/* IP blacklisting */
int is_ip_blacklisted(const char *ip_address);
int blacklist_ip(const char *ip_address, time_t duration);
int whitelist_ip(const char *ip_address);

#endif /* SECURITY_H */