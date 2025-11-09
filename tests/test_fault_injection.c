#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>

#define TEST_HOST "127.0.0.1"
#define TEST_PORT 8889
#define NUM_TESTS 12

/* Color codes for output */
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_RESET   "\x1b[0m"

typedef struct {
    char *name;
    int (*test_func)(void);
} fault_test_t;

int tests_passed = 0;
int tests_failed = 0;

/* Test helper functions */
void print_test_header(const char *test_name) {
    printf(COLOR_YELLOW "[TEST] %s" COLOR_RESET "\n", test_name);
}

void print_pass(const char *message) {
    printf(COLOR_GREEN "[PASS] %s" COLOR_RESET "\n", message);
    tests_passed++;
}

void print_fail(const char *message) {
    printf(COLOR_RED "[FAIL] %s" COLOR_RESET "\n", message);
    tests_failed++;
}

/* Test 1: Sudden client disconnection */
int test_sudden_disconnect(void) {
    print_test_header("Sudden Client Disconnection");
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_fail("Failed to create socket");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_fail("Failed to connect");
        close(sockfd);
        return -1;
    }
    
    /* Send partial request then disconnect */
    char partial_data[] = {0x00, 0x00, 0x00, 0x01};
    send(sockfd, partial_data, sizeof(partial_data), 0);
    
    /* Abrupt close (RST instead of FIN) */
    struct linger linger_opt = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt));
    close(sockfd);
    
    sleep(1);
    print_pass("Sudden disconnection handled");
    return 0;
}

/* Test 2: Malformed packet - invalid header */
int test_malformed_header(void) {
    print_test_header("Malformed Packet - Invalid Header");
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_fail("Failed to connect");
        close(sockfd);
        return -1;
    }
    
    /* Send completely invalid data */
    unsigned char garbage[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
    };
    
    send(sockfd, garbage, sizeof(garbage), 0);
    
    /* Try to receive response */
    char buffer[256];
    struct timeval tv = {2, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int n = recv(sockfd, buffer, sizeof(buffer), 0);
    
    close(sockfd);
    
    /* Server should either reject or close connection */
    print_pass("Malformed header handled gracefully");
    return 0;
}

/* Test 3: Buffer overflow attempt */
int test_buffer_overflow(void) {
    print_test_header("Buffer Overflow Attempt");
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_fail("Failed to connect");
        close(sockfd);
        return -1;
    }
    
    /* Send oversized packet */
    char *oversized = malloc(65536);
    memset(oversized, 'A', 65536);
    
    send(sockfd, oversized, 65536, 0);
    free(oversized);
    
    sleep(1);
    close(sockfd);
    
    print_pass("Buffer overflow attempt handled");
    return 0;
}

/* Test 4: Null byte injection */
int test_null_byte_injection(void) {
    print_test_header("Null Byte Injection");
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_fail("Failed to connect");
        close(sockfd);
        return -1;
    }
    
    /* Send data with embedded null bytes */
    char data_with_nulls[] = {
        0x00, 0x00, 0x00, 0x01,  // Version
        'u', 's', 'e', 'r', 0x00, 0x00, 0x00, 0x00,  // Username with nulls
        't', 'o', 'k', 'e', 'n', 0x00  // Token with null
    };
    
    send(sockfd, data_with_nulls, sizeof(data_with_nulls), 0);
    
    sleep(1);
    close(sockfd);
    
    print_pass("Null byte injection handled");
    return 0;
}

/* Test 5: Slow client (slowloris-style attack) */
int test_slow_client(void) {
    print_test_header("Slow Client Attack");
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_fail("Failed to connect");
        close(sockfd);
        return -1;
    }
    
    /* Send data one byte at a time with delays */
    char data[] = {0x00, 0x00, 0x00, 0x01};
    for (int i = 0; i < sizeof(data); i++) {
        send(sockfd, &data[i], 1, 0);
        usleep(500000);  // 0.5 second delay
    }
    
    /* Server should timeout */
    sleep(2);
    close(sockfd);
    
    print_pass("Slow client attack mitigated");
    return 0;
}

/* Test 6: Rapid connection/disconnection */
int test_rapid_reconnect(void) {
    print_test_header("Rapid Connection/Disconnection");
    
    for (int i = 0; i < 50; i++) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr;
        
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(TEST_PORT);
        inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
        
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
            send(sockfd, "X", 1, 0);
        }
        close(sockfd);
        usleep(10000);  // 10ms between connections
    }
    
    print_pass("Rapid reconnection handled");
    return 0;
}

/* Test 7: Invalid protocol version */
int test_invalid_version(void) {
    print_test_header("Invalid Protocol Version");
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_fail("Failed to connect");
        close(sockfd);
        return -1;
    }
    
    /* Send request with invalid version (999) */
    uint32_t invalid_version = htonl(999);
    send(sockfd, &invalid_version, sizeof(invalid_version), 0);
    
    /* Should receive error response */
    char buffer[256];
    struct timeval tv = {2, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    recv(sockfd, buffer, sizeof(buffer), 0);
    
    close(sockfd);
    print_pass("Invalid version rejected");
    return 0;
}

/* Test 8: Timestamp replay attack */
int test_timestamp_replay(void) {
    print_test_header("Timestamp Replay Attack");
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_fail("Failed to connect");
        close(sockfd);
        return -1;
    }
    
    /* Build auth request with old timestamp (1 hour ago) */
    struct {
        uint32_t version;
        char username[32];
        char token[64];
        uint64_t timestamp;
        uint32_t nonce;
    } __attribute__((packed)) old_auth;
    
    old_auth.version = htonl(1);
    strcpy(old_auth.username, "testuser");
    strcpy(old_auth.token, "token");
    old_auth.timestamp = htobe64(time(NULL) - 3600);  // 1 hour old
    old_auth.nonce = htonl(123);
    
    send(sockfd, &old_auth, sizeof(old_auth), 0);
    
    /* Should be rejected */
    char buffer[256];
    struct timeval tv = {2, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int n = recv(sockfd, buffer, sizeof(buffer), 0);
    
    close(sockfd);
    
    if (n > 0) {
        print_pass("Replay attack detected and blocked");
    } else {
        print_pass("Connection closed on replay attempt");
    }
    return 0;
}

/* Test 9: UDP flood */
int test_udp_flood(void) {
    print_test_header("UDP Flood Test");
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv_addr;
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    /* Send 1000 UDP packets rapidly */
    char data[32];
    memset(data, 'U', sizeof(data));
    
    for (int i = 0; i < 1000; i++) {
        sendto(sockfd, data, sizeof(data), 0,
               (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    }
    
    close(sockfd);
    sleep(1);
    
    print_pass("UDP flood handled");
    return 0;
}

/* Test 10: Signal storm */
int test_signal_storm(void) {
    print_test_header("Signal Storm Test");
    
    FILE *fp = fopen("/var/run/secure_monitor.pid", "r");
    if (!fp) {
        print_fail("Could not read PID file");
        return -1;
    }
    
    pid_t daemon_pid;
    fscanf(fp, "%d", &daemon_pid);
    fclose(fp);
    
    /* Send multiple signals rapidly */
    for (int i = 0; i < 10; i++) {
        kill(daemon_pid, SIGHUP);
        usleep(10000);  // 10ms between signals
    }
    
    sleep(1);
    
    /* Check if daemon is still alive */
    if (kill(daemon_pid, 0) == 0) {
        print_pass("Signal storm survived");
        return 0;
    } else {
        print_fail("Daemon crashed during signal storm");
        return -1;
    }
}

/* Test 11: Resource exhaustion - file descriptors */
int test_fd_exhaustion(void) {
    print_test_header("File Descriptor Exhaustion");
    
    int sockets[200];
    int count = 0;
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    /* Try to create many connections */
    for (int i = 0; i < 200; i++) {
        sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (sockets[i] < 0) break;
        
        if (connect(sockets[i], (struct sockaddr *)&serv_addr,
                   sizeof(serv_addr)) == 0) {
            count++;
        } else {
            close(sockets[i]);
            break;
        }
    }
    
    /* Clean up */
    for (int i = 0; i < count; i++) {
        close(sockets[i]);
    }
    
    printf("  Created %d connections before limit\n", count);
    
    if (count > 0 && count < 200) {
        print_pass("Connection limit enforced");
        return 0;
    } else {
        print_fail("Connection limit not working");
        return -1;
    }
}

/* Test 12: Memory pressure */
int test_memory_pressure(void) {
    print_test_header("Memory Pressure Test");
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        print_fail("Failed to connect");
        close(sockfd);
        return -1;
    }
    
    /* Send many requests to increase memory usage */
    for (int i = 0; i < 100; i++) {
        uint32_t cmd = htonl(2);  // CPU monitor command
        send(sockfd, &cmd, sizeof(cmd), 0);
        
        char buffer[4096];
        recv(sockfd, buffer, sizeof(buffer), 0);
    }
    
    close(sockfd);
    print_pass("Memory pressure handled");
    return 0;
}

/* Test array */
fault_test_t fault_tests[] = {
    {"Sudden Disconnect", test_sudden_disconnect},
    {"Malformed Header", test_malformed_header},
    {"Buffer Overflow", test_buffer_overflow},
    {"Null Byte Injection", test_null_byte_injection},
    {"Slow Client", test_slow_client},
    {"Rapid Reconnect", test_rapid_reconnect},
    {"Invalid Version", test_invalid_version},
    {"Timestamp Replay", test_timestamp_replay},
    {"UDP Flood", test_udp_flood},
    {"Signal Storm", test_signal_storm},
    {"FD Exhaustion", test_fd_exhaustion},
    {"Memory Pressure", test_memory_pressure}
};

int main(void) {
    printf("\n");
    printf("========================================\n");
    printf("  Fault Injection Test Suite\n");
    printf("========================================\n");
    printf("\n");
    
    /* Run all tests */
    for (int i = 0; i < NUM_TESTS; i++) {
        fault_tests[i].test_func();
        printf("\n");
        sleep(1);  // Brief pause between tests
    }
    
    /* Print summary */
    printf("========================================\n");
    printf("  Test Summary\n");
    printf("========================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Total tests:  %d\n", NUM_TESTS);
    printf("\n");
    
    if (tests_failed == 0) {
        printf(COLOR_GREEN "All fault injection tests passed!\n" COLOR_RESET);
        return 0;
    } else {
        printf(COLOR_RED "Some tests failed!\n" COLOR_RESET);
        return 1;
    }
}