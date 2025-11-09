#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define TEST_HOST "127.0.0.1"
#define TEST_PORT 8889

/* Test authentication protocol */
int test_authentication(void) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct auth_request req;
    struct auth_response resp;
    
    printf("Testing authentication protocol...\n");
    
    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    /* Connect to server */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    
    /* Build authentication request */
    memset(&req, 0, sizeof(req));
    req.version = htonl(1);
    strncpy(req.username, "testuser", sizeof(req.username) - 1);
    strncpy(req.token, "test_token_12345", sizeof(req.token) - 1);
    req.timestamp = htobe64(time(NULL));
    req.nonce = htonl(12345);
    
    /* Send request */
    if (send(sockfd, &req, sizeof(req), 0) < 0) {
        perror("send");
        close(sockfd);
        return -1;
    }
    
    /* Receive response */
    if (recv(sockfd, &resp, sizeof(resp), 0) < 0) {
        perror("recv");
        close(sockfd);
        return -1;
    }
    
    /* Check response */
    if (ntohl(resp.status) == 0) {
        printf("Authentication successful! Session ID: %u\n",
               ntohl(resp.session_id));
        close(sockfd);
        return 0;
    } else {
        printf("Authentication failed! Status: %u\n", ntohl(resp.status));
        close(sockfd);
        return -1;
    }
}

/* Test monitoring commands */
int test_monitoring(void) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct monitor_cmd cmd;
    struct monitor_response resp_header;
    char buffer[4096];
    
    printf("Testing monitoring protocol...\n");
    
    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    /* Connect to server */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    
    /* Build monitoring command */
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd_type = htonl(2); /* CMD_MONITOR_CPU */
    cmd.interval = htonl(5);
    cmd.auth_level = htonl(1);
    
    /* Send command */
    if (send(sockfd, &cmd, sizeof(cmd), 0) < 0) {
        perror("send");
        close(sockfd);
        return -1;
    }
    
    /* Receive response header */
    if (recv(sockfd, &resp_header, sizeof(resp_header), 0) < 0) {
        perror("recv");
        close(sockfd);
        return -1;
    }
    
    /* Receive response data */
    uint32_t data_len = ntohl(resp_header.data_length);
    if (data_len > 0 && data_len < sizeof(buffer)) {
        if (recv(sockfd, buffer, data_len, 0) < 0) {
            perror("recv data");
            close(sockfd);
            return -1;
        }
        buffer[data_len] = '\0';
        printf("Received monitoring data:\n%s\n", buffer);
    }
    
    close(sockfd);
    return 0;
}

/* Test UDP protocol */
int test_udp_protocol(void) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct monitor_cmd cmd;
    char buffer[1024];
    socklen_t addr_len;
    
    printf("Testing UDP protocol...\n");
    
    /* Create UDP socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Build server address */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, TEST_HOST, &serv_addr.sin_addr);
    
    /* Build command */
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd_type = htonl(3); /* CMD_MONITOR_MEM */
    cmd.interval = htonl(5);
    
    /* Send datagram */
    if (sendto(sockfd, &cmd, sizeof(cmd), 0,
              (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("sendto");
        close(sockfd);
        return -1;
    }
    
    /* Receive response */
    addr_len = sizeof(serv_addr);
    ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                        (struct sockaddr *)&serv_addr, &addr_len);
    
    if (n > 0) {
        printf("Received UDP response (%zd bytes)\n", n);
        close(sockfd);
        return 0;
    } else {
        printf("No UDP response received\n");
        close(sockfd);
        return -1;
    }
}

int main(void) {
    int failures = 0;
    
    printf("===========================================\n");
    printf("  Protocol Test Suite\n");
    printf("===========================================\n\n");
    
    if (test_authentication() < 0) {
        failures++;
    }
    
    sleep(1);
    
    if (test_monitoring() < 0) {
        failures++;
    }
    
    sleep(1);
    
    if (test_udp_protocol() < 0) {
        failures++;
    }
    
    printf("\n===========================================\n");
    if (failures == 0) {
        printf("All protocol tests passed!\n");
        return 0;
    } else {
        printf("%d protocol test(s) failed!\n", failures);
        return 1;
    }
}