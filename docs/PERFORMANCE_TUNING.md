# Performance Tuning Guide

## System-Level Optimizations

### Kernel Parameters

Add to `/etc/sysctl.conf`:

```bash
# Increase maximum number of open files
fs.file-max = 65536

# TCP tuning
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Memory management
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2

# Network buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

Apply changes:

bash
sudo sysctl -p
File Descriptor Limits
Add to /etc/security/limits.conf:

text
*   soft    nofile  65536
*   hard    nofile  65536
CPU Affinity
Pin daemon to specific CPU cores:

bash
taskset -c 0-3 /usr/local/bin/secure_monitor -standalone
Application-Level Optimizations
Connection Pooling
Modify monitor.conf:

conf
# Increase connection limits
max_connections = 500
connection_timeout = 30

# Reduce rate limit window
rate_limit = 1000
Buffer Sizes
Optimize socket buffers in code:

c
int sndbuf = 262144;  // 256KB
int rcvbuf = 262144;
setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
Plugin Optimization
Reduce plugin collection frequency:


c
uint32_t* plugin_get_interval(void