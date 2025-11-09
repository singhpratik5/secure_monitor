#!/bin/bash
# Stress testing tool for Secure Monitoring Daemon

DAEMON_HOST="localhost"
DAEMON_PORT=8888
NUM_CLIENTS=100
DURATION=60
TEST_TYPE="mixed"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            DAEMON_HOST="$2"
            shift 2
            ;;
        --port)
            DAEMON_PORT="$2"
            shift 2
            ;;
        --clients)
            NUM_CLIENTS="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --type)
            TEST_TYPE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "========================================="
echo "  Stress Test
echo "  Stress Test Configuration"
echo "========================================="
echo "Host:           $DAEMON_HOST"
echo "Port:           $DAEMON_PORT"
echo "Clients:        $NUM_CLIENTS"
echo "Duration:       $DURATION seconds"
echo "Test Type:      $TEST_TYPE"
echo "========================================="
echo ""

# Create temporary directory for results
RESULTS_DIR="/tmp/secure_monitor_stress_$$"
mkdir -p "$RESULTS_DIR"

# Function to run TCP stress test
tcp_stress() {
    local client_id=$1
    local output_file="$RESULTS_DIR/tcp_client_${client_id}.log"
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    local request_count=0
    local error_count=0
    
    while [ $(date +%s) -lt $end_time ]; do
        # Send request and measure response time
        start=$(date +%s.%N)
        
        echo -e "\x00\x00\x00\x02" | nc -w 2 $DAEMON_HOST $DAEMON_PORT > /dev/null 2>&1
        result=$?
        
        end=$(date +%s.%N)
        response_time=$(echo "$end - $start" | bc)
        
        if [ $result -eq 0 ]; then
            request_count=$((request_count + 1))
            echo "$response_time" >> "$output_file"
        else
            error_count=$((error_count + 1))
        fi
        
        sleep 0.1
    done
    
    echo "$request_count,$error_count" > "$RESULTS_DIR/tcp_summary_${client_id}.txt"
}

# Function to run UDP stress test
udp_stress() {
    local client_id=$1
    local output_file="$RESULTS_DIR/udp_client_${client_id}.log"
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    local request_count=0
    
    while [ $(date +%s) -lt $end_time ]; do
        # Send UDP datagram
        echo -e "\x00\x00\x00\x03" | nc -u -w 1 $DAEMON_HOST $DAEMON_PORT > /dev/null 2>&1
        request_count=$((request_count + 1))
        sleep 0.05
    done
    
    echo "$request_count,0" > "$RESULTS_DIR/udp_summary_${client_id}.txt"
}

# Function to run mixed stress test
mixed_stress() {
    local client_id=$1
    
    if [ $((client_id % 2)) -eq 0 ]; then
        tcp_stress $client_id
    else
        udp_stress $client_id
    fi
}

# Launch stress test clients
echo "Starting stress test..."
START_TIME=$(date +%s)

for i in $(seq 1 $NUM_CLIENTS); do
    case $TEST_TYPE in
        tcp)
            tcp_stress $i &
            ;;
        udp)
            udp_stress $i &
            ;;
        mixed)
            mixed_stress $i &
            ;;
        *)
            echo "Unknown test type: $TEST_TYPE"
            exit 1
            ;;
    esac
    
    # Brief delay between client launches to avoid overwhelming the system
    sleep 0.01
done

echo "All clients launched. Waiting for completion..."

# Wait for all background jobs
wait

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "========================================="
echo "  Stress Test Results"
echo "========================================="
echo "Test completed in $ELAPSED seconds"
echo ""

# Analyze results
total_requests=0
total_errors=0
total_response_time=0
response_count=0

# Aggregate TCP results
for file in "$RESULTS_DIR"/tcp_summary_*.txt; do
    if [ -f "$file" ]; then
        read requests errors < "$file"
        total_requests=$((total_requests + requests))
        total_errors=$((total_errors + errors))
    fi
done

for file in "$RESULTS_DIR"/tcp_client_*.log; do
    if [ -f "$file" ]; then
        while read -r time; do
            total_response_time=$(echo "$total_response_time + $time" | bc)
            response_count=$((response_count + 1))
        done < "$file"
    fi
done

# Aggregate UDP results
for file in "$RESULTS_DIR"/udp_summary_*.txt; do
    if [ -f "$file" ]; then
        read requests errors < "$file"
        total_requests=$((total_requests + requests))
        total_errors=$((total_errors + errors))
    fi
done

# Calculate statistics
if [ $response_count -gt 0 ]; then
    avg_response_time=$(echo "scale=3; $total_response_time / $response_count" | bc)
else
    avg_response_time=0
fi

success_rate=0
if [ $total_requests -gt 0 ]; then
    success_rate=$(echo "scale=2; (($total_requests - $total_errors) / $total_requests) * 100" | bc)
fi

requests_per_sec=$(echo "scale=2; $total_requests / $ELAPSED" | bc)

echo "Total Requests:        $total_requests"
echo "Successful Requests:   $((total_requests - total_errors))"
echo "Failed Requests:       $total_errors"
echo "Success Rate:          ${success_rate}%"
echo "Requests/Second:       $requests_per_sec"
echo "Avg Response Time:     ${avg_response_time}s"
echo ""

# Check daemon status
echo "Daemon Status:"
if kill -0 $(cat /var/run/secure_monitor.pid 2>/dev/null) 2>/dev/null; then
    echo "  Status: Running"
    
    # Get daemon resource usage
    PID=$(cat /var/run/secure_monitor.pid)
    CPU=$(ps -p $PID -o %cpu= | tr -d ' ')
    MEM=$(ps -p $PID -o %mem= | tr -d ' ')
    RSS=$(ps -p $PID -o rss= | tr -d ' ')
    
    echo "  CPU Usage:   ${CPU}%"
    echo "  Memory:      ${MEM}% (${RSS}KB)"
else
    echo "  Status: NOT RUNNING (CRASHED?)"
fi

echo "========================================="
echo ""

# Cleanup
rm -rf "$RESULTS_DIR"

# Exit with error if success rate is too low
if [ $(echo "$success_rate < 95" | bc) -eq 1 ]; then
    echo "WARNING: Success rate below 95%"
    exit 1
fi

echo "Stress test completed successfully!"
exit 0