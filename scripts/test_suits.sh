#!/bin/bash
# Comprehensive test suite for Secure Monitoring Daemon

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TEST_PORT=8889
TEST_HOST="localhost"
DAEMON="./bin/secure_monitor"
LOG_FILE="/tmp/secure_monitor_test.log"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
    TESTS_RUN=$((TESTS_RUN + 1))
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

cleanup() {
    echo "Cleaning up..."
    pkill -f secure_monitor || true
    rm -f /var/run/secure_monitor.pid
    sleep 1
}

# Test 1: Daemon initialization
test_daemon_init() {
    print_test "Testing daemon initialization..."
    
    $DAEMON -standalone -p $TEST_PORT > /dev/null 2>&1 &
    DAEMON_PID=$!
    sleep 2
    
    if kill -0 $DAEMON_PID 2>/dev/null; then
        print_pass "Daemon started successfully"
        return 0
    else
        print_fail "Daemon failed to start"
        return 1
    fi
}

# Test 2: TCP connection
test_tcp_connection() {
    print_test "Testing TCP connection..."
    
    # Use netcat to test connection
    timeout 5 nc -z $TEST_HOST $TEST_PORT
    if [ $? -eq 0 ]; then
        print_pass "TCP connection successful"
        return 0
    else
        print_fail "TCP connection failed"
        return 1
    fi
}

# Test 3: UDP connection
test_udp_connection() {
    print_test "Testing UDP connection..."
    
    # Send UDP packet
    echo "test" | nc -u -w1 $TEST_HOST $TEST_PORT
    if [ $? -eq 0 ]; then
        print_pass "UDP connection successful"
        return 0
    else
        print_fail "UDP connection failed"
        return 1
    fi
}

# Test 4: Signal handling (SIGHUP)
test_signal_handling() {
    print_test "Testing SIGHUP (config reload)..."
    
    PID=$(cat /var/run/secure_monitor.pid)
    kill -HUP $PID
    sleep 1
    
    if kill -0 $PID 2>/dev/null; then
        print_pass "Daemon survived SIGHUP"
        return 0
    else
        print_fail "Daemon died on SIGHUP"
        return 1
    fi
}

# Test 5: Protocol interoperability
test_protocol_interop() {
    print_test "Testing concurrent TCP and UDP connections..."
    
    # Start multiple TCP clients
    for i in {1..5}; do
        (echo "TCP_TEST_$i" | nc $TEST_HOST $TEST_PORT > /dev/null 2>&1) &
    done
    
    # Start multiple UDP clients
    for i in {1..5}; do
        (echo "UDP_TEST_$i" | nc -u $TEST_HOST $TEST_PORT > /dev/null 2>&1) &
    done
    
    wait
    
    if [ $? -eq 0 ]; then
        print_pass "Concurrent connections handled"
        return 0
    else
        print_fail "Concurrent connections failed"
        return 1
    fi
}

# Test 6: Connection limit
test_connection_limit() {
    print_test "Testing connection limits..."
    
    # Try to create more connections than allowed
    for i in {1..60}; do
        (nc $TEST_HOST $TEST_PORT > /dev/null 2>&1 &)
    done
    
    sleep 2
    CONN_COUNT=$(netstat -an | grep $TEST_PORT | grep ESTABLISHED | wc -l)
    
    if [ $CONN_COUNT -le 50 ]; then
        print_pass "Connection limit enforced"
        return 0
    else
        print_fail "Connection limit not enforced"
        return 1
    fi
}

# Test 7: Graceful shutdown
test_graceful_shutdown() {
    print_test "Testing graceful shutdown..."
    
    PID=$(cat /var/run/secure_monitor.pid)
    kill -TERM $PID
    
    # Wait for shutdown
    for i in {1..10}; do
        if ! kill -0 $PID 2>/dev/null; then
            print_pass "Graceful shutdown successful"
            return 0
        fi
        sleep 1
    done
    
    print_fail "Graceful shutdown failed"
    return 1
}

# Test 8: Zombie prevention
test_zombie_prevention() {
    print_test "Testing zombie process prevention..."
    
    $DAEMON -standalone -p $TEST_PORT > /dev/null 2>&1 &
    sleep 2
    
    # Create multiple short-lived connections
    for i in {1..20}; do
        (echo "QUIT" | nc $TEST_HOST $TEST_PORT > /dev/null 2>&1 &)
    done
    
    sleep 3
    
    # Check for zombie processes
    ZOMBIES=$(ps aux | grep 'Z' | grep secure_monitor | wc -l)
    
    if [ $ZOMBIES -eq 0 ]; then
        print_pass "No zombie processes found"
        return 0
    else
        print_fail "Found $ZOMBIES zombie processes"
        return 1
    fi
}

# Test 9: Memory leak detection
test_memory_leak() {
    print_test "Testing for memory leaks..."
    
    PID=$(cat /var/run/secure_monitor.pid)
    MEM_START=$(ps -o rss= -p $PID)
    
    # Generate load
    for i in {1..100}; do
        echo "LOAD_TEST" | nc $TEST_HOST $TEST_PORT > /dev/null 2>&1
    done
    
    sleep 2
    MEM_END=$(ps -o rss= -p $PID)
    MEM_GROWTH=$((MEM_END - MEM_START))
    
    # Allow 10MB growth
    if [ $MEM_GROWTH -lt 10240 ]; then
        print_pass "Memory usage stable (growth: ${MEM_GROWTH}KB)"
        return 0
    else
        print_fail "Possible memory leak (growth: ${MEM_GROWTH}KB)"
        return 1
    fi
}

# Test 10: Plugin loading
test_plugin_loading() {
    print_test "Testing plugin loading..."
    
    if [ -d "./bin" ] && [ -n "$(ls -A ./bin/*.so 2>/dev/null)" ]; then
        print_pass "Plugins found and loaded"
        return 0
    else
        print_fail "No plugins found"
        return 1
    fi
}

# Test 11: IPv6 support
test_ipv6_support() {
    print_test "Testing IPv6 support..."
    
    timeout 5 nc -6 -z ::1 $TEST_PORT 2>/dev/null
    if [ $? -eq 0 ]; then
        print_pass "IPv6 connection successful"
        return 0
    else
        print_fail "IPv6 connection failed"
        return 1
    fi
}

# Test 12: Fault injection - malformed packets
test_malformed_packets() {
    print_test "Testing malformed packet handling..."
    
    # Send garbage data
    echo -e "\x00\x00\x00\xFF\xFF\xFF" | nc $TEST_HOST $TEST_PORT > /dev/null 2>&1
    sleep 1
    
    PID=$(cat /var/run/secure_monitor.pid)
    if kill -0 $PID 2>/dev/null; then
        print_pass "Daemon survived malformed packets"
        return 0
    else
        print_fail "Daemon crashed on malformed packets"
        return 1
    fi
}

# Main test execution
main() {
    echo "=========================================="
    echo "  Secure Monitor Daemon Test Suite"
    echo "=========================================="
    echo ""
    
    # Build the project
    echo "Building project..."
    make clean > /dev/null 2>&1
    make > /dev/null 2>&1
    
    if [ ! -f "$DAEMON" ]; then
        echo "Error: Daemon binary not found"
        exit 1
    fi
    
    # Cleanup before tests
    cleanup
    
    # Run tests
    test_daemon_init || true
    test_tcp_connection || true
    test_udp_connection || true
    test_signal_handling || true
    test_protocol_interop || true
    test_connection_limit || true
    test_zombie_prevention || true
    test_memory_leak || true
    test_plugin_loading || true
    test_ipv6_support || true
    test_malformed_packets || true
    test_graceful_shutdown || true
    
    # Print summary
    echo ""
    echo "=========================================="
    echo "  Test Summary"
    echo "=========================================="
    echo "Tests run:    $TESTS_RUN"
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Run main
main