#!/bin/bash
### BEGIN INIT INFO
# Provides:          secure_monitor
# Required-Start:    $network $syslog
# Required-Stop:     $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Secure Monitoring Daemon
# Description:       Multi-protocol secure monitoring daemon with plugin support
### END INIT INFO

# Configuration
NAME=secure_monitor
DAEMON=/usr/local/bin/secure_monitor
PIDFILE=/var/run/secure_monitor.pid
DAEMON_ARGS="-standalone -p 8888"
USER=root

# Read configuration variable file if present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions
. /lib/lsb/init-functions

# Function to check if daemon is running
is_running() {
    [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null
}

# Function to start the daemon
do_start() {
    if is_running; then
        echo "Daemon is already running"
        return 1
    fi
    
    echo "Starting $NAME..."
    $DAEMON $DAEMON_ARGS
    
    # Wait for daemon to start
    for i in {1..10}; do
        if is_running; then
            echo "$NAME started successfully"
            return 0
        fi
        sleep 1
    done
    
    echo "Failed to start $NAME"
    return 2
}

# Function to stop the daemon
do_stop() {
    if ! is_running; then
        echo "Daemon is not running"
        return 1
    fi
    
    echo "Stopping $NAME..."
    PID=$(cat "$PIDFILE")
    kill -TERM $PID 2>/dev/null
    
    # Wait for daemon to stop
    for i in {1..30}; do
        if ! is_running; then
            rm -f "$PIDFILE"
            echo "$NAME stopped successfully"
            return 0
        fi
        sleep 1
    done
    
    # Force kill if still running
    echo "Forcing $NAME to stop..."
    kill -KILL $PID 2>/dev/null
    rm -f "$PIDFILE"
    return 2
}

# Function to reload configuration
do_reload() {
    if ! is_running; then
        echo "Daemon is not running"
        return 1
    fi
    
    echo "Reloading $NAME configuration..."
    PID=$(cat "$PIDFILE")
    kill -HUP $PID
    echo "$NAME configuration reloaded"
    return 0
}

# Function to show status
do_status() {
    if is_running; then
        PID=$(cat "$PIDFILE")
        echo "$NAME is running (PID: $PID)"
        
        # Show statistics
        if [ -f /proc/$PID/status ]; then
            echo "Memory usage: $(grep VmRSS /proc/$PID/status | awk '{print $2 $3}')"
            echo "Threads: $(grep Threads /proc/$PID/status | awk '{print $2}')"
        fi
        return 0
    else
        echo "$NAME is not running"
        return 3
    fi
}

# Main command processing
case "$1" in
    start)
        do_start
        ;;
    stop)
        do_stop
        ;;
    restart)
        do_stop
        sleep 2
        do_start
        ;;
    reload|force-reload)
        do_reload
        ;;
    status)
        do_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|status}"
        exit 3
        ;;
esac

exit $?