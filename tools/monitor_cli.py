#!/usr/bin/env python3
"""
Command-line client for Secure Monitoring Daemon
"""

import socket
import struct
import json
import time
import argparse
import sys
from datetime import datetime

class MonitorClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.session_id = None
        self.sock = None
        
    def connect(self):
        """Establish connection to daemon"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def authenticate(self, username, token):
        """Authenticate with daemon"""
        # Build authentication request
        req = struct.pack(
            '!I32s64sQI',
            1,  # version
            username.encode().ljust(32, b'\x00'),
            token.encode().ljust(64, b'\x00'),
            int(time.time()),
            12345  # nonce
        )
        
        self.sock.send(req)
        
        # Receive response
        resp = self.sock.recv(20)
        if len(resp) < 20:
            print("Authentication failed: incomplete response")
            return False
        
        status, session_id, expire_time, auth_level = struct.unpack('!IIQI', resp)
        
        if status == 0:
            self.session_id = session_id
            expire_dt = datetime.fromtimestamp(expire_time)
            print(f"Authentication successful!")
            print(f"Session ID: {session_id}")
            print(f"Auth Level: {auth_level}")
            print(f"Expires: {expire_dt}")
            return True
        else:
            print(f"Authentication failed with status: {status}")
            return False
    
    def get_cpu_stats(self):
        """Request CPU statistics"""
        cmd = struct.pack(
            '!II32sI',
            2,  # CMD_MONITOR_CPU
            5,  # interval
            b''.ljust(32, b'\x00'),
            1   # auth_level
        )
        
        self.sock.send(cmd)
        
        # Receive response
        resp_header = self.sock.recv(8)
        status, data_length = struct.unpack('!II', resp_header)
        
        if status != 0:
            print(f"Request failed with status: {status}")
            return None
        
        if data_length > 0:
            data = self.sock.recv(data_length)
            return json.loads(data.decode())
        
        return None
    
    def get_memory_stats(self):
        """Request memory statistics"""
        cmd = struct.pack(
            '!II32sI',
            3,  # CMD_MONITOR_MEM
            5,
            b''.ljust(32, b'\x00'),
            1
        )
        
        self.sock.send(cmd)
        resp_header = self.sock.recv(8)
        status, data_length = struct.unpack('!II', resp_header)
        
        if status == 0 and data_length > 0:
            data = self.sock.recv(data_length)
            return json.loads(data.decode())
        
        return None
    
    def get_network_stats(self):
        """Request network statistics"""
        cmd = struct.pack(
            '!II32sI',
            4,  # CMD_MONITOR_NET
            5,
            b''.ljust(32, b'\x00'),
            1
        )
        
        self.sock.send(cmd)
        resp_header = self.sock.recv(8)
        status, data_length = struct.unpack('!II', resp_header)
        
        if status == 0 and data_length > 0:
            data = self.sock.recv(data_length)
            return json.loads(data.decode())
        
        return None
    
    def get_io_stats(self):
        """Request I/O statistics"""
        cmd = struct.pack(
            '!II32sI',
            5,  # CMD_MONITOR_IO
            5,
            b''.ljust(32, b'\x00'),
            1
        )
        
        self.sock.send(cmd)
        resp_header = self.sock.recv(8)
        status, data_length = struct.unpack('!II', resp_header)
        
        if status == 0 and data_length > 0:
            data = self.sock.recv(data_length)
            return json.loads(data.decode())
        
        return None
    
    def disconnect(self):
        """Disconnect from daemon"""
        if self.sock:
            cmd = struct.pack('!I', 99)  # CMD_DISCONNECT
            try:
                self.sock.send(cmd)
            except:
                pass
            self.sock.close()
            print("Disconnected")
    
    def format_bytes(self, bytes_val):
        """Format bytes in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    def display_stats(self, stats):
        """Display statistics in formatted output"""
        if not stats:
            print("No statistics available")
            return
        
        print("\n" + "="*60)
        print(f"Statistics collected at: {datetime.fromtimestamp(stats.get('timestamp', 0))}")
        print("="*60)
        
        if 'cpu_usage' in stats:
            print(f"\nCPU Usage: {stats['cpu_usage']:.2f}%")
        
        if 'mem_total' in stats:
            print(f"\nMemory Statistics:")
            print(f"  Total:     {self.format_bytes(stats['mem_total'])}")
            print(f"  Free:      {self.format_bytes(stats['mem_free'])}")
            print(f"  Available: {self.format_bytes(stats['mem_available'])}")
            mem_used = stats['mem_total'] - stats['mem_available']
            mem_percent = (mem_used / stats['mem_total']) * 100
            print(f"  Used:      {self.format_bytes(mem_used)} ({mem_percent:.2f}%)")
        
        if 'net_bytes_recv' in stats:
            print(f"\nNetwork Statistics:")
            print(f"  Received:  {self.format_bytes(stats['net_bytes_recv'])}")
            print(f"  Sent:      {self.format_bytes(stats['net_bytes_sent'])}")
        
        if 'io_reads' in stats:
            print(f"\nI/O Statistics:")
            print(f"  Reads:     {stats['io_reads']}")
            print(f"  Writes:    {stats['io_writes']}")
            print(f"  Read:      {self.format_bytes(stats.get('io_read_bytes', 0))}")
            print(f"  Written:   {self.format_bytes(stats.get('io_write_bytes', 0))}")
        
        print("="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description='Secure Monitor Client')
    parser.add_argument('--host', default='localhost', help='Daemon host')
    parser.add_argument('--port', type=int, default=8888, help='Daemon port')
    parser.add_argument('--username', default='testuser', help='Username')
    parser.add_argument('--token', default='test_token', help='Auth token')
    parser.add_argument('--command', choices=['cpu', 'mem', 'net', 'io', 'all', 'monitor'],
                       default='all', help='Command to execute')
    parser.add_argument('--interval', type=int, default=5,
                       help='Update interval for monitor mode (seconds)')
    
    args = parser.parse_args()
    
    client = MonitorClient(args.host, args.port)
    
    if not client.connect():
        sys.exit(1)
    
    if not client.authenticate(args.username, args.token):
        client.disconnect()
        sys.exit(1)
    
    try:
        if args.command == 'monitor':
            # Continuous monitoring mode
            print("\nContinuous monitoring mode (Ctrl+C to exit)\n")
            while True:
                stats = {}
                
                cpu = client.get_cpu_stats()
                if cpu:
                    stats.update(cpu)
                
                mem = client.get_memory_stats()
                if mem:
                    stats.update(mem)
                
                net = client.get_network_stats()
                if net:
                    stats.update(net)
                
                io = client.get_io_stats()
                if io:
                    stats.update(io)
                
                client.display_stats(stats)
                time.sleep(args.interval)
        
        elif args.command == 'cpu':
            stats = client.get_cpu_stats()
            client.display_stats(stats)
        
        elif args.command == 'mem':
            stats = client.get_memory_stats()
            client.display_stats(stats)
        
        elif args.command == 'net':
            stats = client.get_network_stats()
            client.display_stats(stats)
        
        elif args.command == 'io':
            stats = client.get_io_stats()
            client.display_stats(stats)
        
        else:  # all
            stats = {}
            
            cpu = client.get_cpu_stats()
            if cpu:
                stats.update(cpu)
            
            mem = client.get_memory_stats()
            if mem:
                stats.update(mem)
            
            net = client.get_network_stats()
            if net:
                stats.update(net)
            
            io = client.get_io_stats()
            if io:
                stats.update(io)
            
            client.display_stats(stats)
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        client.disconnect()

if __name__ == '__main__':
    main()