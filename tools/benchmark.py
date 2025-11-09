#!/usr/bin/env python3
"""
Comprehensive benchmarking tool for Secure Monitoring Daemon
"""

import socket
import struct
import time
import statistics
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

class Benchmark:
    def __init__(self, host, port, num_requests, num_threads):
        self.host = host
        self.port = port
        self.num_requests = num_requests
        self.num_threads = num_threads
        self.results = []
        
    def single_request(self, request_type='tcp'):
        """Execute a single request and measure latency"""
        start_time = time.time()
        
        try:
            if request_type == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.host, self.port))
                
                # Send simple command
                cmd = struct.pack('!II32sI', 2, 5, b'', 1)
                sock.send(cmd)
                
                # Receive response
                resp = sock.recv(8)
                if len(resp) == 8:
                    status, data_len = struct.unpack('!II', resp)
                    if data_len > 0:
                        data = sock.recv(data_len)
                
                sock.close()
                
            else:  # UDP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                cmd = struct.pack('!II32sI', 3, 5, b'', 1)
                sock.sendto(cmd, (self.host, self.port))
                
                # Receive response
                data, addr = sock.recvfrom(4096)
                sock.close()
            
            end_time = time.time()
            latency = (end_time - start_time) * 1000  # Convert to ms
            
            return {'success': True, 'latency': latency}
            
        except Exception as e:
            end_time = time.time()
            latency = (end_time - start_time) * 1000
            return {'success': False, 'latency': latency, 'error': str(e)}
    
    def run_benchmark(self, protocol='tcp'):
        """Run benchmark with specified protocol"""
        print(f"\nRunning {protocol.upper()} benchmark...")
        print(f"Requests: {self.num_requests}, Threads: {self.num_threads}")
        
        self.results = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = [executor.submit(self.single_request, protocol) 
                      for _ in range(self.num_requests)]
            
            completed = 0
            for future in as_completed(futures):
                result = future.result()
                self.results.append(result)
                completed += 1
                
                if completed % 100 == 0:
                    print(f"Progress: {completed}/{self.num_requests}", end='\r')
        
        end_time = time.time()
        total_time = end_time - start_time
        
        print(f"\nCompleted in {total_time:.2f} seconds")
        
        return self.analyze_results(total_time)
    
    def analyze_results(self, total_time):
        """Analyze benchmark results"""
        successful = [r for r in self.results if r['success']]
        failed = [r for r in self.results if not r['success']]
        
        if not successful:
            print("All requests failed!")
            return None
        
        latencies = [r['latency'] for r in successful]
        
        stats = {
            'total_requests': len(self.results),
            'successful': len(successful),
            'failed': len(failed),
            'success_rate': (len(successful) / len(self.results)) * 100,
            'total_time': total_time,
            'requests_per_sec': len(self.results) / total_time,
            'min_latency': min(latencies),
            'max_latency': max(latencies),
            'avg_latency': statistics.mean(latencies),
            'median_latency': statistics.median(latencies),
            'stdev_latency': statistics.stdev(latencies) if len(latencies) > 1 else 0,
        }
        
        # Calculate percentiles
        sorted_latencies = sorted(latencies)
        stats['p50'] = sorted_latencies[int(len(sorted_latencies) * 0.50)]
        stats['p90'] = sorted_latencies[int(len(sorted_latencies) * 0.90)]
        stats['p95'] = sorted_latencies[int(len(sorted_latencies) * 0.95)]
        stats['p99'] = sorted_latencies[int(len(sorted_latencies) * 0.99)]
        
        return stats
    
    def print_results(self, stats):
        """Print formatted results"""
        if not stats:
            return
        
        print("\n" + "="*60)
        print("  Benchmark Results")
        print("="*60)
        print(f"\nRequest Statistics:")
        print(f"  Total Requests:    {stats['total_requests']}")
        print(f"  Successful:        {stats['successful']}")
        print(f"  Failed:            {stats['failed']}")
        print(f"  Success Rate:      {stats['success_rate']:.2f}%")
        print(f"\nPerformance:")
        print(f"  Total Time:        {stats['total_time']:.2f}s")
        print(f"  Requests/Second:   {stats['requests_per_sec']:.2f}")
        print(f"\nLatency (ms):")
        print(f"  Min:               {stats['min_latency']:.2f}")
        print(f"  Max:               {stats['max_latency']:.2f}")
        print(f"  Average:           {stats['avg_latency']:.2f}")
        print(f"  Median:            {stats['median_latency']:.2f}")
        print(f"  Std Deviation:     {stats['stdev_latency']:.2f}")
        print(f"\nPercentiles (ms):")
        print(f"  50th percentile:   {stats['p50']:.2f}")
        print(f"  90th percentile:   {stats['p90']:.2f}")
        print(f"  95th percentile:   {stats['p95']:.2f}")
        print(f"  99th percentile:   {stats['p99']:.2f}")
        print("="*60 + "\n")
    
    def save_results(self, stats, filename):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Benchmark Secure Monitor Daemon')
    parser.add_argument('--host', default='localhost', help='Daemon host')
    parser.add_argument('--port', type=int, default=8888, help='Daemon port')
    parser.add_argument('--requests', type=int, default=1000, 
                       help='Number of requests')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of concurrent threads')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'both'],
                       default='both', help='Protocol to test')
    parser.add_argument('--output', help='Output file for results (JSON)')
    
    args = parser.parse_args()
    
    print("="*60)
    print("  Secure Monitor Daemon Benchmark")
    print("="*60)
    
    benchmark = Benchmark(args.host, args.port, args.requests, args.threads)
    
    results = {}
    
    if args.protocol in ['tcp', 'both']:
        tcp_stats = benchmark.run_benchmark('tcp')
        if tcp_stats:
            benchmark.print_results(tcp_stats)
            results['tcp'] = tcp_stats
    
    if args.protocol in ['udp', 'both']:
        udp_stats = benchmark.run_benchmark('udp')
        if udp_stats:
            benchmark.print_results(udp_stats)
            results['udp'] = udp_stats
    
    # Compare protocols if both were tested
    if 'tcp' in results and 'udp' in results:
        print("\n" + "="*60)
        print("  Protocol Comparison")
        print("="*60)
        print(f"\nTCP vs UDP:")
        print(f"  Requests/sec:  TCP {results['tcp']['requests_per_sec']:.2f} | "
              f"UDP {results['udp']['requests_per_sec']:.2f}")
        print(f"  Avg Latency:   TCP {results['tcp']['avg_latency']:.2f}ms | "
              f"UDP {results['udp']['avg_latency']:.2f}ms")
        print(f"  Success Rate:  TCP {results['tcp']['success_rate']:.2f}% | "
              f"UDP {results['udp']['success_rate']:.2f}%")
        print("="*60 + "\n")
    
    if args.output:
        benchmark.save_results(results, args.output)

if __name__ == '__main__':
    main()