#!/usr/bin/env python3
"""
Port Scanner & Banner Grabber
Educational use only. Do not scan systems you don't own or have permission to test.
"""

import socket
import argparse
import concurrent.futures
import sys
from datetime import datetime

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080]

socket.setdefaulttimeout(2.0)

def grab_banner(ip, port):
    """Try to connect and read a short banner from the service."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        try:
            # Try a small recv - many services send a banner immediately (SMTP, FTP, etc.)
            banner = s.recv(1024)
            if banner:
                return banner.decode(errors='ignore').strip()
        except socket.timeout:
            return ""
        finally:
            s.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None  # port closed / unreachable
    return ""

def scan_port(ip, port):
    """Return tuple (port, state, banner) where state is True=open, False=closed."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port)
                return (port, True, banner if banner is not None else "")
            else:
                return (port, False, "")
    except Exception as e:
        return (port, False, "")

def parse_target(target):
    """Support single IP/hostname or simple start-end port syntax handled elsewhere."""
    try:
        # let socket.gethostbyname resolve hostnames
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        raise ValueError(f"Unable to resolve host: {target}")

def run_scan(target, ports, workers):
    ip = parse_target(target)
    print(f"Scanning {target} ({ip})")
    start = datetime.now()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            try:
                port, is_open, banner = fut.result()
                if is_open:
                    open_ports.append((port, banner))
                    print(f"[+] {port}/tcp OPEN     {(' - ' + banner) if banner else ''}")
            except Exception as exc:
                # be robust: report but continue
                print(f"[!] Error scanning port {p}: {exc}", file=sys.stderr)

    duration = (datetime.now() - start).total_seconds()
    print(f"\nScan finished in {duration:.2f} seconds. Open ports: {len(open_ports)}")
    if open_ports:
        print("Detailed results:")
        for port, banner in sorted(open_ports):
            print(f" - {port}/tcp  {('Banner: ' + banner) if banner else '(no banner)'}")

def parse_ports(port_arg):
    """
    Accept formats:
    - comma separated: 22,80,443
    - range: 1-1024
    - single number: 80
    - empty -> DEFAULT_PORTS
    """
    if not port_arg:
        return DEFAULT_PORTS
    ports = set()
    for part in port_arg.split(','):
        part = part.strip()
        if '-' in part:
            lo, hi = part.split('-', 1)
            lo, hi = int(lo), int(hi)
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def main():
    parser = argparse.ArgumentParser(description="Port Scanner & Banner Grabber (educational use only).")
    parser.add_argument("target", help="Target hostname or IP (e.g., example.com or 192.168.1.10)")
    parser.add_argument("-p", "--ports", help="Ports (e.g. 22,80,443 or 1-1024). Default common ports.")
    parser.add_argument("-w", "--workers", help="Concurrency (threads). Default 50.", type=int, default=50)
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except Exception as e:
        print("Invalid ports:", e, file=sys.stderr)
        sys.exit(1)

    try:
        run_scan(args.target, ports, args.workers)
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
