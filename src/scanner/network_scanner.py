import nmap
import ipaddress
import asyncio
import concurrent.futures
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from logger_config import setup_logger

logs = 'logs/scanner.log'
logger = setup_logger(__name__, log_file_path=logs)

try:
    from pythonping import ping
    PING_AVAILABLE = True
except ImportError:
    PING_AVAILABLE = False
    logger.warning("pythonping not available. Install with: pip install pythonping")

# Import our database module
from src.database.database import NetworkDatabase

@dataclass
class ScanResult:
    """Results from a network scan operation."""
    network_cidr: str
    scan_start: datetime
    scan_end: datetime
    live_hosts_found: int
    new_devices: int
    devices_needing_full_scan: int
    total_ports_discovered: int
    errors: List[str]
    performance_stats: Dict[str, float]

@dataclass
class HostScanResult:
    """Results from scanning a single host."""
    ip_address: str
    is_alive: bool
    ports: List[Dict]
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    scan_error: Optional[str] = None
    scan_duration: float = 0.0


class OptimizedNetworkScanner:
    """
    High-performance network scanner using async pings and threaded Nmap scans.
    
    This scanner optimizes for real-world enterprise networks by:
    1. Using async pings for fast host discovery
    2. Threading Nmap scans for parallel port scanning
    3. Auto-configuring thread counts based on network size
    4. Maintaining smart scan logic with performance optimization
    """

    def __init__(self, database: NetworkDatabase, max_threads: Optional[int] = None):
        """
        Initialize the optimized network scanner.
        
        Args:
            database: NetworkDatabase instance for storing results
            max_threads: Maximum threads to use (auto-calculated if None)
        """
        self.db = database
        self.max_threads = max_threads
        self.scan_timeout = 600  # 5 minutes per host max
        self.ping_timeout = 3    # 3 seconds per ping
        self.ping_count = 1      # Single ping per host for speed
        
        # Thread-safe Nmap instances (one per thread)
        self._nmap_instances = {}
        self._lock = threading.Lock()
        
        logger.info(f"OptimizedNetworkScanner initialized (max_threads: {max_threads})")

    def _get_nmap_instance(self) -> nmap.PortScanner:
        """Get thread-local Nmap instance."""
        thread_id =  threading.current_thread().ident

        if thread_id not in self._nmap_instances:
            with self._lock:
                if thread_id not in self._nmap_instances:
                    self._nmap_instances[thread_id] = nmap.PortScanner()

        return self._nmap_instances[thread_id]
    
    def _calculate_thread_count(self, host_count: int) -> int:
        """
        Calculate optimal thread count based on network size.
        
        Args:
            host_count: Number of hosts to scan
            
        Returns:
            Optimal number of threads
        """
        if self.max_threads:
            return min(self.max_threads, host_count)
        
        # Auto-calculate based on host count
        if host_count <= 5:
            return 2
        elif host_count <= 20:
            return 5
        elif host_count <= 50:
            return 10
        elif host_count <= 100:
            return 15
        else:
            return 20

    async def ping_host_async(self, ip_address: str) -> Tuple[str, bool, Optional[str]]:
        """
        Asynchronously ping a single host.
        
        Args:
            ip_address: IP address to ping
            
        Returns:
            Tuple of (ip_address, is_alive, error_message)
        """
        try:
            if not PING_AVAILABLE:
                # Fallback to subprocess ping if pythonping not available
                import subprocess
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(self.ping_timeout), ip_address],
                    capture_output=True,
                    timeout=self.ping_timeout + 1
                )
                return (ip_address, result.returncode == 0, None)
            
            # Use pythonping for async ping
            loop = asyncio.get_event_loop()

            # Run ping in thread pool to avoid blocking
            def do_ping():
                try:
                    response = ping(ip_address, count=self.ping_count, timeout=self.ping_timeout)
                    return response.success()
                except Exception as e:
                    logger.debug(f"Ping failed for {ip_address}: {e}")
                    return False
                
            with ThreadPoolExecutor(max_workers=1) as executor:
                is_alive = await loop.run_in_executor(executor, do_ping)

            return (ip_address, is_alive, None)
        
        except Exception as e:
            error_msg = f"Ping error for {ip_address}: {str(e)}"
            logger.debug(error_msg)
            return (ip_address, False, error_msg)
        
    async def discover_live_hosts(self, network_cidr: str) -> Tuple[List[str], List[str]]:
        """
        Discover live hosts using async pings with graceful error handling.
        
        Args:
            network_cidr: Network range to scan
            
        Returns:
            Tuple of (live_hosts, error_messages)
        """
        try:
            logger.info(f"Starting async host discovery for {network_cidr}")
            discovery_start = time.time()

            # Generate list of IPs to ping
            network = ipaddress.IPv4Network(network_cidr, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]

            if len(ip_list) > 1000:
                logger.warning(f"Large network detected ({len(ip_list)} hosts). "
                              "Consider scanning in smaller chunks for better performance.")
                
            # Create ping tasks
            ping_tasks = [self.ping_host_async(ip) for ip in ip_list]

            # Execute all pings concurrently
            ping_results = await asyncio.gather(*ping_tasks, return_exceptions=True)

            # Process results
            live_hosts = []
            errors = []

            for result in ping_results:
                if isinstance(result, Exception):
                    errors.append(f"Ping task failed: {str(result)}")
                    continue

                ip, is_alive, error = result
                if error:
                    errors.append(error)
                elif is_alive:
                    live_hosts.append(ip)

            discovery_duration = time.time() - discovery_start
            logger.info(f"Async host discovery completed in {discovery_duration:.2f}s: "
                       f"{len(live_hosts)} live hosts found out of {len(ip_list)} total")
            
            # Sort IPs for consistent processing order
            live_hosts.sort(key=lambda ip: ipaddress.IPv4Address(ip))
            
            return live_hosts, errors
        
        except Exception as e:
            error_msg = f"Host discovery failed for {network_cidr}: {str(e)}"
            logger.error(error_msg)
            return [], [error_msg]
        
    def scan_device_ports(self, ip_address: str, scan_type: str = 'quick') -> HostScanResult:
        """
        Thread-safe version of device port scanning.
        
        This method is designed to be called from multiple threads simultaneously.
        
        Args:
            ip_address: IP address to scan
            scan_type: 'quick' or 'full'
            
        Returns:
            HostScanResult with discovered ports and services
        """
        nm = self._get_nmap_instance()  # Thread-local Nmap instance

        try:
            logger.debug(f"[Thread-{threading.current_thread().ident}] Scanning {ip_address} (type: {scan_type})")

            if scan_type == 'full':
                nmap_args = '-sV -sC --version-all -p- -T4'
                timeout = self.scan_timeout
            else:
                nmap_args = '-sV --top-ports 1000 -T4'
                timeout = 60

            # Perform the scan
            scan_start = time.time()
            nm.scan(hosts=ip_address, arguments=nmap_args, timeout=timeout)
            scan_duration = time.time() - scan_start

            # Check if host responded
            if ip_address not in nm.all_hosts():
                logger.debug(f"Host {ip_address} did not respond to port scan")
                return HostScanResult(
                    ip_address=ip_address,
                    is_alive=False,
                    ports=[],
                    scan_error="Host did not respond to port scan",
                    scan_duration=scan_duration
                )
        
            # Process scan results
            host_info = nm[ip_address]

            hostname = None
            mac_address = None

            if 'hostnames' in host_info and host_info['hostnames']:
                hostname = host_info['hostnames'][0]['name']
            
            if 'addresses' in host_info and 'mac' in host_info['addresses']:
                mac_address = host_info['addresses']['mac']

            ports = []
            for protocol in host_info.all_protocols():
                ports_dict = host_info[protocol]

                for port_num, port_info in ports_dict.items():
                    #logger.debug(f"Raw port_info for {ip_address}:{port_num}: {port_info}")
                    if port_info['state'] == 'open':
                        port_data = {
                            'port_number': port_num,
                            'protocol': protocol,
                            'state': port_info['state'],
                            'service_name': port_info.get('name', ''),
                            'service_version': port_info.get('version', ''),
                            'service_product': port_info.get('product', ''),
                            'service_extrainfo': port_info.get('extrainfo', ''),
                            'service_cpe': port_info.get('cpe', 'blank'),
                            'confidence': port_info.get('conf', '')
                        }
                        #logger.debug(f"Raw port_data for {ip_address}:{port_num}: {port_data}")
                        ports.append(port_data)
                
            logger.debug(f"[Thread-{threading.current_thread().ident}] "
                        f"Scan completed for {ip_address} in {scan_duration:.1f}s: {len(ports)} open ports")
            
            return HostScanResult(
                ip_address=ip_address,
                is_alive=True,
                ports=ports,
                hostname=hostname,
                mac_address=mac_address,
                scan_duration=scan_duration
            )

        except Exception as e:
            error_msg = f"Port scan failed for {ip_address}: {str(e)}"
            logger.error(error_msg)
            return HostScanResult(
                ip_address=ip_address,
                is_alive=False,
                ports=[],
                scan_error=error_msg,
                scan_duration=time.time() - scan_start if 'scan_start' in locals() else 0
            )
        
    async def scan_network_optimized(self, network_cidr: str, network_id: int) -> ScanResult:
        """
        Perform optimized network scan using async pings and threaded Nmap scans.
        
        This is the main method that implements your hybrid approach:
        1. Async ping discovery
        2. Threaded port scanning
        3. Smart scan logic maintained
        
        Args:
            network_cidr: Network to scan
            network_id: Database ID of the network
            
        Returns:
            ScanResult with performance statistics
        """
        scan_start = datetime.now()
        errors = []
        new_devices = 0
        devices_needing_full_scan = 0
        total_ports = 0
        
        # Performance tracking
        perf_stats = {
            'discovery_time': 0.0,
            'scanning_time': 0.0,
            'database_time': 0.0
        }
        
        logger.info(f"Starting optimized network scan of {network_cidr}")
        
        try:
            # Phase 1: Async Host Discovery
            discovery_start = time.time()
            live_hosts, discovery_errors = await self.discover_live_hosts(network_cidr)
            perf_stats['discovery_time'] = time.time() - discovery_start
            
            errors.extend(discovery_errors)
            
            if not live_hosts:
                logger.warning("No live hosts found")
                return ScanResult(
                    network_cidr=network_cidr,
                    scan_start=scan_start,
                    scan_end=datetime.now(),
                    live_hosts_found=0,
                    new_devices=0,
                    devices_needing_full_scan=0,
                    total_ports_discovered=0,
                    errors=errors,
                    performance_stats=perf_stats
                )
            
            # Phase 2: Threaded Port Scanning with Smart Logic
            scanning_start = time.time()
            thread_count = self._calculate_thread_count(len(live_hosts))
            logger.info(f"Using {thread_count} threads for scanning {len(live_hosts)} hosts")
            
            # Prepare scanning tasks
            scan_tasks = []
            
            # First, classify all devices (sequential for database safety)
            db_start = time.time()
            device_scan_plan = {}  # ip -> (device_id, scan_type)
            
            for ip in live_hosts:
                existing_device = self.db.find_device_by_ip(ip)
                
                if existing_device is None:
                    # New device - add to database and plan full scan
                    device_id = self.db.add_or_update_device(network_id, ip)
                    device_scan_plan[ip] = (device_id, 'full')
                    new_devices += 1
                else:
                    # Known device - plan quick scan first
                    device_scan_plan[ip] = (existing_device.device_id, 'quick')
            
            perf_stats['database_time'] += time.time() - db_start
            
            # Execute initial scans in parallel (both quick scans and full scans for new devices)
            initial_scan_futures = {}
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                for ip, (device_id, scan_type) in device_scan_plan.items():
                    if scan_type == 'quick':
                        future = executor.submit(self.scan_device_ports, ip, 'quick')
                        initial_scan_futures[future] = (ip, device_id, 'quick')
                    else:
                        # New devices get full scan immediately
                        future = executor.submit(self.scan_device_ports, ip, 'full')
                        initial_scan_futures[future] = (ip, device_id, 'full')
                
                # Process initial scan results and determine additional full scans needed
                full_scan_tasks = []
                
                for future in as_completed(initial_scan_futures):
                    ip, device_id, original_scan_type = initial_scan_futures[future]
                    
                    try:
                        scan_result = future.result()
                        
                        if scan_result.ports:
                            # Update database
                            db_start = time.time()
                            ports_changed = self.db.update_device_ports(device_id, scan_result.ports)
                            perf_stats['database_time'] += time.time() - db_start
                            
                            total_ports += len(scan_result.ports)
                            
                            # Only check for changes if this was originally a quick scan
                            if original_scan_type == 'quick' and ports_changed:
                                logger.info(f"Port changes detected on {ip}, scheduling full scan")
                                devices_needing_full_scan += 1
                                full_scan_tasks.append((ip, device_id))
                            elif original_scan_type == 'full':
                                # New device - full scan already completed, nothing more to do
                                logger.info(f"Full scan completed for new device {ip}: {len(scan_result.ports)} ports found")
                        
                    except Exception as e:
                        error_msg = f"Error processing scan result for {ip}: {str(e)}"
                        logger.error(error_msg)
                        errors.append(error_msg)
                
                # Execute full scans for devices with detected changes
                if full_scan_tasks:
                    logger.info(f"Performing {len(full_scan_tasks)} full scans for devices with changes")
                    
                    full_scan_futures = {}
                    for ip, device_id in full_scan_tasks:
                        future = executor.submit(self.scan_device_ports, ip, 'full')
                        full_scan_futures[future] = (ip, device_id)
                    
                    for future in as_completed(full_scan_futures):
                        ip, device_id = full_scan_futures[future]
                        
                        try:
                            full_scan_result = future.result()
                            
                            if full_scan_result.ports:
                                db_start = time.time()
                                self.db.update_device_ports(device_id, full_scan_result.ports)
                                perf_stats['database_time'] += time.time() - db_start
                                
                                # Update total port count (replace quick scan count)
                                total_ports += len(full_scan_result.ports)
                                
                        except Exception as e:
                            error_msg = f"Error in full scan for {ip}: {str(e)}"
                            logger.error(error_msg)
                            errors.append(error_msg)
            
            perf_stats['scanning_time'] = time.time() - scanning_start
            
        except Exception as e:
            error_msg = f"Critical error during optimized scan: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)
        
        scan_end = datetime.now()
        total_duration = (scan_end - scan_start).total_seconds()
        
        result = ScanResult(
            network_cidr=network_cidr,
            scan_start=scan_start,
            scan_end=scan_end,
            live_hosts_found=len(live_hosts) if 'live_hosts' in locals() else 0,
            new_devices=new_devices,
            devices_needing_full_scan=devices_needing_full_scan,
            total_ports_discovered=total_ports,
            errors=errors,
            performance_stats=perf_stats
        )
        
        logger.info(f"Optimized scan completed in {total_duration:.1f}s "
                   f"(discovery: {perf_stats['discovery_time']:.1f}s, "
                   f"scanning: {perf_stats['scanning_time']:.1f}s, "
                   f"database: {perf_stats['database_time']:.1f}s)")
        logger.info(f"Results: {result.live_hosts_found} hosts, {result.new_devices} new devices, "
                   f"{result.total_ports_discovered} total ports")
        
        return result
    

if __name__ == "__main__":
    import asyncio
    
    # Initialize database and scanner
    db = NetworkDatabase("src/database/network_scanner.db")
    scanner = OptimizedNetworkScanner(db)
    
    # Set up test data
    with db.get_connection() as conn:
        conn.execute("INSERT OR IGNORE INTO customers (customer_name, contact_email) VALUES (?, ?)",
                    ("Test Company", "admin@testcompany.com"))
        
        cursor = conn.execute("INSERT OR IGNORE INTO networks (customer_id, network_cidr, description) VALUES (?, ?, ?)",
                             (1, "127.0.0.1/30", "Test network"))
        network_id = cursor.lastrowid or 1
        conn.commit()
    
    async def run_test():
        try:
            test_network = "127.0.0.1/30"
            
            print(f"Starting optimized scan of {test_network}...")
            print("Performance comparison will be shown...")
            
            result = await scanner.scan_network_optimized(test_network, network_id)
            
            print(f"\nOptimized Scan Results:")
            print(f"- Total duration: {(result.scan_end - result.scan_start).total_seconds():.2f}s")
            print(f"- Discovery time: {result.performance_stats['discovery_time']:.2f}s")
            print(f"- Scanning time: {result.performance_stats['scanning_time']:.2f}s")
            print(f"- Database time: {result.performance_stats['database_time']:.2f}s")
            print(f"- Live hosts: {result.live_hosts_found}")
            print(f"- New devices: {result.new_devices}")
            print(f"- Full scans needed: {result.devices_needing_full_scan}")
            print(f"- Total ports: {result.total_ports_discovered}")
            
            if result.errors:
                print(f"- Errors: {len(result.errors)}")
                for error in result.errors[:3]:  # Show first 3 errors
                    print(f"  * {error}")
            
        except Exception as e:
            print(f"Test failed: {e}")
            print("Note: Install pythonping with: pip install pythonping")
            print("      Adjust test_network to a range you can scan")
    
    # Run the async test
    asyncio.run(run_test())