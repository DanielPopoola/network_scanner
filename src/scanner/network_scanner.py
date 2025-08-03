import nmap
import logging
import ipaddress
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import json


from src.database.database import NetworkDatabase

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ScanTask:
    """Represents a scanning task for the thread pool."""
    ip_address: str
    device_id: Optional[int]
    scan_type: str # 'discovery', 'quick', 'full'
    network_id: int
    priority: int = 1   # lower number = Higher priority


@dataclass
class OptimizedScanResult:
    """Results from an optimized network scan."""
    network_cidr: str
    scan_start: datetime
    scan_end: datetime
    total_hosts_attempted: int
    successful_scans: int
    failed_scans: int
    new_devices: int
    devices_with_changes: int
    total_ports_discovered: int
    parallel_workers_used: int
    errors: List[str]


class OptimizedNetworkScanner:
    """
    High-performance network scanner with parallel processing.
    
    Key optimizations:
    1. Parallel host scanning using ThreadPoolExecutor
    2. Batch processing and smart scheduling
    3. Connection pooling for database operations
    4. Configurable scan intervals and priorities
    """
    
    def __init__(self, database: NetworkDatabase, max_workers: int = 10):
        """
        Initialize the optimized scanner.
        
        Args:
            database: NetworkDatabase instance
            max_workers: Maximum parallel scanning threads (default: 10)
        """
        self.db = database
        self.max_workers = max_workers
        self.scan_timeout = 600  # 5 mins per host
        self.discovery_timeout = 120

        # Thread-local storage for Nmap instances
        self._local = threading.local()

        # Scan scheduling configuration
        self.quick_scan_interval = timedelta(hours=4)
        self.full_scan_interval = timedelta(days=1)

        logger.info(f"OptimizedNetworkScanner initialized with {max_workers} workers")
    
    def _get_nmap_scanner(self):
        """Get thread-local Nmap scanner"""
        if not hasattr(self._local, 'nm'):
            self._local.nm = nmap.PortScanner()
        return self._local.nm
    
    def scan_network_optimized(self, network_cidr: str, network_id: int) -> OptimizedScanResult:
        """
        Perform optimized parallel network scan.
        
        Strategy:
        1. Fast discovery of all live hosts (parallel)
        2. Classify hosts and create scan tasks
        3. Execute scan tasks in parallel with priority queue
        4. Batch database updates
        
        Args:
            network_cidr: Network to scan
            network_id: Database ID of the network
            
        Returns:
            OptimizedScanResult with performance metrics
        """
        scan_start = datetime.now()
        errors = []
        successful_scans = 0
        failed_scans = 0
        new_devices = 0
        devices_with_changes = 0
        total_ports = 0
        live_hosts = []

        logger.info(f"Starting optimized scan of {network_cidr} with {self.max_workers} workers")

        try:
            # Parallel Host Discovery
            logger.info("Parallel host discovery...")
            live_hosts = self._discover_hosts_parallel(network_cidr)
            logger.info(f"Discovered {len(live_hosts)} live hosts")

            if not live_hosts:
                return self._create_empty_result(network_cidr, scan_start, "No live hosts found")
            
            # Create Scan Tasks with Smart Scheduling
            logger.info("Creating scan tasks...")
            scan_tasks = self._create_scan_tasks(live_hosts, network_id)
            logger.info(f"Created {len(scan_tasks)} scan tasks")

            # Execute Scan Tasks in Parallel
            logger.info(f"Executing scan tasks in parallel")
            scan_results = self._execute_scan_tasks_parallel(scan_tasks)

            logger.info("Phase 4: Processing quick scan results...")
            full_scan_tasks = []  # Collect devices needing full scan

            for result in scan_results:
                if result['success']:
                    successful_scans += 1

                    # Process the scan result (without doing full scans yet)
                    device_result = self._process_scan_result_without_full_scan(result, network_id)
                    
                    if device_result['is_new_device']:
                        new_devices += 1
                    if device_result['ports_changed']:
                        devices_with_changes += 1

                        # If this was a quick scan with changes → add to full scan batch
                        if result['scan_type'] == 'quick':
                            full_scan_tasks.append(ScanTask(
                                ip_address=result['ip_address'],
                                device_id=device_result['device_id'],
                                scan_type='full',
                                network_id=network_id,
                                priority=1  # High priority for change-triggered scans
                            ))

                    total_ports += device_result['port_count']
                else:
                    failed_scans += 1
                    errors.append(result['error'])
                
            if full_scan_tasks:
                logger.info(f"Executing {len(full_scan_tasks)} full scans in parallel...")
                full_scan_results = self._execute_scan_tasks_parallel(full_scan_tasks)
                
                # Process full scan results
                for full_result in full_scan_results:
                    if full_result['success']:
                        # Update database with full scan results
                        full_device_result = self._process_full_scan_result(full_result, network_id)
                        total_ports += full_device_result['additional_ports']
                    else:
                        errors.append(f"Full scan failed: {full_result['error']}")
                
                logger.info(f"Completed {len(full_scan_tasks)} parallel full scans")
            else:
                logger.info("All scan tasks were full scans. No quick scan results to evaluate.")


        except Exception as e:
            error_msg = f"Critical error in optimized scan: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)

        scan_end = datetime.now()
        scan_duration = (scan_end - scan_start).total_seconds()

        result = OptimizedScanResult(
            network_cidr=network_cidr,
            scan_start=scan_start,
            scan_end=scan_end,
            total_hosts_attempted=len(live_hosts) if 'live_hosts' in locals() else 0,
            successful_scans=successful_scans,
            failed_scans=failed_scans,
            new_devices=new_devices,
            devices_with_changes=devices_with_changes,
            total_ports_discovered=total_ports,
            parallel_workers_used=self.max_workers,
            errors=errors
        )

        logger.info(f"Optimized scan completed in {scan_duration:1.1f}s: "
                        f"{result.successful_scans}/{result.total_hosts_attempted} hosts scanned successfully")
            
        return result

    def _discover_hosts_parallel(self, network_cidr: str) -> List[str]:
        """
        Discover live hosts using parallel ping scans.
        
        Strategy: Split network into smaller chunks and scan in parallel.
        """
        try:
            network = ipaddress.IPv4Network(network_cidr, strict=False)
            all_ips = [str(ip) for ip in network.hosts()]

            live_hosts = []

            if len(all_ips) <= 5:
                live_hosts = all_ips

            # Split IPs into chunks for parallel processing
            chunk_size = max(1, len(all_ips) // self.max_workers)
            ip_chunks = [all_ips[i:i + chunk_size] for i in range(0, len(all_ips), chunk_size)]

            # Parallel discovery
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_chunk = {
                    executor.submit(self._scan_ip_chunk_for_discovery, chunk): chunk
                    for chunk in ip_chunks
                }

                for future in as_completed(future_to_chunk):
                    try:
                        chunk_results = future.result(timeout=self.discovery_timeout)
                        live_hosts.extend(chunk_results)
                    except Exception as e:
                        logger.error(f"Discovery chunk failed: {str(e)}")

            return sorted(live_hosts, key=lambda ip: ipaddress.IPv4Address(ip))

        except Exception as e:
            logger.error(f"Parallel host discovery failed: {str(e)}")
            raise

    def _scan_ip_chunk_for_discovery(self, ip_chunk: List[str]) -> List[str]:
        nm = self._get_nmap_scanner()
        try:
            nm.scan(hosts=' '.join(ip_chunk), arguments='-sn')
            return [
                ip for ip in ip_chunk
                if ip in nm.all_hosts() and nm[ip].state() == 'up'
            ]
        except Exception as e:
            logger.debug(f"Chunk scan failed: {e}")
            return []

    def _create_scan_tasks(self, live_hosts: List[str], network_id: int) -> List[ScanTask]:
        """
        Create scan tasks using smart scan logic.
        
        Smart Logic:
        1. New devices → Full scan immediately
        2. Known devices → Quick scan first (always)
        3. After quick scan → Check for changes → Full scan if needed
        """
        tasks = []

        for ip in live_hosts:
            # Check if device exists and get its status
            existing_device = self.db.find_device_by_ip(ip)

            if existing_device is None:
                # New device - highest priority, needs full scan
                logger.info(f"Scanning {ip} with full scan")
                tasks.append(ScanTask(
                    ip_address=ip,
                    device_id=None,
                    scan_type='full',
                    network_id=network_id,
                    priority=1
                ))
            else:
                # Determine scan type based on port/service change
                logger.info(f"Known device: {ip} (last scanned: {existing_device.last_scanned})")
                tasks.append(ScanTask(
                    ip_address=ip,
                    device_id=existing_device.device_id,
                    scan_type='quick',
                    network_id=network_id,
                    priority=2
                ))

        # Sort tasks by priority (lower number = higher priority)
        tasks.sort(key=lambda x: x.priority)

        logger.info(f"Smart scan tasks created: "
                   f"New devices (full): {sum(1 for t in tasks if t.scan_type == 'full')}, "
                   f"Known devices (quick first): {sum(1 for t in tasks if t.scan_type == 'quick')}")
        
        return tasks
    
    def _execute_scan_tasks_parallel(self, tasks: List[ScanTask]) -> List[Dict]:
        """Execute scan tasks in parallel with proper error handling."""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(self._execute_single_scan_task, task): task
                for task in tasks
            }

            # Collect results as they complete
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    result = future.result(timeout=self.scan_timeout)
                    results.append(result)
                except Exception as e:
                    error_result = {
                        'success': False,
                        'ip_address': task.ip_address,
                        'scan_type': task.scan_type,
                        'error': f"Scan task failed: {str(e)}"
                    }
                    results.append(error_result)
                    logger.error(f"Scan task failed for {task.ip_address}: {str(e)}")
            return results
        
    def _execute_single_scan_task(self, task: ScanTask) -> Dict:
        """Execute a single scan task (thread worker function)."""
        try:
            nm = self._get_nmap_scanner()

            # Choose scan arguments based on task type
            if task.scan_type == 'quick':
                nmap_args = '-sV --top-ports 1000 -T4'
                timeout = 60
            elif task.scan_type == 'full':
                nmap_args = '-sV -sC --version-all -p- -T4'
                timeout = self.scan_timeout
            else:
                nmap_args = '-sV --top-ports 1000 -T4'
                timeout = 60

            # Perform the scan
            start_time = time.time()
            nm.scan(hosts=task.ip_address, arguments=nmap_args, timeout=timeout)
            scan_duration = time.time() - start_time

            # Process results
            if task.ip_address not in nm.all_hosts():
                return {
                    'success': False,
                    'ip_address': task.ip_address,
                    'scan_type': task.scan_type,
                    'error': 'Host did not respond'
                }
            
            host_info = nm[task.ip_address]

            # Extract port info
            ports = []
            for protocol in host_info.all_protocols():
                ports_dict = host_info[protocol]
                for port_num, port_info in ports_dict.items():
                    if port_info['state'] == 'open':
                        ports.append({
                            'port_number': port_num,
                            'protocol': protocol,
                            'state': port_info['state'],
                            'service_name': port_info.get('name', ''),
                            'service_version': port_info.get('version', ''),
                            'service_product': port_info.get('product', ''),
                            'service_cpe': port_info['cpe'],
                            'service_extrainfo': port_info['extrainfo'],
                            'service_conf': port_info['conf'],
                        })

            # Extract hostname and MAC
            hostname = None
            mac_address = None

            if 'hostnames' in host_info and host_info['hostnames']:
                hostname = host_info['hostnames'][0]['name']

            if 'addresses' in host_info and 'mac' in host_info['addresses']:
                mac_address = host_info['addresses']['mac']

            return {
                'success': True,
                'ip_address': task.ip_address,
                'device_id': task.device_id,
                'scan_type': task.scan_type,
                'ports': ports,
                'hostname': hostname,
                'mac_address': mac_address,
                'scan_duration': scan_duration,
                'network_id': task.network_id
            }

        except Exception as e:
            return {
                'success': False,
                'ip_address': task.ip_address,
                'scan_type': task.scan_type,
                'error': str(e)
            }
        
    def _process_scan_result_without_full_scan(self, scan_result: Dict, network_id: int) -> Dict:
        """
        Process scan result WITHOUT triggering full scans.
        
        This handles the quick scan results and identifies which devices need full scans,
        but doesn't execute them (that's done in parallel later).
        """
        try:
            ip = scan_result['ip_address']
            ports = scan_result['ports']
            hostname = scan_result.get('hostname')
            mac_address = scan_result.get('mac_address')
            device_id = scan_result.get('device_id')
            scan_type = scan_result['scan_type']

            # Add or update device
            if device_id is None:
                # New device (this was already a full scan)
                device_id = self.db.add_or_update_device(network_id, ip, mac_address, hostname)
                is_new_device = True
                ports_changed = False  # New device, so no "change" comparison
            else:
                # Update existing device
                self.db.add_or_update_device(network_id, ip, mac_address, hostname)
                is_new_device = False
                
                # Check for port changes (CORE LOGIC!)
                ports_changed = self.db.update_device_ports(device_id, ports)
                
                if scan_type == 'quick' and ports_changed:
                    logger.info(f"Changes detected on {ip}, will schedule for parallel full scan")

            return {
                'success': True,
                'device_id': device_id,
                'is_new_device': is_new_device,
                'ports_changed': ports_changed,
                'port_count': len(ports)
            }
        
        except Exception as e:
            logger.error(f"Failed to process scan result for {scan_result.get('ip_address', 'unknown')}: {str(e)}")
            return {
                'success': False,
                'device_id': None,
                'is_new_device': False,
                'ports_changed': False,
                'port_count': 0
            }

    def _process_full_scan_result(self, full_scan_result: Dict, network_id: int) -> Dict:
        """
        Process full scan results (triggered by change detection).
        
        This updates the database with comprehensive port information.
        """
        try:
            ip = full_scan_result['ip_address']
            ports = full_scan_result['ports']
            hostname = full_scan_result.get('hostname')
            mac_address = full_scan_result.get('mac_address')
            device_id = full_scan_result['device_id']
            
            # Update device info (might have gotten more details from full scan)
            self.db.add_or_update_device(network_id, ip, mac_address, hostname)
            
            # Get current port count before update
            existing_device = self.db.find_device_by_ip(ip)
            old_port_count = len(existing_device.ports) if existing_device else 0
            
            # Update with full scan results
            self.db.update_device_ports(device_id, ports)
            
            additional_ports = len(ports) - old_port_count
            logger.info(f"Full scan completed for {ip}: {len(ports)} total ports ({additional_ports:+d} from quick scan)")
            
            return {
                'success': True,
                'additional_ports': max(0, additional_ports)  # Don't count negative (shouldn't happen)
            }
            
        except Exception as e:
            logger.error(f"Failed to process full scan result for {full_scan_result.get('ip_address', 'unknown')}: {str(e)}")
            return {
                'success': False,
                'additional_ports': 0
            }

    def _create_empty_result(self, network_cidr: str, scan_start: datetime, reason: str) -> OptimizedScanResult:
        """Create an empty result for failed scans."""
        return OptimizedScanResult(
            network_cidr=network_cidr,
            scan_start=scan_start,
            scan_end=datetime.now(),
            total_hosts_attempted=0,
            successful_scans=0,
            failed_scans=0,
            new_devices=0,
            devices_with_changes=0,
            total_ports_discovered=0,
            parallel_workers_used=self.max_workers,
            errors=[reason]
        )
    
    def get_performance_metrics(self, network_id: int) -> Dict:
        """Get performance and efficiency metrics for the network."""
        with self.db.get_connection() as conn:
            # Calculate scan efficiency metrics
            metrics = conn.execute("""
                SELECT 
                    COUNT(*) as total_devices,
                    AVG(julianday('now') - julianday(last_scanned)) as avg_days_since_scan,
                    COUNT(CASE WHEN scan_status = 'full_scan_needed' THEN 1 END) as needs_full_scan,
                    COUNT(CASE WHEN last_scanned > datetime('now', '-1 day') THEN 1 END) as scanned_recently
                FROM devices 
                WHERE network_id = ?
            """, (network_id,)).fetchone()
            
            return {
                'total_devices': metrics['total_devices'],
                'average_days_since_scan': round(metrics['avg_days_since_scan'] or 0, 2),
                'devices_needing_full_scan': metrics['needs_full_scan'],
                'devices_scanned_recently': metrics['scanned_recently'],
                'scan_efficiency': round((metrics['scanned_recently'] / max(metrics['total_devices'], 1)) * 100, 1)
            }
        
if __name__ == "__main__":
    # Initialize optimized scanner
    db = NetworkDatabase("src/database/network_scanner.db")
    
    # Test different worker configurations
    for workers in [10, 20]:
        print(f"\n=== Testing with {workers} workers ===")
        scanner = OptimizedNetworkScanner(db, max_workers=workers)
        
        # Set up test network
        with db.get_connection() as conn:
            conn.execute("INSERT OR IGNORE INTO customers (customer_name) VALUES (?)", ("Test Company",))
            cursor = conn.execute("INSERT OR IGNORE INTO networks (customer_id, network_cidr, description) VALUES (?, ?, ?)",
                                 (1, "192.168.1.0/24", f"Test network - {workers} workers"))
            network_id = cursor.lastrowid or 1
            conn.commit()
        
        # Run performance test
        start_time = time.time()
        try:
            result = scanner.scan_network_optimized("192.168.1.0/24", network_id)
            duration = time.time() - start_time
            
            print(f"Scan completed in {duration:.2f}s")
            print(f"Success rate: {result.successful_scans}/{result.total_hosts_attempted}")
            print(f"Performance: {result.successful_scans/duration:.2f} hosts/second")
            
            # Get efficiency metrics
            metrics = scanner.get_performance_metrics(network_id)
            print(f"Scan efficiency: {metrics['scan_efficiency']}%")
            
        except Exception as e:
            print(f"Test failed: {e}")