import nmap
import logging
import ipaddress
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import time

from src.database.database import NetworkDatabase


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

@dataclass
class HostScanResult:
    """Results from scanning a single host."""
    ip_address: str
    is_alive: bool
    ports: List[Dict]
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    scan_error: Optional[str] = None


class NetworkScanner:
    """
    Network scanner that implements smart scanning logic.
    
    This scanner uses Nmap to discover devices and detect changes,
    working with the database to implement efficient scanning strategies.
    """
    def __init__(self, database: NetworkDatabase):
        """
        Initialize the network scanner.
        Args:
            database: NetworkDatabase instance for storing results
        """
        self.db = database
        self.nm = nmap.PortScanner()
        self.scan_timeout = 300
        self.discovery_timeout = 60

        logger.info("NetworkScanner initialized")

    def scan_network(self, network_cidr: str, network_id: int) -> ScanResult:
        """
        Perform complete network scan with smart scanning logic.
        This is the main orchestration method that implements the
        design: discover → classify → smart scan → update database.

        Args:
            network_cidr: Network to scan (e.g., "192.168.1.0/24")
            network_id: Database ID of the network being scanned
            
        Returns:
            ScanResult with summary of what was discovered/changed
        """
        scan_start = datetime.now()
        errors = []
        new_devices = 0
        devices_needing_full_scan = 0
        total_ports = 0
        live_hosts = []

        logger.info(f"Starting network scan of {network_cidr}")

        try:
            # Host Discovery
            logger.info("Phase 1: Discovering live hosts...")
            live_hosts = self.discover_live_hosts(network_cidr)
            logger.info(f"Found {len(live_hosts)} live hosts")

            if not live_hosts:
                logger.warning("No live hosts found!")
                return ScanResult(
                    network_cidr=network_cidr,
                    scan_start=scan_start,
                    scan_end=datetime.now(),
                    live_hosts_found=0,
                    new_devices=0,
                    devices_needing_full_scan=0,
                    total_ports_discovered=0,
                    errors=["No live hosts discovered"]
                )
            
            # Classify devices and apply smart scanning
            for ip in live_hosts:
                try:
                    logger.info(f"Processing {ip}...")

                    # Check if device exists in db
                    existing_device = self.db.find_device_by_ip(ip)

                    if existing_device is None:
                        # New device - needs full scan
                        logger.info(f"New device detected: {ip}")
                        device_id = self.db.add_or_update_device(network_id, ip)
                        new_devices += 1

                        # Perform full scan on new devices
                        scan_result = self.scan_device_ports(ip, scan_type='full')
                        if scan_result.ports:
                            ports_changed = self.db.update_device_ports(device_id, scan_result.ports)
                            total_ports += len(scan_result.ports)
                            logger.info(f"Full scan completed for new device {ip}: {len(scan_result.ports)}  ports")

                    else:
                        # Known device - quick scan first
                        logger.info(f"Known device: {ip} (last scanned: {existing_device.last_scanned})")

                        # Update device info
                        self.db.add_or_update_device(
                            network_id, ip,
                            existing_device.mac_address,
                            existing_device.hostname
                        )

                        # Quick scan on commmon ports
                        scan_result = self.scan_device_ports(ip, scan_type='quick')

                        if scan_result.ports:
                            # Check if ports changed
                            ports_changed = self.db.update_device_ports(existing_device.device_id, scan_result.ports)
                            total_ports += len(scan_result.ports)
                            
                            if ports_changed:
                                # Changes detected - schedule full scan
                                logger.info(f"Port changes detected on {ip}, performing full scan...")
                                devices_needing_full_scan += 1

                                full_scan_result = self.scan_device_ports(ip, scan_type='full')
                                if full_scan_result.ports:
                                    self.db.update_device_ports(existing_device.device_id, full_scan_result.ports)
                                    total_ports += len(full_scan_result.ports) - len(scan_result.ports)
                                    logger.info(f"Full scan completed for {ip}")
                            else:
                                logger.info(f"No changes detected on: {ip}")

                except Exception as e:
                    error_msg = f"Erro scanning {ip}: {str(e)}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    continue
            
        except Exception as e:
            error_msg = f"Critical error during network scan: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)

        scan_end = datetime.now()
        scan_duration = (scan_end - scan_start).total_seconds()

        result = ScanResult(
            network_cidr=network_cidr,
            scan_start=scan_start,
            scan_end=scan_end,
            live_hosts_found=len(live_hosts) if 'live_hosts' in locals() else 0,
            new_devices=new_devices,
            devices_needing_full_scan=devices_needing_full_scan,
            total_ports_discovered=total_ports,
            errors=errors
        )

        logger.info(f"Network scan completed in {scan_duration:.1f}s "
                    f"{result.live_hosts_found} hosts, {result.new_devices} new devices, "
                    f"{result.total_ports_discovered} total ports")
        
        return result
    
    def discover_live_hosts(self, networkd_cidr: str) -> List[str]:
        """
        Discover live hosts using ping scan (-sn).
        This implements the discovery logic.
        Args:
            network_cidr: Network range to scan
            
        Returns:
            List of IP addresses that responded to ping
        """
        try:
            logger.info(f"Discovering live hosts in {networkd_cidr}")

            # Validate network CIDR
            self.nm.scan(hosts=networkd_cidr, arguments='sn', timeout=self.discovery_timeout)

            live_hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    live_hosts.append(host)
                    logger.debug(f"Live host discovered: {host}")

            return sorted(live_hosts, key=lambda ip: ipaddress.IPv4Address(ip))
        except Exception as e:
            logger.error(f"Host discovery failed for {networkd_cidr}: {str(e)}")
            raise

    def scan_device_ports(self, ip_address: str, scan_type: str = 'smart') -> HostScanResult:
        """
        Scan ports on a specific device.
        
        This implements your scanning strategy decisions:
        - 'quick': -sV --top-ports 1000 (known devices)
        - 'full': -sV -p- (new devices or changes detected)
        
        Args:
            ip_address: IP address to scan
            scan_type: 'quick', 'full', or 'smart' (auto-decide)
            
        Returns:
            HostScanResult with discovered ports and services
        """
        try:
            logger.info(f"Scanning {ip_address} (type: {scan_type})")

            # Choose nmap arguments based on scan_type
            if scan_type == 'quick':
                nmap_args = '-sV --top-ports 1000 -T4'
                timeout = 60  # 1 minute quick scan
            elif scan_type == 'full':
                nmap_args = '-sV -sC --version-all -p- -T4'
                timeout = self.scan_timeout  # 5 minutes for full scan
            else:
                nmap_args = '-sV --top-ports 1000 -T4'
                timeout = 60

            # Perform the scan
            scan_start = time.time()
            self.nm.scan(hosts=ip_address, arguments=nmap_args, timeout=timeout)
            scan_duration = time.time() - scan_start

            # Check if host responded
            if ip_address not in self.nm.all_hosts():
                logger.info(f"Host {ip_address} did not respond to scan")
                return HostScanResult(
                    ip_address=ip_address,
                    is_alive=False,
                    ports=[],
                    scan_error="did not respond"
                )
            
            # Host is alive, process result
            host_info = self.nm[ip_address]

            # Extract host
            hostname = None
            mac_address = None
            
            if 'hostnames' in host_info and host_info['hostnames']:
                hostname = host_info['hostnames'][0]['name']

            if 'addresses' in host_info and 'mac' in host_info['addresses']:
                mac_address = host_info['addresses']['mac']

            # Extract port information
            ports = []
            for protocol in host_info.all_protocols():
                ports_dict = host_info[protocol]

                for port_num, port_info in ports_dict.items():
                    port_data = {
                        'port_number': port_num,
                        'protocol': protocol,
                        'state': port_info['state'],
                        'service_name': port_info.get('name', ''),
                        'service_version': port_info.get('version', ''),
                        'service_product': port_info.get('product', ''),
                        'service_extrainfo': port_info.get('extrainfo', '')
                    }

                    # Only include open ports
                    if port_data['state'] == 'open':
                        ports.append(port_data)

            logger.info(f"Scan completed for {ip_address} in {scan_duration:1.1f}s: "
                        f"{len(ports)} open ports found")
            
            return HostScanResult(
                ip_address=ip_address,
                is_alive=True,
                ports=ports,
                hostname=hostname,
                mac_address=mac_address
            )
        
        except Exception as e:
            error_msg = f"Port scan failed for {ip_address}: {str(e)}"
            logger.error(error_msg)

            return HostScanResult(
                ip_address=ip_address,
                is_alive=False,
                ports=[],
                scan_error=error_msg
            )
        
    def get_scan_summary(self, network_id: int) -> Dict:
        """
        Get summary statistics for a network.
        Useful for reporting and dashboard display.
        
        Args:
            network_id: Database ID of network to summarize
            
        Returns:
            Dictionary with summary statistics
        """
        with self.db.get_connection() as conn:
            # Get device counts
            device_stats = conn.execute("""
            SELECT
                COUNT(*) AS total_devices,
                COUNT(CASE WHEN scan_status = 'full_scan_needed' THEN 1 END) as needs_full_scan,
                COUNT(CASE WHEN scan_status = 'up_to_date' THEN 1 END) as up_to_date,
                COUNT(CASE WHEN last_scanned IS NULL THEN 1 END) as never_scanned
            FROM devices
            WHERE network_id = ?
            """, (network_id,)).fetchone()

            # Get port statistics
            port_stats = conn.execute("""
                SELECT 
                    COUNT(*) as total_open_ports,
                    COUNT(DISTINCT service_name) as unique_services
                FROM ports p
                JOIN devices d ON p.device_id = d.device_id
                WHERE d.network_id = ? AND p.state = 'open'
            """, (network_id,)).fetchone()

            # Get vulnerability count
            vuln_stats = conn.execute("""
                    SELECT COUNT(*) as total_vulnerabilities
                    FROM device_vulnerabilities dv
                    JOIN devices d ON dv.device_id = d.device_id
                    WHERE d.network_id = ?    
                    """, (network_id,)).fetchone()

            return {
                'total_devices': device_stats['total_devices'],
                'devices_needing_scan': device_stats['needs_full_scan'],
                'devices_up_to_date': device_stats['up_to_date'],
                'devices_never_scanned': device_stats['never_scanned'],
                'total_open_ports': port_stats['total_open_ports'],
                'unique_services': port_stats['unique_services'],
                'total_vulnerabilities': vuln_stats['total_vulnerabilities']
            }

# Example usage and testing
if __name__ == "__main__":
    db = NetworkDatabase("src/database/network_scanner.db")
    scanner = NetworkScanner(db)

    # Set up test data (normally done through configuration)
    with db.get_connection() as conn:
        # Add test customer and network
        conn.execute("INSERT OR IGNORE INTO customers (customer_name, contact_email) VALUES (?, ?)",
                    ("Test Company", "admin@testcompany.com"))
        
        cursor = conn.execute("INSERT OR IGNORE INTO networks (customer_id, network_cidr, description) VALUES (?, ?, ?)",
                             (1, "192.168.1.0/24", "Server network"))
        network_id = cursor.lastrowid or 1
        conn.commit()

    # Perform test scan (adjust network range to match your environment)
    try:
        test_network = "192.168.1.0/24" 
        
        print(f"Starting scan of {test_network}...")
        result = scanner.scan_network(test_network, network_id)
        
        print(f"\nScan Results:")
        print(f"- Live hosts found: {result.live_hosts_found}")
        print(f"- New devices: {result.new_devices}")
        print(f"- Devices needing full scan: {result.devices_needing_full_scan}")
        print(f"- Total ports discovered: {result.total_ports_discovered}")
        
        if result.errors:
            print(f"- Errors encountered: {len(result.errors)}")
            for error in result.errors:
                print(f"  * {error}")
        
        # Get network summary
        summary = scanner.get_scan_summary(network_id)
        print(f"\nNetwork Summary:")
        for key, value in summary.items():
            print(f"- {key.replace('_', ' ').title()}: {value}")
            
    except Exception as e:
        print(f"Test scan failed: {e}")
        print("Note: Adjust test_network to a range you have permission to scan")