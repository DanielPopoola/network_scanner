import sqlite3
import logging
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any
import time


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """Data structure for device information returned by database queries."""
    device_id: int
    network_id: int
    ip_address: str
    mac_address: Optional[str]
    hostname: Optional[str]
    first_seen: Optional[datetime]
    last_scanned: Optional[datetime]
    scan_status: str
    ports: List[Dict[str, Any]]

@dataclass
class PortInfo:
    """Data structure for port information"""
    port_id: int
    port_number: int
    protocol: str
    service_name: Optional[str]
    service_version: Optional[str]
    state: str

class NetworkDatabase:
    """
    Database manager for the network scanner application.
    
    This class handles all database operations including device tracking,
    port management, and vulnerability storage.
    """
    def __init__(self, db_path: str):
        """
        Initialize database manager.
        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = db_path
        self.max_retries = 3
        self.retry_delay = 0.5

        self.create_tables()
        logger.info(f"Database initialized at {db_path}")

    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        
        This ensures connections are always properly closed and provides
        automatic retry logic for SQLite locking issues.
        """
        conn = None
        for attempt in range(self.max_retries):
            try:
                conn = sqlite3.connect(self.db_path, timeout=10.0)
                conn.row_factory = sqlite3.Row
                yield conn
                break
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < self.max_retries - 1:
                    logger.warning(f"Database locked, retrying in {self.retry_delay}s (attempt {attempt + 1})")
                    time.sleep(self.retry_delay)
                    continue
                else:
                    raise
            finally:
                if conn:
                    conn.close()

    def create_tables(self):
        """
        Create all necessary database tables.
        This method is idempotent - safe to run multiple times.
        """
        schema_sql = """
        -- Customers table
        CREATE TABLE IF NOT EXISTS customers (
            customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            contact_email TEXT
        );

        -- Networks table
        CREATE TABLE IF NOT EXISTS networks (
            network_id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            network_cidr TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
        );

        -- Devices Table
        CREATE TABLE IF NOT EXISTS devices (
            device_id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL UNIQUE,
            mac_address TEXT,
            hostname TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_scanned DATETIME,
            scan_status TEXT DEFAULT 'full_scan_needed',
            FOREIGN KEY (network_id) REFERENCES networks(network_id)
        );

        -- Ports Table
        CREATE TABLE IF NOT EXISTS ports (
            port_id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            port_number INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service_name TEXT,
            service_version TEXT,
            state TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices (device_id)
            UNIQUE(device_id, port_number, protocol)
        );

        -- Vulnerabilities table
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_v3_score REAL,
            reference_url TEXT
        );
        
        -- Device vulnerabilities linking table
        CREATE TABLE IF NOT EXISTS device_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            port_id INTEGER,
            cve_id TEXT NOT NULL,
            discovered_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(device_id),
            FOREIGN KEY (port_id) REFERENCES ports(port_id),
            FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id),
            UNIQUE(device_id, port_id, cve_id)
        );

        -- Create indexes for better query performance
        CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
        CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_id);
        CREATE INDEX IF NOT EXISTS idx_device_vulns_device ON device_vulnerabilities(device_id);
        """
        with self.get_connection() as conn:
            conn.executescript(schema_sql)
            conn.commit()

        logger.info(f"Database tables created/verified")

    def find_device_by_ip(self, ip_address: str)  -> Optional[DeviceInfo]:
        """
        Find device by IP address and return complete device information.
        
        Args:
            ip_address: IP address to search for
            
        Returns:
            DeviceInfo object if found, None otherwise
        """
        device_query = """
        SELECT d.*, n.customer_id
        FROM devices d
        JOIN networks n ON d.network_id = n.network_id
        WHERE d.ip_address = ?
        """

        ports_query = """
        SELECT port_id, port_number, protocol, service_name, service_version, state
        FROM ports
        WHERE device_id = ?
        ORDER BY port_number
        """

        with self.get_connection() as conn:
            # Get device info
            device_row = conn.execute(device_query, (ip_address,)).fetchone()
            if not device_row:
                return None
            
            # Get associated ports
            port_rows = conn.execute(ports_query, (device_row['device_id'],)).fetchall()
            ports = [dict(row) for row in port_rows]

            # Convert datetime to objects
            first_seen = datetime.fromisoformat(device_row['first_seen']) if device_row['first_seen'] else None
            last_scanned = datetime.fromisoformat(device_row['last_scanned']) if device_row['last_scanned'] else None

            if first_seen is not None:
                return DeviceInfo(
                    device_id=device_row['device_id'],
                    network_id=device_row['network_id'],
                    ip_address=device_row['ip_address'],
                    mac_address=device_row['ip_address'],
                    hostname=device_row['hostname'],
                    first_seen=first_seen,
                    last_scanned=last_scanned,
                    scan_status=device_row['scan_status'],
                    ports=ports
                )
            else:
                return None
            
    def add_or_update_device(self, network_id: int, ip_address: str,
                             mac_address: str = None, hostname: str = None) -> int:
        """
        Add new device or update existing device information.
        
        Args:
            network_id: ID of the network this device belongs to
            ip_address: Device IP address
            mac_address: Device MAC address (optional)
            hostname: Device hostname (optional)
            
        Returns:
            device_id of the added/updated device
        """
        # Check if device already exists
        existing_device = self.find_device_by_ip(ip_address)

        if existing_device:
            # Update existing device
            update_sql = """
            UPDATE devices
            SET mac_address = COALESCE(?, mac_address),
                hostname = COALESCE(?, hostname),
                last_scanned = CURRENT_TIMESTAMP
            WHERE ip_address = ?
            """
            with self.get_connection() as conn:
                conn.execute(update_sql, (mac_address, hostname, ip_address))
                conn.commit()

            logger.info(f"Updated existing device: {ip_address}")
            return existing_device.device_id
        else:
            # Add new device
            insert_sql = """
            INSERT INTO devices (network_id, ip_address, mac_address, hostname, scan_status)
            VALUES (?, ?, ?, ?, 'full_scan_needed')
            """
            with self.get_connection() as conn:
                cursor = conn.execute(insert_sql, (network_id, ip_address, mac_address, hostname))
                device_id = cursor.lastrowid
                conn.commit()

            logger.info(f"Added new device: {ip_address} (ID : {device_id})")
            return device_id if device_id is not None else 0
        
    def update_device_ports(self, device_id: int, new_ports: List[Dict]) -> bool:
        """
        Update ports for a device and detect changes.
        
        Args:
            device_id: ID of the device
            new_ports: List of port dictionaries from scan results
            
        Returns:
            True if ports changed (requiring full scan), False otherwise
        """
        current_ports_query = """
        SELECT port_number, protocol, service_name, service_version, state
        FROM ports WHERE device_id = ?
        """

        with self.get_connection() as conn:
            current_rows = conn.execute(current_ports_query, (device_id,)).fetchall()
            current_ports = {(row['port_number'], row['protocol']): dict(row) for row in current_rows}

            # Create set of new ports for comparison
            new_ports_set = {(port['port_number'], port['protocol']): port for port in new_ports}

            # Detect changes
            ports_changed = (
                set(current_ports.keys()) != set(new_ports_set.keys()) or
                any(current_ports[key] != new_ports_set[key] for key in current_ports.keys() & new_ports_set.keys())
            )

            # Update ports in database
            # First, remove ports that no longer exist
            conn.execute("DELETE FROM ports WHERE device_id = ?", (device_id,))

            # Then add all current ports
            port_insert_sql = """
            INSERT INTO ports (device_id, port_number, protocol, service_name, service_version, state)
            VALUES (?, ?, ?, ?, ?, ?)
            """

            for port in new_ports:
                conn.execute(port_insert_sql, (
                    device_id,
                    port['port_number'],
                    port['protocol'],
                    port.get('service_name'),
                    port.get('service_version'),
                    port['state']
                ))

            # Update device scan status based on whether ports changed
            status = 'full_scan_needed' if ports_changed else 'up_to_date'
            conn.execute(
                "UPDATE devices SET scan_status = ?, last_scanned = CURRENT_TIMESTAMP WHERE device_id = ?",
                (status, device_id)
            )

            conn.commit()

            logger.info(f"Updated ports for device {device_id}. Changes detected: {ports_changed}")
            return ports_changed
        
    def get_devices_needing_full_scan(self) -> List[DeviceInfo]:
        """
        Get all devices that need a full scan.
        
        Returns:
            List of DeviceInfo objects for devices needing full scans
        """
        query = """
        SELECT d.*, n.customer_id,
        FROM devices d
        JOIN networks n ON d.network_id = n.network_id
        WHERE d.scan_status = 'full_scan_needed'
        """

        devices = []
        with self.get_connection() as  conn:
            rows = conn.execute(query).fetchall()
            for row in rows:
                # Get ports for each device
                ports_query = "SELECT * from ports WHERE device_id = ?"
                port_rows = conn.execute(ports_query, (row['device_id'],))
                ports = [dict(port_row) for port_row in port_rows]

                device_info = DeviceInfo(
                    device_id=row['device_id'],
                    network_id=row['network_id'],
                    ip_address=row['ip_address'],
                    mac_address=row['mac_address'],
                    hostname=row['hostname'],
                    first_seen=datetime.fromisoformat(row['first_seen']) if row['first_seen'] else None,
                    last_scanned=datetime.fromisoformat(row['last_scanned']) if row['last_scanned'] else None,
                    scan_status=row['scan_status'],
                    ports=ports
                )
                devices.append(device_info)

        return devices



if __name__ == "__main__":
    # Initialize database
    db = NetworkDatabase("network_scanner.db")
    
    # Test device operations
    print("Testing database operations...")
    
    # This would typically be set up during initial configuration
    with db.get_connection() as conn:
        # Add test customer and network
        conn.execute("INSERT OR IGNORE INTO customers (customer_name, contact_email) VALUES (?, ?)",
                    ("Test Company", "admin@testcompany.com"))
        conn.execute("INSERT OR IGNORE INTO networks (customer_id, network_cidr, description) VALUES (?, ?, ?)",
                    (1, "192.168.1.0/24", "Main office network"))
        conn.commit()
    
    # Test adding a device
    device_id = db.add_or_update_device(1, "192.168.1.100", "aa:bb:cc:dd:ee:ff", "server01")
    print(f"Added device with ID: {device_id}")
    
    # Test finding device
    device_info = db.find_device_by_ip("192.168.1.100")
    if device_info:
        print(f"Found device: {device_info.ip_address} (Status: {device_info.scan_status})")
    
    # Test port updates
    test_ports = [
        {"port_number": 22, "protocol": "tcp", "service_name": "ssh", "service_version": "OpenSSH 8.0", "state": "open"},
        {"port_number": 80, "protocol": "tcp", "service_name": "http", "service_version": "Apache 2.4.41", "state": "open"}
    ]
    
    ports_changed = db.update_device_ports(device_id, test_ports)
    print(f"Ports updated. Changes detected: {ports_changed}")