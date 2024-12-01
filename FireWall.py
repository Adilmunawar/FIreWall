import subprocess
import requests
import time
import logging
from geoip2.database import Reader  # Better GeoIP2 library
from ipaddress import ip_address, AddressValueError

# Configure logging
logging.basicConfig(filename="advanced_firewall_log.txt", level=logging.INFO,
                    format="%(asctime)s - [%(levelname)s] - %(message)s")

GEOIP_DB_PATH = "GeoLite2-Country.mmdb"  # Path to GeoIP2 database

# Helper: Execute a shell command
def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Executed: {command}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to execute: {command}. Error: {e}")

# Helper: Validate IP address
def is_valid_ip(ip):
    try:
        ip_address(ip)
        return True
    except AddressValueError:
        return False

# Function to block an IP
def block_ip(ip):
    if not is_valid_ip(ip):
        logging.warning(f"Invalid IP address: {ip}")
        return
    run_command(f"iptables -A INPUT -s {ip} -j DROP")
    logging.info(f"Blocked IP: {ip}")

# Allow internal network traffic
def allow_internal_traffic():
    run_command("iptables -A INPUT -s 192.168.0.0/24 -j ACCEPT")
    logging.info("Allowed internal network traffic")

# Function to set up basic firewall rules
def setup_firewall():
    # Backup existing rules
    run_command("iptables-save > firewall_backup.rules")
    logging.info("Firewall rules backed up")

    # Flush existing rules
    run_command("iptables -F")

    # Allow internal traffic
    allow_internal_traffic()

    # Allow essential services
    essential_ports = {"HTTP": 80, "HTTPS": 443, "SSH": 22}
    for service, port in essential_ports.items():
        run_command(f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
        logging.info(f"Allowed {service} traffic on port {port}")

    # Default policy to drop everything
    run_command("iptables -P INPUT DROP")
    logging.info("Default policy set to DROP")

# Block known scammer IPs dynamically from a threat feed
def block_known_scammers(threat_feed_url):
    try:
        response = requests.get(threat_feed_url, timeout=10)
        response.raise_for_status()
        scammer_ips = response.text.splitlines()

        for ip in scammer_ips:
            block_ip(ip)
    except requests.RequestException as e:
        logging.error(f"Failed to fetch threat feed: {e}")

# Block traffic by geographic location
def block_by_geo(ip, blocked_countries):
    try:
        with Reader(GEOIP_DB_PATH) as reader:
            match = reader.country(ip)
            if match and match.country.iso_code in blocked_countries:
                block_ip(ip)
                logging.info(f"Blocked IP {ip} from country {match.country.iso_code}")
    except Exception as e:
        logging.error(f"Geo-blocking failed for {ip}: {e}")

# Rate limiting
def rate_limit(port=80, limit="10/second", burst=20):
    run_command(f"iptables -A INPUT -p tcp --dport {port} -m limit --limit {limit} --limit-burst {burst} -j ACCEPT")
    logging.info(f"Rate limiting applied on port {port}: {limit}, burst={burst}")

# Detect and block port scans
def detect_port_scan():
    run_command("iptables -N PORTSCAN")
    run_command("iptables -A PORTSCAN -m recent --update --seconds 60 --hitcount 4 -j LOG --log-prefix 'Portscan: '")
    run_command("iptables -A PORTSCAN -m recent --update --seconds 60 --hitcount 4 -j DROP")
    run_command("iptables -A INPUT -p tcp --syn -m multiport --dports 1:65535 -j PORTSCAN")
    logging.info("Port scan detection enabled")

# Whitelist trusted IPs
def whitelist_ips(trusted_ips):
    for ip in trusted_ips:
        if is_valid_ip(ip):
            run_command(f"iptables -A INPUT -s {ip} -j ACCEPT")
            logging.info(f"Whitelisted IP: {ip}")
        else:
            logging.warning(f"Invalid IP for whitelisting: {ip}")

# Restore firewall rules
def restore_firewall():
    run_command("iptables-restore < firewall_backup.rules")
    logging.info("Firewall rules restored from backup")

# Main function
if __name__ == "__main__":
    # Setup firewall
    setup_firewall()

    # Apply rate limiting
    rate_limit(port=80, limit="10/second", burst=20)

    # Detect port scans
    detect_port_scan()

    # Dynamically block known scammer IPs
    threat_feed_url = "https://example.com/threat-feed.txt"
    block_known_scammers(threat_feed_url)

    # Geo-block traffic from specific countries
    blocked_countries = ["CN", "RU"]
    block_by_geo("203.0.113.1", blocked_countries)

    # Whitelist trusted IPs
    trusted_ips = ["203.0.113.5", "198.51.100.10"]
    whitelist_ips(trusted_ips)
