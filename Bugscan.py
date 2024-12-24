import asyncio
import socket
import ssl
import logging
import requests  # HTTP requests to check response status
import json
from typing import List, Optional

# ScanResult class to hold scan details
class ScanResult:
    def __init__(self, domain):
        self.domain = domain
        self.IP = None
        self.server = None
        self.Ports = []
        self.TLSVersions = []
        self.CipherSuites = []
        self.ALPNProtocols = []
        self.ESNI = None
        self.ECH = None
        self.http_status = None  # To track HTTP response status separately

    def to_dict(self):
        return {
            "Domain": self.domain,
            "IP": self.IP,
            "Server": self.server,
            "Ports": self.Ports,
            "TLSVersions": self.TLSVersions,
            "CipherSuites": self.CipherSuites,
            "ALPNProtocols": self.ALPNProtocols,
            "ESNI": self.ESNI,
            "ECH": self.ECH,
            "HTTPStatus": self.http_status,  # Include the HTTP status separately
        }

# Function to check the HTTP response status
async def response_checker(domain: str) -> Optional[str]:
    """
    Check the HTTP response for the domain by performing an HTTP GET request.
    If successful, it will return the status code, else None.
    """
    try:
        # Performing HTTP GET request to check the response status
        response = requests.get(f"https://{domain}", timeout=5)
        if response.status_code == 200:
            return "200 OK"
        else:
            return f"HTTP {response.status_code}"
    except requests.RequestException as e:
        logging.error(f"Error checking response for {domain}: {e}")
        return None

# Scan domain function
async def scan_domain(domain: str, start_port: int, end_port: int, semaphore: asyncio.Semaphore) -> Optional[ScanResult]:
    """
    Scan the domain for open ports, TLS details, and add response checking.
    """
    async with semaphore:
        result = ScanResult(domain=domain)

        # Resolve IP address
        try:
            ips = socket.gethostbyname(domain)
            result.IP = ips
        except socket.gaierror:
            logging.error(f"Error resolving IP for domain {domain}")
            return None

        # TLS connection and scanning details
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as s:
                s.settimeout(5)  # Increased timeout to 5 seconds
                s.connect((domain, 443))
                result.server = domain
                # TLS version and cipher suite extraction
                ssl_info = s.getpeercert()
                if ssl_info:
                    result.TLSVersions.append(ssl_info.get('version', 'Unknown'))
                    result.CipherSuites.append(s.cipher()[0] if s.cipher() else 'Unknown')
                result.ALPNProtocols = s.selected_alpn_protocol() if s.selected_alpn_protocol() else []

        except ssl.SSLError as e:
            logging.error(f"SSL Error scanning TLS for {domain}: {e}")
            return None
        except socket.error as e:
            logging.error(f"Socket error scanning TLS for {domain}: {e}")
            return None

        # Perform HTTP Response check
        http_status = await response_checker(domain)
        if http_status:
            result.http_status = http_status

        # Scan open ports with a longer timeout
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)  # Increased timeout to 5 seconds
                    s.connect((domain, port))
                    result.Ports.append(port)
            except (socket.timeout, socket.error):
                continue

        # Example placeholders for ESNI and ECH checks (you can implement actual checks here)
        result.ESNI = False
        result.ECH = False

        return result

# Function to save the results to file
async def save_results(results: List[ScanResult], output_file: str):
    """
    Save the scan results in JSON or CSV format based on output file extension.
    """
    if output_file.endswith(".json"):
        with open(output_file, "w") as f:
            json.dump([result.to_dict() for result in results], f, indent=4)
    elif output_file.endswith(".csv"):
        import csv
        with open(output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["Domain", "IP", "Server", "Ports", "TLSVersions", "CipherSuites", "ALPNProtocols", "ESNI", "ECH", "HTTPStatus"])
            writer.writeheader()
            for result in results:
                writer.writerow(result.to_dict())
    else:
        logging.error(f"Unsupported output format: {output_file}")

# Function to load domains from a file asynchronously
async def load_domains(input_path: str) -> List[str]:
    """
    Load domains from a file asynchronously.
    """
    domains = []
    with open(input_path, "r") as f:
        domains = [line.strip() for line in f.readlines()]
    return domains

# Main function
async def main(input_path: str, start_port: int, end_port: int, output: str, rate_limit: int):
    """
    Main function to orchestrate the scanning.
    """
    domains = await load_domains(input_path)
    results = []
    semaphore = asyncio.Semaphore(rate_limit)  # Rate limit handling

    tasks = [scan_domain(domain, start_port, end_port, semaphore) for domain in domains]
    for task in asyncio.as_completed(tasks):
        result = await task
        if result:
            results.append(result)

    await save_results(results, output)
    logging.info(f"Results saved to {output}")

# Example entry point
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)  # Set to DEBUG for detailed logs during development
    input_file = "domains.txt"  # Change this to the file path containing the domains
    output_file = "results.json"  # You can also set this to results.csv
    start_port = 1
    end_port = 1024
    rate_limit = 10  # Number of simultaneous connections allowed

    asyncio.run(main(input_file, start_port, end_port, output_file, rate_limit))
