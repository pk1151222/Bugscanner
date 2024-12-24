import argparse
import csv
import json
import logging
import os
import socket
import ssl
import asyncio
from typing import List, Optional
from asyncio import Semaphore


class ScanResult:
    def __init__(self, domain: str, ip: str = '', server: str = '', ports: List[int] = None,
                 tls_versions: List[str] = None, cipher_suites: List[str] = None,
                 alpn_protocols: List[str] = None, esni: bool = False, ech: bool = False):
        self.domain = domain
        self.ip = ip
        self.server = server
        self.ports = ports or []
        self.tls_versions = tls_versions or []
        self.cipher_suites = cipher_suites or []
        self.alpn_protocols = alpn_protocols or []
        self.esni = esni
        self.ech = ech

    def to_dict(self):
        return {
            "Domain": self.domain,
            "IP": self.ip,
            "Server": self.server,
            "Ports": self.ports,
            "TLSVersions": self.tls_versions,
            "CipherSuites": self.cipher_suites,
            "ALPNProtocols": self.alpn_protocols,
            "ESNI": self.esni,
            "ECH": self.ech
        }


async def load_domains(input_path: str) -> List[str]:
    if os.path.isfile(input_path):
        with open(input_path, 'r') as file:
            return [line.strip() for line in file.readlines()]
    else:
        return [input_path]


async def save_results(results: List[ScanResult], output_file: str):
    if output_file.endswith('.json'):
        with open(output_file, 'w') as file:
            json.dump([result.to_dict() for result in results], file, indent=4)
    elif output_file.endswith('.csv'):
        with open(output_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Domain", "IP", "Server", "Ports", "TLSVersions", "CipherSuites", "ALPNProtocols", "ESNI", "ECH"])
            for result in results:
                writer.writerow([
                    result.domain,
                    result.ip,
                    result.server,
                    ', '.join(map(str, result.ports)),
                    ', '.join(result.tls_versions),
                    ', '.join(result.cipher_suites),
                    ', '.join(result.alpn_protocols),
                    result.esni,
                    result.ech
                ])
    else:
        logging.error(f"Unsupported output format: {output_file}")


async def scan_port(domain: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.open_connection(domain, port)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def scan_domain(domain: str, start_port: int, end_port: int, semaphore: Semaphore) -> Optional[ScanResult]:
    async with semaphore:
        result = ScanResult(domain=domain)
        try:
            result.ip = socket.gethostbyname(domain)
        except socket.gaierror as e:
            logging.error(f"Error resolving IP for {domain}: {e}")
            return None

        # TLS Details
        try:
            context = ssl.create_default_context()
            reader, writer = await asyncio.open_connection(domain, 443)
            tls = context.wrap_socket(writer.get_extra_info('socket'), server_hostname=domain)
            result.server = tls.server_hostname
            result.tls_versions.append(tls.version())
            result.cipher_suites.append(tls.cipher()[0])
            result.alpn_protocols.append(tls.selected_alpn_protocol() or "")
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logging.warning(f"TLS error on {domain}: {e}")

        # Port Scanning
        ports = [port for port in range(start_port, end_port + 1)]
        tasks = [scan_port(domain, port) for port in ports]
        results = await asyncio.gather(*tasks)
        result.ports = [port for port, is_open in zip(ports, results) if is_open]

        # ESNI/ECH Checks
        result.esni = await check_esni(domain)
        result.ech = await check_ech(domain)

        return result


async def check_esni(domain: str) -> bool:
    # Placeholder for actual ESNI check logic
    logging.info(f"Checking ESNI for {domain}...")
    await asyncio.sleep(0.1)  # Simulate time delay
    return False


async def check_ech(domain: str) -> bool:
    # Placeholder for actual ECH check logic
    logging.info(f"Checking ECH for {domain}...")
    await asyncio.sleep(0.1)  # Simulate time delay
    return False


async def main(input_path: str, start_port: int, end_port: int, output: str, rate_limit: int):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    domains = await load_domains(input_path)
    results = []
    semaphore = Semaphore(rate_limit)

    tasks = [scan_domain(domain, start_port, end_port, semaphore) for domain in domains]
    for task in asyncio.as_completed(tasks):
        result = await task
        if result:
            results.append(result)

    await save_results(results, output)
    logging.info(f"Results saved to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced SNI Bug Finder Tool")
    parser.add_argument("-i", "--input", required=True, help="Domain or file containing domains")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start of port range")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End of port range")
    parser.add_argument("-o", "--output", default="results.json", help="Output file")
    parser.add_argument("-r", "--rate", type=int, default=100, help="Rate limit (requests per second)")
    args = parser.parse_args()

    asyncio.run(main(args.input, args.start, args.end, args.output, args.rate))
