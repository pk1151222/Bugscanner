# Bugscanner
---

# SNI Bug Finder Tool

A powerful tool to scan domains for SNI (Server Name Indication) bugs, perform TLS version and cipher suite checks, and discover open ports. The tool includes rate limiting, ESNI/ECH checks, and supports saving results in both JSON and CSV formats.

## Features

- **Port Scanning:** Scans a range of ports for open services.
- **TLS Information Extraction:** Extracts TLS version, cipher suite, and ALPN protocols.
- **ESNI/ECH Detection:** Placeholder for ESNI (Encrypted Server Name Indication) and ECH (Encrypted ClientHello) checks.
- **Rate Limiting:** Controls the number of simultaneous requests.
- **File Input:** Supports scanning single domains or reading from a file.
- **Output Formats:** Saves results in JSON or CSV format.
- **Asynchronous Execution:** Fast domain scanning with `asyncio` for concurrent port scanning and DNS resolution.

## Prerequisites

- Python 3.6 or higher
- Required Python libraries:
  - `asyncio`
  - `socket`
  - `ssl`
  - `csv`
  - `json`

To install the dependencies, run:

```bash
pip install -r requirements.txt
```

Where `requirements.txt` should contain:

```
# Optional dependencies for future enhancements
aiohttp
```

## Usage

### Command Line Arguments

- `-i, --input <domain or file>`: The domain or file containing domains to scan. If a file is provided, each line should be a domain.
- `-s, --start <port>`: The starting port for the scan (default is 1).
- `-e, --end <port>`: The ending port for the scan (default is 1024).
- `-o, --output <output_file>`: The output file for storing results (`results.json` or `results.csv`).
- `-r, --rate <rate_limit>`: The maximum number of concurrent requests (default is 100).

### Example Usage

1. **Single Domain Scan**:
   ```bash
   python sni_bug_finder.py -i example.com -s 1 -e 1024 -o results.json -r 50
   ```

2. **Scan from a File** (each line contains a domain):
   ```bash
   python sni_bug_finder.py -i domains.txt -s 1 -e 1024 -o results.csv -r 100
   ```

3. **Custom Port Range and Rate Limit**:
   ```bash
   python sni_bug_finder.py -i example.com -s 80 -e 443 -o results.json -r 200
   ```

## ESNI and ECH Checks

The tool has placeholders for ESNI (Encrypted Server Name Indication) and ECH (Encrypted ClientHello) checks. These checks are designed to be implemented later and may require further dependencies, such as `scapy` for DNS queries.

## Output Formats

- **JSON**: Stores results in JSON format with detailed information about the domain.
- **CSV**: Stores results in CSV format with columns: Domain, IP, Server, Ports, TLSVersions, CipherSuites, ALPNProtocols, ESNI, ECH.

### Example Output (JSON)

```json
[
  {
    "Domain": "example.com",
    "IP": "93.184.216.34",
    "Server": "nginx",
    "Ports": [80, 443],
    "TLSVersions": ["TLSv1.2", "TLSv1.3"],
    "CipherSuites": ["TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
    "ALPNProtocols": ["h2", "http/1.1"],
    "ESNI": false,
    "ECH": false
  }
]
```

### Example Output (CSV)

```csv
Domain, IP, Server, Ports, TLSVersions, CipherSuites, ALPNProtocols, ESNI, ECH
example.com, 93.184.216.34, nginx, 80, 443, "TLSv1.2, TLSv1.3", "TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "h2, http/1.1", false, false
```

## Logging

The tool uses Python's built-in `logging` library for error reporting and progress tracking. Logs are displayed in the console during execution.

### Log Levels:
- `INFO`: General information, such as domain scanning progress.
- `WARNING`: Non-critical issues, such as TLS connection errors.
- `ERROR`: Critical issues, such as DNS resolution failures.

## Contributing

1. Fork this repository.
2. Create a new branch.
3. Implement your changes and improvements.
4. Submit a pull request.

We welcome contributions, especially for implementing ESNI/ECH detection, optimizing scanning techniques, or adding more features!

## License

This tool is open-source and available under the [MIT License](LICENSE).

---

This **README.md** provides comprehensive instructions on how to use, configure, and extend the tool. Let me know if you need further adjustments!
