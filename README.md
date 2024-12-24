
---

# Bugscanner - TLS & Port Scanning Tool

**Bugscanner** is a comprehensive domain and port scanning tool that allows users to identify open ports, extract TLS handshake details, and analyze the security aspects of websites. It supports checking for HTTP response status, extracting TLS versions, cipher suites, and various features like ESNI and ECH.

## Features

- Scans a domain or a list of domains for open ports.
- Extracts TLS handshake details (versions, cipher suites, ALPN protocols).
- Checks for HTTP response status.
- Optionally checks for ESNI and ECH support.
- Supports rate-limited scanning for performance.
- Outputs results in JSON or CSV format.
- Detailed logging for debugging and tracking errors.

## Prerequisites

Before using the Bugscanner tool, ensure you have the following:

- Python 3.7 or later.
- The following Python libraries:
  - `requests`
  - `socket`
  - `ssl`
  - `logging`
  
You can install the required dependencies with the following command:

```bash
pip install -r requirements.txt
```

## Installation

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/pk1151222/Bugscanner.git
   ```

2. Navigate to the project directory:

   ```bash
   cd Bugscanner
   ```

3. Install the required Python libraries:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Command Line Options

The `Bugscanner` tool can be invoked via the command line with the following options:

- **input**: Path to a file containing domains or a single domain to scan. (Required)
- **start_port**: Starting port number for the scan. Default is `1`.
- **end_port**: Ending port number for the scan. Default is `1024`.
- **output**: Output file to save the results (JSON or CSV format). Default is `results.json`.
- **rate_limit**: The number of simultaneous requests to allow. Default is `10`.

### Example Command Syntax

```bash
python bugscanner.py --input <domain_or_domains_file> --start_port <start_port> --end_port <end_port> --output <output_file> --rate_limit <rate_limit>
```

### Command Options

- `--input, -i`: The domain or file containing domains to scan (Required).
- `--start_port, -s`: Starting port number (default: `1`).
- `--end_port, -e`: Ending port number (default: `1024`).
- `--output, -o`: Output file (default: `results.json`).
- `--rate_limit, -r`: Rate limit for concurrent connections (default: `10`).
- `--help, -h`: Displays help information for using the tool.

### Example Commands

1. **Scan a single domain**:
   ```bash
   python bugscanner.py --input example.com --start_port 80 --end_port 443 --output results.json --rate_limit 5
   ```

2. **Scan multiple domains from a file**:
   ```bash
   python bugscanner.py --input domains.txt --start_port 1 --end_port 1024 --output results.csv --rate_limit 10
   ```

3. **Scan with a different rate limit**:
   ```bash
   python bugscanner.py --input example.com --start_port 1 --end_port 1024 --output results.csv --rate_limit 3
   ```

## Output Formats

You can save the results in two different formats: JSON or CSV. The output format is determined based on the file extension.

### JSON Output

Example of a JSON result:

```json
[
    {
        "Domain": "example.com",
        "IP": "93.184.216.34",
        "Server": "example.com",
        "Ports": [80, 443],
        "TLSVersions": ["TLSv1.2", "TLSv1.3"],
        "CipherSuites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        "ALPNProtocols": ["h2", "http/1.1"],
        "ESNI": false,
        "ECH": false,
        "HTTPStatus": "200 OK"
    }
]
```

### CSV Output

Example of a CSV result:

```csv
Domain,IP,Server,Ports,TLSVersions,CipherSuites,ALPNProtocols,ESNI,ECH,HTTPStatus
example.com,93.184.216.34,example.com,"[80, 443]","['TLSv1.2', 'TLSv1.3']","['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384']","['h2', 'http/1.1']",false,false,"200 OK"
```

## Logging and Debugging

Bugscanner provides detailed logging to track errors, progress, and debugging information.

- **Error Handling**: The tool captures connection errors, SSL/TLS handshake failures, and port scanning failures. Each error is logged with a specific message for better debugging.
- **Log Level**: The default log level is `INFO`, but you can set it to `DEBUG` for more detailed information during development.

Example log entry:

```text
Scanning domain: example.com
TLS version: TLSv1.3, Cipher Suite: TLS_AES_128_GCM_SHA256, ALPN: h2
Open ports: 80, 443
HTTP Response Status: 200 OK
```

## Error Handling

Bugscanner captures and logs various types of errors:

- **Connection Timeouts**: If the tool fails to connect to a domain within the specified timeout, an error will be logged.
- **SSL/TLS Errors**: Errors during the TLS handshake are caught and logged with details.
- **Port Scanning Failures**: Any issues encountered during the port scan (e.g., network errors) will be recorded.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

