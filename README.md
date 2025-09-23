# pqCTLOG

A tool for analyzing Certificate Transparency logs to identify quantum-vulnerable certificates and TLS configurations.

## Features

- **Certificate Transparency Log Analysis**
  - Fetch and parse certificates from multiple CT logs
  - Extract domain names and certificate details
  - Identify quantum-vulnerable algorithms and key types

- **TLS Configuration Scanning**
  - Scan domains for supported TLS ciphersuites
  - Check for weak or vulnerable cipher configurations
  - Identify quantum-vulnerable key exchange mechanisms

- **Data Storage & Analysis**
  - Store certificate and scan data in OpenSearch
  - Query and analyze data using OpenSearch Dashboards
  - Generate reports on security findings

- **Automation**
  - Continuous monitoring of CT logs
  - Scheduled scanning of domains
  - Alerting on security issues

## Prerequisites

- Python 3.8+
- Docker and Docker Compose (for running OpenSearch and OpenSearch Dashboards)
- OpenSearch 2.0+ (included in Docker setup)

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.8+

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/pqctlog.git
   cd pqctlog
   ```

2. **Set up a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Start the OpenSearch services**
   ```bash
   docker-compose up -d
   ```

5. **Initialize OpenSearch indices**
   ```bash
   python scripts/init_opensearch.py
   ```

6. **Run the application**
   ```bash
   python scripts/run_dev.py
   ```

### Using Docker Compose (All-in-One)

For a complete development environment with the application and all dependencies:

```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

This will start:
- OpenSearch on http://localhost:9200
- OpenSearch Dashboards on http://localhost:5601
- The pqCTLOG application

### Configuration

Edit `config/opensearch.yaml` to configure:
- OpenSearch connection settings
- CT Log endpoints
- Scanner settings
- Logging configuration

## Project Structure

```
pqctlog/
├── config/                  # Configuration files
│   └── opensearch.yaml      # Main configuration
├── docker/                  # Docker-related files
├── docs/                    # Documentation
├── scripts/                 # Utility scripts
├── src/                     # Source code
│   ├── ctlog/               # CT Log client and parser
│   ├── scanner/             # TLS scanner
│   ├── storage/             # Data storage (OpenSearch)
│   └── main.py              # Main application entry point
├── tests/                   # Unit and integration tests
├── .dockerignore
├── .gitignore
├── docker-compose.yml       # Production services
├── docker-compose.dev.yml   # Development overrides
├── Dockerfile               # Multi-stage Dockerfile
└── requirements.txt         # Python dependencies
```

## Development

### Running Tests

```bash
pytest tests/
```

### Linting and Code Style

```bash
# Auto-format code
black .

# Sort imports
isort .

# Check for style issues
flake8

# Type checking
mypy .
```

### Building for Production

```bash
docker build -t pqctlog:latest .
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/pqCTLOG.git
cd pqCTLOG
```

### 2. Set Up the Environment

Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### 3. Start OpenSearch and OpenSearch Dashboards

Start the services using Docker Compose:

```bash
docker-compose up -d
```

This will start:
- OpenSearch at http://localhost:9200
- OpenSearch Dashboards at http://localhost:5601

### 4. Configure the Application

Edit the configuration file at `config/config.yaml` to customize the settings:

```yaml
opensearch:
  host: "localhost"
  port: 9200
  use_ssl: false
  verify_certs: false
  http_auth:
    username: "admin"
    password: "admin"
  index_prefix: "pqctlog_"

# Add or modify CT logs to monitor
ct_logs: []  # Currently not used, as we're using crt.sh for certificate search

# Scanner configuration
scanner:
  max_entries: 1000  # Max entries to fetch per run
  scan_interval: 3600  # Time between scans in seconds
  worker_threads: 5    # Number of worker threads

# TLS scanner configuration
tls_scanner:
  timeout: 5  # Connection timeout in seconds
  ports: [443, 8443]  # Ports to scan for TLS
  ciphersuites:  # List of ciphersuites to test
    - "TLS_AES_128_GCM_SHA256"
    - "TLS_AES_256_GCM_SHA384"
    - "TLS_CHACHA20_POLY1305_SHA256"
    # ... more ciphersuites ...
```

### Searching for Certificates by Domain

Search for certificates containing a specific domain name:

```bash
# Include all certificates (including expired ones)
python -m src.main --search-dns example.com

# Exclude expired certificates
python -m src.main --search-dns example.com --exclude-expired
```

### Options for --search-dns
- `--exclude-expired`: Exclude expired certificates from the search results

This will search the crt.sh certificate database and display matching certificates.

### 5. Run the Application

Run the application in one-time mode:

```bash
python src/main.py --run-once
```

Or run it as a continuous service:

```bash
python src/main.py
```

### 6. View Results in OpenSearch Dashboards

1. Open OpenSearch Dashboards at http://localhost:5601
2. Navigate to "Discover" to explore the data
3. Create visualizations and dashboards to analyze the results

## Command Line Options

```
usage: main.py [-h] [--config CONFIG] [--log-level {DEBUG,INFO,WARNING,ERROR}]
               [--max-entries MAX_ENTRIES] [--scan-interval SCAN_INTERVAL]
               [--run-once]

pqCTLOG - Certificate Transparency Log Analyzer

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to configuration file
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        Set the logging level
  --max-entries MAX_ENTRIES
                        Maximum number of entries to fetch per CT log
  --scan-interval SCAN_INTERVAL
                        Time between scans in seconds
  --run-once            Run once and exit
```

## Data Model

### Certificates

Stored in the `pqctlog_certificates` index, containing:
- Certificate details (issuer, subject, validity period)
- Public key information
- Signature algorithm
- Certificate extensions
- CT log entry information

### Scan Results

Stored in the `pqctlog_scan_results` index, containing:
- Domain name
- Scan timestamp
- Supported TLS versions
- List of supported ciphersuites
- Security assessment

## Security Considerations

- The tool connects to public CT logs and scans publicly accessible services
- Use appropriate rate limiting to avoid overwhelming target systems
- Store sensitive configuration (e.g., API keys) securely using environment variables
- Configure proper authentication for OpenSearch in production environments

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Acknowledgments

- Certificate Transparency Project
- OpenSearch Community
- Cryptography.io for the Python cryptography library
