# pqCTLOG

A streamlined tool for analyzing certificates from Certificate Transparency logs to identify quantum-vulnerable certificates and assess post-quantum readiness.

## Features

- **Certificate Analysis**
  - Search certificates by domain using crt.sh
  - Parse and analyze certificate details
  - Identify quantum-vulnerable signature algorithms
  - Extract Subject Alternative Names and validity information

- **Data Storage**
  - Store certificate data in OpenSearch
  - Efficient bulk indexing with batching
  - Structured data models with validation

- **Configuration Management**
  - Centralized configuration with Pydantic validation
  - Environment variable support
  - Multiple configuration file locations

## Prerequisites

- Python 3.8+
- Docker and Docker Compose (for OpenSearch)
- OpenSearch 2.0+

## Quick Start

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

4. **Start OpenSearch**
   ```bash
   docker-compose up -d
   ```

5. **Search for certificates**
   ```bash
   python -m src.main --domain example.com
   ```

### Configuration

The application uses `config/config.yaml` for configuration. You can also set environment variables:

```bash
export PQCTLOG_OPENSEARCH_HOST=localhost
export PQCTLOG_OPENSEARCH_PORT=9200
export PQCTLOG_LOG_LEVEL=DEBUG
```

## Project Structure

```
pqctlog/
├── config/                  # Configuration files
│   └── config.yaml          # Main configuration
├── src/                     # Source code
│   ├── core/                # Core utilities and shared components
│   │   ├── config.py        # Centralized configuration management
│   │   ├── utils.py         # Common utility functions
│   │   └── certificate_parser.py  # Consolidated certificate parsing
│   ├── ctlog/               # Certificate Transparency clients
│   │   └── simplified_crtsh_client.py  # Simplified crt.sh client
│   ├── storage/             # Data storage (OpenSearch)
│   │   └── opensearch_client.py
│   └── main.py              # Main application entry point
├── tests/                   # Unit tests
├── scripts/                 # Utility scripts
├── docker-compose.yml       # OpenSearch services
└── requirements.txt         # Python dependencies
```

## Usage

### Command Line Options

```bash
python -m src.main --help
```

Options:
- `--domain`: Domain name to search for (required)
- `--exclude-expired`: Exclude expired certificates
- `--include-precerts`: Include pre-certificates
- `--download-full-certs`: Download and parse full certificate details (slower)
- `--log-level`: Set logging level (DEBUG, INFO, WARNING, ERROR)
- `--config`: Path to configuration file

### Performance Notes

By default, the application only fetches basic certificate information from crt.sh search results, which is fast and efficient. This includes:
- Certificate ID and serial number
- Issuer and subject information
- Validity dates
- Subject Alternative Names
- Entry type (certificate vs pre-certificate)

Use `--download-full-certs` only when you need detailed information like:
- Signature algorithms and quantum vulnerability analysis
- Public key details and sizes
- Certificate extensions
- Fingerprints

**Performance comparison:**
- Basic search: ~1-2 seconds for 100 certificates
- Full certificate download: ~30-60 seconds for 100 certificates (due to individual downloads)

## Index Management

### Clear the certificates index
```bash
# Clear all documents from the certificates index
python scripts/manage_index.py clear

# Clear a specific index
python scripts/manage_index.py --index scan_results clear
```

### Delete an index entirely
```bash
# Delete the certificates index (with confirmation)
python scripts/manage_index.py delete

# Delete a specific index
python scripts/manage_index.py --index scan_results delete
```

### View index statistics
```bash
# Show statistics for certificates index
python scripts/manage_index.py stats

# Show statistics for all indices
python scripts/manage_index.py list
```

### Direct OpenSearch commands
You can also use curl commands directly:

```bash
# Clear certificates index
curl -X POST "localhost:9200/pqctlog_certificates/_delete_by_query" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}}'

# Delete certificates index entirely
curl -X DELETE "localhost:9200/pqctlog_certificates"

# Get index statistics
curl -X GET "localhost:9200/pqctlog_certificates/_stats"
```

### Examples

```bash
# Search for certificates for example.com (basic info only - fast)
python -m src.main --domain example.com

# Exclude expired certificates
python -m src.main --domain example.com --exclude-expired

# Include pre-certificates and set debug logging
python -m src.main --domain example.com --include-precerts --log-level DEBUG

# Download full certificate details (slower but more complete)
python -m src.main --domain example.com --download-full-certs
```

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Quality

```bash
# Format code
black src/ tests/

# Sort imports  
isort src/ tests/

# Type checking
mypy src/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### 1. Clone the Repository

```bash
git clone https://github.com/wilsonstuart/pqCTLOG.git
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
