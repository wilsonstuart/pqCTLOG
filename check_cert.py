import logging
from src.ctlog.crtsh_client import CRTshClient
from src.storage.opensearch_client import OpenSearchClient
import json

# Set up logging to file
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='cert_debug.log',
    filemode='w'  # Overwrite the file each time
)

logger = logging.getLogger('pqctlog.crtsh')

# Create clients
crtsh_client = CRTshClient()
os_client = OpenSearchClient()

# Search for the specific certificate
cert_id = 15536323591
logger.info(f"Fetching certificate with ID: {cert_id}")

# Try to get the certificate from OpenSearch first
cert = os_client.client.get(
    index="pqctlog_certificates",
    id=str(cert_id),
    ignore=404  # Don't raise an error if not found
)

if cert and 'found' in cert and cert['found']:
    logger.info("Found certificate in OpenSearch:")
    logger.info(json.dumps(cert['_source'], indent=2))
else:
    logger.warning(f"Certificate {cert_id} not found in OpenSearch")

# Try to fetch the certificate directly from crt.sh
logger.info("Fetching certificate directly from crt.sh...")
try:
    cert_data = crtsh_client._get_certificate_details(cert_id)
    if cert_data:
        logger.info("Raw certificate data from crt.sh:")
        logger.info(json.dumps(cert_data, indent=2))
    else:
        logger.warning("No data returned from crt.sh")
except Exception as e:
    logger.error(f"Error fetching from crt.sh: {e}", exc_info=True)

# Process the certificate through _process_certificate to see the debug output
logger.info("Processing certificate through _process_certificate...")
try:
    # Create a mock certificate data structure
    mock_cert = {
        'id': cert_id,
        'issuer_ca_id': 107462,
        'issuer_name': 'C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018',
        'common_name': 'myfca.fca.org.uk',
        'name_value': 'api.myfca.fca.org.uk\nint-alb-api.myfca.fca.org.uk\nint-api.myfca.fca.org.uk\nmyfca.fca.org.uk\nwww.myfca.fca.org.uk',
        'entry_timestamp': '2024-11-28T18:01:08.068',
        'not_before': '2024-11-28T18:01:05',
        'not_after': '2025-12-30T18:01:04',
        'serial_number': '42cec779974970dea844eec5',
        'result_count': 6,
        '_exclude_precerts': False  # Make sure we don't exclude pre-certs
    }
    
    # Add entry_type to test if it's a pre-certificate
    mock_cert['entry_type'] = 1  # 1 indicates a pre-certificate
    
    processed = crtsh_client._process_certificate(mock_cert)
    if processed:
        logger.info("Processed certificate:")
        logger.info(json.dumps(processed, indent=2))
    else:
        logger.warning("Certificate was filtered out during processing")
        
except Exception as e:
    logger.error(f"Error processing certificate: {e}", exc_info=True)

logger.info("Script completed")
