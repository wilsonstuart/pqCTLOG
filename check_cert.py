import logging
from src.ctlog.simplified_crtsh_client import SimplifiedCRTshClient
from src.storage.opensearch_client import OpenSearchClient
from src.core.config import load_config
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
config = load_config()
crtsh_client = SimplifiedCRTshClient()
os_client = OpenSearchClient(config)

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

# Try to download the certificate directly from crt.sh
logger.info("Downloading certificate directly from crt.sh...")
try:
    cert_data = crtsh_client._download_certificate(cert_id)
    if cert_data:
        logger.info("Downloaded certificate data from crt.sh:")
        logger.info(json.dumps(cert_data, indent=2, default=str))
    else:
        logger.warning("No data returned from crt.sh")
except Exception as e:
    logger.error(f"Error downloading from crt.sh: {e}", exc_info=True)

logger.info("Script completed")
