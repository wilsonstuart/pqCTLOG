"""
OpenSearch client for storing and querying certificate and scan data.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from opensearchpy import OpenSearch
from opensearchpy.helpers import bulk

from src.core.config import AppConfig

logger = logging.getLogger(__name__)

class OpenSearchClient:
    """Client for interacting with OpenSearch."""
    
    def __init__(self, config: AppConfig):
        """Initialize the OpenSearch client.
        
        Args:
            config: Application configuration object.
        """
        self.config = config.opensearch
        self.client = self._create_client()
        self.index_prefix = self.config.index_prefix
        self._indices_created = False
    
    def bulk_index(self, index: str, documents: List[Dict], id_field: str = 'id', batch_size: int = 100) -> int:
        """Index multiple documents in bulk with batching.
        
        Args:
            index: The name of the index to index documents into
            documents: List of documents to index
            id_field: Field to use as document ID
            batch_size: Number of documents to process in each batch
            
        Returns:
            Number of successfully indexed documents
        """
        if not documents:
            return 0
        
        self._ensure_indices()
        full_index_name = f"{self.index_prefix}{index}"
        total_success = 0
        
        # Process documents in batches
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            actions = []
            
            for doc in batch:
                doc_id = str(doc.get(id_field, ''))
                if not doc_id:
                    logger.warning(f"Document missing {id_field} field, skipping")
                    continue
                
                # Add timestamps
                now = datetime.utcnow().isoformat()
                doc.setdefault('created_at', now)
                doc['updated_at'] = now
                
                actions.append({
                    "_index": full_index_name,
                    "_id": doc_id,
                    "_source": doc
                })
            
            if actions:
                try:
                    success, failed = bulk(
                        self.client, 
                        actions,
                        chunk_size=batch_size,
                        request_timeout=60,
                        max_retries=3,
                        initial_backoff=2,
                        max_backoff=600
                    )
                    total_success += success
                    
                    if failed:
                        logger.warning(f"Failed to index {len(failed)} documents in batch")
                        
                except Exception as e:
                    logger.error(f"Error bulk indexing batch {i//batch_size + 1}: {str(e)}")
                    continue
        
        logger.info(f"Successfully indexed {total_success} documents into {full_index_name}")
        return total_success

    def _create_client(self) -> OpenSearch:
        """Create and configure the OpenSearch client."""
        hosts = [{
            'host': self.config.host,
            'port': self.config.port
        }]
        logger.info(f"Connecting to OpenSearch at {self.config.host}:{self.config.port}")
        
        http_auth = None
        if self.config.http_auth:
            http_auth = (self.config.http_auth.username, self.config.http_auth.password)
        
        return OpenSearch(
            hosts=hosts,
            http_auth=http_auth,
            use_ssl=self.config.use_ssl,
            verify_certs=self.config.verify_certs,
            ssl_show_warn=False,
            timeout=self.config.timeout,
            max_retries=self.config.max_retries,
            retry_on_timeout=True
        )
    
    def _ensure_indices(self) -> None:
        """Ensure that the required indices exist with proper mappings."""
        if self._indices_created:
            return
            
        self._ensure_index('certificates', self._get_certificate_mapping())
        self._ensure_index('scan_results', self._get_scan_result_mapping())
        self._indices_created = True
    
    def _ensure_index(self, index_name: str, mapping: Dict[str, Any]) -> None:
        """Ensure that an index exists with the given mapping.
        
        Args:
            index_name: Base name of the index
            mapping: Index mapping
        """
        full_index_name = f"{self.index_prefix}{index_name}"
        
        try:
            if not self.client.indices.exists(index=full_index_name):
                # Create the index with the mapping
                self.client.indices.create(
                    index=full_index_name,
                    body={
                        'mappings': mapping,
                        'settings': {
                            'index': {
                                'number_of_shards': 1,
                                'number_of_replicas': 0
                            }
                        }
                    }
                )
                logger.info(f"Created index: {full_index_name}")
            else:
                # Update the mapping if needed
                current_mapping = self.client.indices.get_mapping(index=full_index_name)
                if 'mappings' in current_mapping.get(full_index_name, {}):
                    current_mapping = current_mapping[full_index_name]['mappings']
                    
                    # Check if we need to update the mapping
                    update_needed = False
                    for field, field_mapping in mapping.get('properties', {}).items():
                        if field not in current_mapping.get('properties', {}):
                            update_needed = True
                            break
                    
                    if update_needed:
                        # Remove the type name from the mapping if it exists
                        if '_doc' in mapping:
                            mapping = mapping['_doc']
                        
                        # Update the mapping
                        self.client.indices.put_mapping(
                            index=full_index_name,
                            body=mapping
                        )
                        logger.info(f"Updated mapping for index: {full_index_name}")
        except Exception as e:
            logger.error(f"Failed to ensure index {full_index_name}: {e}")
            raise
    
    def _get_certificate_mapping(self) -> Dict:
        """Get the mapping for the certificates index."""
        return {
            'properties': {
                'serial_number': {'type': 'keyword'},
                'issuer': {
                    'properties': {
                        'commonName': {'type': 'keyword'},
                        'organizationName': {'type': 'keyword'},
                        'organizationalUnitName': {'type': 'keyword'},
                        'countryName': {'type': 'keyword'},
                        'localityName': {'type': 'keyword'},
                        'stateOrProvinceName': {'type': 'keyword'},
                        'emailAddress': {'type': 'keyword'}
                    }
                },
                'subject': {
                    'properties': {
                        'commonName': {'type': 'keyword'},
                        'organizationName': {'type': 'keyword'},
                        'organizationalUnitName': {'type': 'keyword'},
                        'countryName': {'type': 'keyword'},
                        'localityName': {'type': 'keyword'},
                        'stateOrProvinceName': {'type': 'keyword'},
                        'emailAddress': {'type': 'keyword'}
                    }
                },
                'subject_alternative_names': {'type': 'keyword'},
                'signature_algorithm': {
                    'properties': {
                        'name': {'type': 'keyword'},
                        'is_quantum_vulnerable': {'type': 'boolean'},
                        'is_post_quantum': {'type': 'boolean'},
                        'pq_algorithm_type': {'type': 'keyword'},  # e.g., 'lattice', 'hash', 'code'
                        'security_level': {'type': 'integer'}  # Security level in bits
                    }
                },
                'tls_scan': {
                    'properties': {
                        'hostname': {'type': 'keyword'},
                        'ip_address': {'type': 'ip'},
                        'port': {'type': 'integer'},
                        'supported_versions': {'type': 'keyword'},
                        'is_post_quantum': {'type': 'boolean'},
                        'security_level': {'type': 'keyword'},
                        'preferred_cipher': {'type': 'object'},
                        'supported_ciphers': {
                            'type': 'nested',
                            'properties': {
                                'name': {'type': 'keyword'},
                                'bits': {'type': 'integer'},
                                'tls_version': {'type': 'keyword'},
                                'security_level': {'type': 'keyword'},
                                'is_post_quantum': {'type': 'boolean'}
                            }
                        },
                        'scan_timestamp': {'type': 'date'},
                        'scan_errors': {'type': 'keyword'}
                    }
                },
                'compliance': {
                    'properties': {
                        'post_quantum': {
                            'type': 'boolean',
                            'doc_values': True
                        },
                        'compliance_level': {
                            'type': 'keyword',  # e.g., 'pq_secure', 'hybrid', 'classical', 'deprecated'
                            'doc_values': True
                        },
                        'last_verified': {
                            'type': 'date',
                            'format': 'strict_date_optional_time||epoch_millis'
                        }
                    }
                },
                'validity': {
                    'properties': {
                        'not_before': {'type': 'date'},
                        'not_after': {'type': 'date'},
                        'is_valid': {'type': 'boolean'}
                    }
                },
                'public_key': {
                    'properties': {
                        'type': {'type': 'keyword'},
                        'key_size': {'type': 'integer'},
                        'curve': {'type': 'keyword'}
                    }
                },
                'is_self_signed': {'type': 'boolean'},
                'is_precertificate': {'type': 'boolean', 'doc_values': True},
                'key_usage': {'type': 'keyword'},
                'extended_key_usage': {'type': 'keyword'},
                'basic_constraints': {
                    'properties': {
                        'is_ca': {'type': 'boolean'},
                        'path_length': {'type': 'integer'}
                    }
                },
                'ct_log_entries': {
                    'properties': {
                        'log_id': {'type': 'keyword'},
                        'timestamp': {'type': 'date'},
                        'entry_type': {'type': 'keyword'}
                    }
                },
                'created_at': {'type': 'date'},
                'updated_at': {'type': 'date'}
            }
        }
    
    def _get_scan_result_mapping(self) -> Dict:
        """Get the mapping for the scan_results index."""
        return {
            'properties': {
                'domain': {'type': 'keyword'},
                'timestamp': {'type': 'date'},
                'ports': {
                    'properties': {
                        'port': {'type': 'integer'},
                        'supported_ciphersuites': {
                            'properties': {
                                'name': {'type': 'keyword'},
                                'tls_version': {'type': 'keyword'},
                                'security': {'type': 'keyword'},
                                'is_quantum_safe': {'type': 'boolean'}
                            }
                        },
                        'tls_versions': {
                            'properties': {
                                'version': {'type': 'keyword'},
                                'supported': {'type': 'boolean'}
                            }
                        },
                        'error': {'type': 'text'}
                    }
                },
                'created_at': {'type': 'date'}
            }
        }
    
    def _validate_certificate_data(self, cert_data: Dict) -> bool:
        """Validate the certificate data structure.
        
        Args:
            cert_data: Certificate data to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        required_fields = ['id', 'serial_number', 'issuer', 'subject']
        for field in required_fields:
            if field not in cert_data:
                logger.error(f"Missing required field in certificate data: {field}")
                # Log the available fields for debugging
                available_fields = list(cert_data.keys())
                logger.error(f"Available fields: {available_fields}")
                return False
        
        # Validate issuer and subject are dictionaries with commonName
        for field in ['issuer', 'subject']:
            if not isinstance(cert_data[field], dict):
                logger.error(f"{field} must be a dictionary")
                return False
            if 'commonName' not in cert_data[field]:
                cert_data[field]['commonName'] = ''
        
        # Validate signature_algorithm structure
        if 'signature_algorithm' not in cert_data:
            cert_data['signature_algorithm'] = {}
        
        sig_algo = cert_data['signature_algorithm']
        if not isinstance(sig_algo, dict):
            logger.error("signature_algorithm must be a dictionary")
            return False
            
        # Set default values for signature_algorithm if not present
        sig_algo.setdefault('name', '')
        sig_algo.setdefault('is_quantum_vulnerable', False)
        sig_algo.setdefault('is_post_quantum', False)
        sig_algo.setdefault('pq_algorithm_type', None)
        sig_algo.setdefault('security_level', None)
        
        # Validate validity period
        if 'validity' not in cert_data:
            cert_data['validity'] = {}
            
        validity = cert_data['validity']
        if not isinstance(validity, dict):
            logger.error("validity must be a dictionary")
            return False
            
        # Set default values for all validity fields
        validity.setdefault('start', None)
        validity.setdefault('end', None)
        validity.setdefault('not_before', None)
        validity.setdefault('not_after', None)
        validity.setdefault('is_valid', False)
        
        # Ensure backward compatibility by copying not_before/not_after to start/end if not set
        if validity.get('not_before') is not None and validity.get('start') is None:
            validity['start'] = validity['not_before']
        if validity.get('not_after') is not None and validity.get('end') is None:
            validity['end'] = validity['not_after']
        
        return True
    
    def index_certificate(self, cert_data: Dict) -> bool:
        """Index a certificate in OpenSearch.
        
        Args:
            cert_data: Certificate data to index. Must include at minimum:
                      - id (str): Unique identifier for the certificate
                      - serial_number (str): Certificate serial number
                      - issuer (dict): Certificate issuer information
                      - subject (dict): Certificate subject information
                      
        Returns:
            bool: True if indexing was successful, False otherwise
            
        Raises:
            ValueError: If certificate data is invalid
        """
        if not cert_data:
            logger.error("No certificate data provided")
            return False
            
        # Make a copy to avoid modifying the original
        cert_data = cert_data.copy()
        
        # Log the raw certificate data for debugging
        logger.debug("Raw certificate data before validation:")
        import json
        logger.debug(json.dumps(cert_data, indent=2, default=str, ensure_ascii=False))
        
        # Validate the certificate data structure
        if not self._validate_certificate_data(cert_data):
            logger.error("Invalid certificate data structure")
            # Log the problematic certificate data
            logger.error("Problematic certificate data:")
            logger.error(json.dumps(cert_data, indent=2, default=str, ensure_ascii=False))
            return False
            
        index_name = f"{self.index_prefix}certificates"
        doc_id = str(cert_data['serial_number'])  # Ensure doc_id is a string
        
        # Add timestamps
        now = datetime.utcnow().isoformat()
        cert_data['created_at'] = now
        cert_data['updated_at'] = now
        
        # Log the document being indexed
        logger.debug(f"Indexing certificate with ID: {doc_id}")
        if logger.isEnabledFor(logging.DEBUG):
            import json
            logger.debug("Certificate document to index:")
            logger.debug(json.dumps(cert_data, indent=2, default=str, ensure_ascii=False))
        
        try:
            # Ensure the index exists with the correct mapping
            self._ensure_indices()
            
            # Index the document
            response = self.client.index(
                index=index_name,
                id=doc_id,
                body=cert_data,
                refresh=True
            )
            
            result = response.get('result')
            if result in ('created', 'updated'):
                logger.debug(f"Successfully {result} certificate {doc_id}")
                return True
            else:
                logger.warning(f"Unexpected response when indexing certificate {doc_id}: {response}")
                return False
                
        except Exception as e:
            error_msg = f"Failed to index certificate {doc_id}: {str(e)}"
            logger.error(error_msg)
            
            # Extract and log detailed error information if available
            if hasattr(e, 'info') and 'error' in e.info:
                error_info = e.info['error']
                logger.error(f"OpenSearch error details: {json.dumps(error_info, indent=2, ensure_ascii=False)}")
                
                # Check for mapping issues
                if 'root_cause' in error_info and isinstance(error_info['root_cause'], list):
                    for cause in error_info['root_cause']:
                        if 'mapper_parsing_exception' in cause.get('type', ''):
                            field = cause.get('reason', 'unknown field')
                            logger.error(f"Mapping error in field: {field}")
                            
            # Log the problematic document
            if logger.isEnabledFor(logging.ERROR):
                import json
                logger.error("Certificate data that caused the error:")
                logger.error(json.dumps(cert_data, indent=2, default=str, ensure_ascii=False))
            
            logger.error("Full traceback:", exc_info=True)
            return False
    
    def index_scan_result(self, scan_result: Dict) -> bool:
        """Index a scan result in OpenSearch.
        
        Args:
            scan_result: Scan result data
            
        Returns:
            True if successful, False otherwise
        """
        if not scan_result or 'domain' not in scan_result:
            return False
        
        index_name = f"{self.index_prefix}scan_results"
        doc_id = f"{scan_result['domain']}_{int(scan_result.get('timestamp', 0))}"
        
        # Add timestamp
        scan_result['created_at'] = datetime.utcnow().isoformat()
        
        try:
            self.client.index(
                index=index_name,
                id=doc_id,
                document=scan_result,
                refresh=True
            )
            return True
        except Exception as e:
            logger.error(f"Failed to index scan result {doc_id}: {e}")
            return False
    
    def search_certificates_by_domain(self, domain: str, size: int = 100, exclude_expired: bool = False) -> List[Dict]:
        """Search for certificates by domain name.
        
        Args:
            domain: Domain name to search for (e.g., 'example.com')
            size: Maximum number of results to return
            exclude_expired: If True, exclude expired certificates
            
        Returns:
            List of certificates matching the domain
        """
        # Build a more comprehensive search query
        must_conditions = [
            {
                "bool": {
                    "should": [
                        {"wildcard": {"subject.commonName": f"*{domain}*"}},
                        {"wildcard": {"subject_common_name": f"*{domain}*"}},
                        {"wildcard": {"subject_alternative_names": f"*{domain}*"}},
                        {"wildcard": {"extensions.subjectAltName": f"*{domain}*"}},
                        {"query_string": {"query": f"*{domain}*", "fields": ["subject.commonName", "subject_common_name", "subject_alternative_names"]}}
                    ],
                    "minimum_should_match": 1
                }
            }
        ]
        
        # Add filter for non-expired certificates if requested
        if exclude_expired:
            must_conditions.append({
                "range": {
                    "validity.not_after": {
                        "gte": "now"
                    }
                }
            })
        
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [
                {"not_before": {"order": "desc"}}
            ]
        }
        
        return self.search_certificates(query, size)
        
    def search_certificates(self, query: Dict, size: int = 100) -> List[Dict]:
        """Search for certificates using a custom query.
        
        Args:
            query: Elasticsearch query DSL
            size: Maximum number of results to return
            
        Returns:
            List of matching certificates
        """
        index_name = f"{self.index_prefix}certificates"
        
        try:
            response = self.client.search(
                index=index_name,
                body=query,
                size=size
            )
            return [hit['_source'] for hit in response.get('hits', {}).get('hits', [])]
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    def get_certificate(self, serial_number: str) -> Optional[Dict]:
        """Get a certificate by serial number.
        
        Args:
            serial_number: Certificate serial number
            
        Returns:
            Certificate data if found, None otherwise
        """
        index_name = f"{self.index_prefix}certificates"
        
        try:
            response = self.client.get(
                index=index_name,
                id=str(serial_number)
            )
            return response['_source']
        except Exception:
            return None
    
    def get_scan_results_by_domain(self, domain: str, limit: int = 10) -> List[Dict]:
        """Get scan results for a domain.
        
        Args:
            domain: Domain name
            limit: Maximum number of results to return
            
        Returns:
            List of scan results for the domain
        """
        index_name = f"{self.index_prefix}scan_results"
        
        query = {
            'query': {
                'term': {
                    'domain': domain
                }
            },
            'sort': [
                {'timestamp': {'order': 'desc'}}
            ],
            'size': limit
        }
        
        try:
            response = self.client.search(
                index=index_name,
                body=query
            )
            return [hit['_source'] for hit in response.get('hits', {}).get('hits', [])]
        except Exception as e:
            logger.error(f"Failed to get scan results for {domain}: {e}")
            return []
    
    def get_vulnerable_certificates(self, limit: int = 100) -> List[Dict]:
        """Get certificates with quantum-vulnerable algorithms.
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of vulnerable certificates
        """
        query = {
            'query': {
                'term': {
                    'signature_algorithm.is_quantum_vulnerable': True
                }
            },
            'sort': [
                {'created_at': {'order': 'desc'}}
            ],
            'size': limit
        }
        
        return self.search_certificates(query, limit)
    
    def get_certificates_expiring_soon(self, days: int = 30, limit: int = 100) -> List[Dict]:
        """Get certificates that will expire within the specified number of days.
        
        Args:
            days: Number of days to look ahead for expiring certificates
            limit: Maximum number of results to return
            
        Returns:
            List of expiring certificates
        """
        now = datetime.utcnow().isoformat()
        later = (datetime.utcnow() + timedelta(days=days)).isoformat()
        
        query = {
            'query': {
                'range': {
                    'validity.not_after': {
                        'gte': now,
                        'lte': later
                    }
                }
            },
            'sort': [
                {'validity.not_after': {'order': 'asc'}}
            ],
            'size': limit
        }
        
        return self.search_certificates(query, limit)
    
    def clear_index(self, index: str) -> bool:
        """Clear all documents from an index.
        
        Args:
            index: Base name of the index to clear (without prefix)
            
        Returns:
            True if successful, False otherwise
        """
        full_index_name = f"{self.index_prefix}{index}"
        
        try:
            # Delete all documents using delete by query
            response = self.client.delete_by_query(
                index=full_index_name,
                body={
                    "query": {
                        "match_all": {}
                    }
                },
                refresh=True
            )
            
            deleted_count = response.get('deleted', 0)
            logger.info(f"Cleared {deleted_count} documents from index {full_index_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear index {full_index_name}: {e}")
            return False
    
    def delete_index(self, index: str) -> bool:
        """Delete an entire index.
        
        Args:
            index: Base name of the index to delete (without prefix)
            
        Returns:
            True if successful, False otherwise
        """
        full_index_name = f"{self.index_prefix}{index}"
        
        try:
            if self.client.indices.exists(index=full_index_name):
                self.client.indices.delete(index=full_index_name)
                logger.info(f"Deleted index {full_index_name}")
                return True
            else:
                logger.warning(f"Index {full_index_name} does not exist")
                return False
                
        except Exception as e:
            logger.error(f"Failed to delete index {full_index_name}: {e}")
            return False
    
    def get_index_stats(self, index: str) -> Dict[str, Any]:
        """Get statistics for an index.
        
        Args:
            index: Base name of the index (without prefix)
            
        Returns:
            Dictionary with index statistics
        """
        full_index_name = f"{self.index_prefix}{index}"
        
        try:
            if not self.client.indices.exists(index=full_index_name):
                return {"exists": False}
            
            stats = self.client.indices.stats(index=full_index_name)
            index_stats = stats['indices'][full_index_name]
            
            return {
                "exists": True,
                "document_count": index_stats['total']['docs']['count'],
                "size_in_bytes": index_stats['total']['store']['size_in_bytes'],
                "size_human": self._format_bytes(index_stats['total']['store']['size_in_bytes'])
            }
            
        except Exception as e:
            logger.error(f"Failed to get stats for index {full_index_name}: {e}")
            return {"exists": False, "error": str(e)}
    
    def _format_bytes(self, bytes_size: int) -> str:
        """Format bytes into human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} PB"
