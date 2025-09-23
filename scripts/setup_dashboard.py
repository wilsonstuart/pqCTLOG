"""Script to set up OpenSearch Dashboards for Post-Quantum certificate analysis."""
import json
import os
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
OPENSEARCH_HOST = os.getenv('OPENSEARCH_HOST', 'http://localhost:9200')
DASHBOARDS_HOST = os.getenv('DASHBOARDS_HOST', 'http://localhost:5601')
OPENSEARCH_USER = os.getenv('OPENSEARCH_USER', 'admin')
OPENSEARCH_PASSWORD = os.getenv('OPENSEARCH_PASSWORD', 'admin')
INDEX_PATTERN = 'pqctlog_certificates*'

# Headers for OpenSearch Dashboards API
HEADERS = {
    'kbn-xsrf': 'true',
    'Content-Type': 'application/json',
    'osd-xsrf': 'true'
}

def get_auth():
    """Get authentication for OpenSearch requests."""
    return HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASSWORD)

def create_index_pattern():
    """Create index pattern in OpenSearch Dashboards."""
    url = f"{DASHBOARDS_HOST}/api/saved_objects/index-pattern/certificates"
    data = {
        'attributes': {
            'title': INDEX_PATTERN,
            'timeFieldName': 'not_after'
        }
    }
    
    try:
        response = requests.post(
            url,
            headers=HEADERS,
            json=data,
            auth=get_auth(),
            verify=False
        )
        response.raise_for_status()
        print("✅ Successfully created index pattern")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating index pattern: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        return None

def create_visualization(vis_data):
    """Create a visualization in OpenSearch Dashboards."""
    url = f"{DASHBOARDS_HOST}/api/saved_objects/visualization/{vis_data['id']}"
    
    # Prepare the request body
    request_body = {
        'attributes': vis_data['attributes'],
        'references': vis_data.get('references', [])
    }
    
    try:
        response = requests.post(
            url,
            headers=HEADERS,
            json=request_body,
            auth=get_auth(),
            verify=False
        )
        response.raise_for_status()
        print(f"✅ Successfully created visualization: {vis_data['id']}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating visualization {vis_data['id']}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        return None

def create_dashboard():
    """Create the main dashboard."""
    dashboard = {
        'attributes': {
            'title': 'Post-Quantum Certificate Compliance',
            'description': 'Dashboard showing Post-Quantum compliance status of certificates',
            'panelsJSON': json.dumps([
                {
                    'panelIndex': '1',
                    'gridData': {'x': 0, 'y': 0, 'w': 24, 'h': 10, 'i': '1'},
                    'version': '7.10.2',
                    'type': 'visualization',
                    'id': 'compliance-levels'
                },
                {
                    'panelIndex': '2',
                    'gridData': {'x': 0, 'y': 10, 'w': 24, 'h': 10, 'i': '2'},
                    'version': '7.10.2',
                    'type': 'visualization',
                    'id': 'algorithms-distribution'
                }
            ]),
            'optionsJSON': '{"darkTheme": false}',
            'version': 1,
            'timeRestore': False,
            'kibanaSavedObjectMeta': {
                'searchSourceJSON': json.dumps({
                    'query': {'query': '', 'language': 'kuery'},
                    'filter': []
                })
            }
        },
        'references': [
            {
                'name': 'certificates',
                'type': 'index-pattern',
                'id': 'certificates'
            }
        ]
    }
    
    url = f"{DASHBOARDS_HOST}/api/saved_objects/dashboard/pq-compliance-dashboard"
    
    # Prepare the request body
    request_body = {
        'attributes': dashboard['attributes'],
        'references': dashboard.get('references', [])
    }
    
    try:
        response = requests.post(
            url,
            headers=HEADERS,
            json=request_body,
            auth=get_auth(),
            verify=False
        )
        response.raise_for_status()
        print("✅ Successfully created dashboard")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error creating dashboard: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        return None

def main():
    """Main function to set up the dashboard."""
    print("🚀 Setting up OpenSearch Dashboard...")
    
    # Disable SSL warnings for self-signed certificates
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # 1. Create index pattern
    print("\n🔍 Creating index pattern...")
    create_index_pattern()
    
    # 2. Create visualizations
    print("\n📊 Creating visualizations...")
    
    # Compliance Levels Pie Chart
    compliance_vis = {
        'id': 'compliance-levels',
        'type': 'visualization',
        'attributes': {
            'title': 'Compliance Levels',
            'visState': json.dumps({
                'type': 'pie',
                'params': {
                    'type': 'pie',
                    'addTooltip': True,
                    'addLegend': True,
                    'isDonut': True,
                    'labels': {
                        'show': True,
                        'values': True,
                        'last_level': True,
                        'truncate': 100
                    }
                },
                'aggs': [
                    {
                        'id': '1',
                        'enabled': True,
                        'type': 'count',
                        'schema': 'metric',
                        'params': {}
                    },
                    {
                        'id': '2',
                        'enabled': True,
                        'type': 'terms',
                        'schema': 'segment',
                        'params': {
                            'field': 'compliance.compliance_level',
                            'orderBy': '1',
                            'order': 'desc',
                            'size': 5,
                            'otherBucket': True,
                            'otherBucketLabel': 'Other',
                            'missingBucket': False
                        }
                    }
                ]
            }),
            'uiStateJSON': '{}',
            'description': 'Distribution of certificate compliance levels',
            'version': 1,
            'kibanaSavedObjectMeta': {
                'searchSourceJSON': json.dumps({
                    'index': 'certificates',
                    'query': {'query': '', 'language': 'kuery'},
                    'filter': []
                })
            }
        },
        'references': [
            {
                'name': 'certificates',
                'type': 'index-pattern',
                'id': 'certificates'
            }
        ]
    }
    create_visualization(compliance_vis)
    
    # Algorithms Distribution Bar Chart
    algorithms_vis = {
        'id': 'algorithms-distribution',
        'type': 'visualization',
        'attributes': {
            'title': 'Signature Algorithms Distribution',
            'visState': json.dumps({
                'type': 'histogram',
                'params': {
                    'type': 'histogram',
                    'grid': {'categoryLines': False},
                    'categoryAxes': [
                        {
                            'id': 'CategoryAxis-1',
                            'type': 'category',
                            'position': 'bottom',
                            'show': True,
                            'style': {},
                            'scale': {'type': 'linear'},
                            'labels': {'show': True, 'truncate': 100},
                            'title': {}
                        }
                    ],
                    'valueAxes': [
                        {
                            'id': 'ValueAxis-1',
                            'name': 'LeftAxis-1',
                            'type': 'value',
                            'position': 'left',
                            'show': True,
                            'style': {},
                            'scale': {'type': 'linear', 'mode': 'normal'},
                            'labels': {'show': True, 'rotate': 0, 'filter': False, 'truncate': 100},
                            'title': {'text': 'Count'}
                        }
                    ],
                    'seriesParams': [
                        {
                            'show': True,
                            'type': 'histogram',
                            'mode': 'stacked',
                            'data': {'label': 'Count', 'id': '1'},
                            'valueAxis': 'ValueAxis-1',
                            'drawLinesBetweenPoints': True,
                            'lineWidth': 2,
                            'showCircles': True,
                            'interpolate': 'linear'
                        }
                    ],
                    'addTooltip': True,
                    'addLegend': True,
                    'legendPosition': 'right',
                    'times': [],
                    'addTimeMarker': False
                },
                'aggs': [
                    {
                        'id': '1',
                        'enabled': True,
                        'type': 'count',
                        'schema': 'metric',
                        'params': {}
                    },
                    {
                        'id': '2',
                        'enabled': True,
                        'type': 'terms',
                        'schema': 'segment',
                        'params': {
                            'field': 'signature_algorithm.name',
                            'orderBy': '1',
                            'order': 'desc',
                            'size': 10,
                            'otherBucket': False,
                            'otherBucketLabel': 'Other',
                            'missingBucket': False
                        }
                    }
                ]
            }),
            'uiStateJSON': '{}',
            'description': 'Distribution of signature algorithms',
            'version': 1,
            'kibanaSavedObjectMeta': {
                'searchSourceJSON': json.dumps({
                    'index': 'certificates',
                    'query': {'query': '', 'language': 'kuery'},
                    'filter': []
                })
            }
        },
        'references': [
            {
                'name': 'certificates',
                'type': 'index-pattern',
                'id': 'certificates'
            }
        ]
    }
    create_visualization(algorithms_vis)
    
    # 3. Create dashboard
    print("\n📋 Creating dashboard...")
    create_dashboard()
    
    print("\n✨ Dashboard setup complete!")
    print(f"🌐 Access your dashboard at: {DASHBOARDS_HOST}/app/dashboards#/view/pq-compliance-dashboard")

if __name__ == "__main__":
    main()
