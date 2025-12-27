"""
Clean up old Elasticsearch indices with wrong mappings
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv
from src.export.elasticsearch_exporter import ElasticsearchExporter  # ← ADD THIS
from elasticsearch import Elasticsearch

load_dotenv()

# Get credentials
es_host = os.getenv("ELASTICSEARCH_HOST", "localhost")
es_port = int(os.getenv("ELASTICSEARCH_PORT", "9200"))
es_username = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
es_password = os.getenv("ELASTICSEARCH_PASSWORD", "BCn06rNdLowb5UMQ+0-D")

print("Elasticsearch Cleanup Utility")
print("=" * 50)
print()

# Connect
es = Elasticsearch(
    hosts=[f"https://{es_host}:{es_port}"],
    basic_auth=(es_username, es_password),
    verify_certs=False,
    ssl_show_warn=False
)

print("1. Checking for old indices...")

try:
    # Get all ioc-* indices
    indices = es.indices.get(index="ioc-*")

    if not indices:
        print("   No IOC indices found")
    else:
        print(f"   Found {len(indices)} IOC indices:")
        for index_name in indices.keys():
            print(f"     - {index_name}")

        print()
        confirm = input("Delete these indices? (yes/no): ")

        if confirm.lower() == "yes":
            for index_name in indices.keys():
                es.indices.delete(index=index_name)
                print(f"   ✓ Deleted: {index_name}")
        else:
            print("   Cancelled")
except Exception as e:
    print(f"   No indices found or error: {e}")

print()
print("2. Creating new index template...")

try:
    exporter = ElasticsearchExporter(
        host=es_host,
        port=es_port,
        username=es_username,
        password=es_password
    )
    print("   ✓ Template created")
except Exception as e:
    print(f"   Error: {e}")

print()
print("=" * 50)
print("Ready! Run your collector now:")
print("  python scripts/run_collector.py")
