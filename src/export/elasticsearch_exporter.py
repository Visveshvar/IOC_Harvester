"""
Export IOCs directly to Elasticsearch with SSL/TLS and Authentication
"""

import logging
from typing import List, Dict, Any
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class ElasticsearchExporter:
    """Export IOCs directly to Elasticsearch"""

    def __init__(self,
                 host: str = "localhost",
                 port: int = 9200,
                 username: str = "elastic",
                 password: str = "BCn06rNdLowb5UMQ+0-D",
                 verify_certs: bool = False):
        """
        Initialize Elasticsearch connection with SSL/TLS

        Args:
            host: Elasticsearch host
            port: Elasticsearch port
            username: Elasticsearch username
            password: Elasticsearch password
            verify_certs: Verify SSL certificates
        """
        try:
            # Build connection URL
            scheme = "https" if port == 9200 else "http"

            # Create Elasticsearch client with authentication
            self.es = Elasticsearch(
                hosts=[f"{scheme}://{host}:{port}"],
                basic_auth=(username, password),
                verify_certs=verify_certs,
                ssl_show_warn=False
            )

            # Test connection
            info = self.es.info()
            version = info['version']['number']
            logger.info(f"✓ Connected to Elasticsearch {version} at {scheme}://{host}:{port}")

            # Create index template (THIS IS NEW)
            self._create_index_template()

        except ConnectionError as e:
            logger.error(f"Connection error to Elasticsearch: {e}")
            raise
        except Exception as e:
            logger.error(f"Error connecting to Elasticsearch: {e}")
            raise

    def _create_index_template(self):
        """
        Create index template for IOCs
        Ensures new indices have correct field mappings
        """
        try:
            template = {
                "index_patterns": ["ioc-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0
                    },
                    "mappings": {
                        "properties": {
                            "ioc_id": {"type": "keyword"},
                            "indicator": {
                                "type": "text",
                                "fields": {
                                    "keyword": {"type": "keyword", "ignore_above": 256}
                                }
                            },
                            "ioc_type": {"type": "keyword"},  # ← KEY FIX
                            "role": {"type": "keyword"},  # ← KEY FIX
                            "confidence": {"type": "integer"},
                            "reputation_score": {"type": "integer"},
                            "source": {"type": "keyword"},
                            "source_feed_name": {"type": "keyword"},
                            "source_reference_url": {"type": "text"},
                            "first_seen": {"type": "date"},
                            "last_seen": {"type": "date"},
                            "last_updated": {"type": "date"},
                            "tlp": {"type": "keyword"},
                            "is_active": {"type": "boolean"},
                            "title": {"type": "text"},
                            "description": {"type": "text"},
                            "tags": {"type": "keyword"},
                            "malware_families": {"type": "keyword"},
                            "threat_actors": {"type": "keyword"},
                            "campaigns": {"type": "keyword"},
                            "metadata": {"type": "object"}
                        }
                    }
                }
            }

            # Create template
            self.es.indices.put_index_template(
                name="ioc-template",
                body=template
            )
            logger.info("✓ Created Elasticsearch index template")

        except Exception as e:
            logger.warning(f"Error creating index template: {e}")

    def index_ioc(self, ioc) -> bool:
        """Index a single IOC"""
        try:
            index_name = f"ioc-{datetime.utcnow().strftime('%Y.%m.%d')}"
            ioc_dict = ioc.model_dump()

            result = self.es.index(
                index=index_name,
                id=ioc.ioc_id,
                document=ioc_dict
            )

            logger.debug(f"Indexed: {ioc.indicator}")
            return True

        except Exception as e:
            logger.error(f"Error indexing IOC: {e}")
            return False

    def bulk_index(self, iocs: List) -> int:
        """Bulk index IOCs"""
        if not iocs:
            return 0

        try:
            from elasticsearch.helpers import bulk

            index_name = f"ioc-{datetime.utcnow().strftime('%Y.%m.%d')}"

            documents = []
            for ioc in iocs:
                documents.append({
                    "_index": index_name,
                    "_id": ioc.ioc_id,
                    "_source": ioc.model_dump()
                })

            success, failed = bulk(self.es, documents, raise_on_error=False)

            logger.info(f"Indexed {len(iocs)} IOCs to Elasticsearch")
            return len(iocs)

        except Exception as e:
            logger.error(f"Error in bulk indexing: {e}")
            return 0

    def search(self, query: Dict[str, Any]) -> List[Dict]:
        """Search IOCs"""
        try:
            results = self.es.search(index="ioc-*", body=query, size=1000)
            hits = [hit["_source"] for hit in results["hits"]["hits"]]
            return hits
        except Exception as e:
            logger.error(f"Error searching: {e}")
            return []

    def search_by_indicator(self, indicator: str) -> List[Dict]:
        """Search IOCs by indicator value"""
        query = {
            "query": {
                "match": {"indicator": indicator}
            }
        }
        return self.search(query)

    def search_by_type(self, ioc_type: str) -> List[Dict]:
        """Search IOCs by type"""
        query = {
            "query": {
                "term": {"ioc_type": ioc_type}
            }
        }
        return self.search(query)

    def search_by_confidence(self, min_confidence: int = 80) -> List[Dict]:
        """Search high confidence IOCs"""
        query = {
            "query": {
                "range": {"confidence": {"gte": min_confidence}}
            }
        }
        return self.search(query)

    def get_statistics(self) -> Dict[str, Any]:
        """Get IOC statistics (FIXED aggregations)"""
        try:
            # Count total
            count_query = {"query": {"match_all": {}}}
            count_result = self.es.search(
                index="ioc-*",
                body=count_query,
                size=0
            )
            total = count_result["hits"]["total"]["value"]

            # Aggregations - now using keyword fields
            agg_query = {
                "query": {"match_all": {}},
                "aggs": {
                    "by_type": {
                        "terms": {"field": "ioc_type", "size": 50}  # ← Now works!
                    },
                    "by_role": {
                        "terms": {"field": "role", "size": 50}  # ← Now works!
                    },
                    "by_source": {
                        "terms": {"field": "source", "size": 50}
                    }
                }
            }

            result = self.es.search(index="ioc-*", body=agg_query, size=0)
            aggs = result["aggregations"]

            stats = {
                "total_iocs": total,
                "by_type": {},
                "by_role": {},
                "by_source": {}
            }

            for bucket in aggs["by_type"]["buckets"]:
                stats["by_type"][bucket["key"]] = bucket["doc_count"]

            for bucket in aggs["by_role"]["buckets"]:
                stats["by_role"][bucket["key"]] = bucket["doc_count"]

            for bucket in aggs["by_source"]["buckets"]:
                stats["by_source"][bucket["key"]] = bucket["doc_count"]

            return stats

        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
