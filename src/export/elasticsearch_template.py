"""
Create Elasticsearch index template for IOCs
Defines correct field mappings to avoid fielddata errors
"""

import logging
from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)


class ElasticsearchTemplate:
    """Manage Elasticsearch index templates"""

    def __init__(self, es_client: Elasticsearch):
        """
        Initialize with Elasticsearch client

        Args:
            es_client: Elasticsearch client instance
        """
        self.es = es_client

    def create_ioc_template(self):
        """
        Create index template for IOCs

        This ensures new indices use correct field types:
        - Text fields for searching
        - Keyword fields for aggregations
        """

        template = {
            "index_patterns": ["ioc-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "index": {
                        "codec": "best_compression"
                    }
                },
                "mappings": {
                    "properties": {
                        # Identification
                        "ioc_id": {
                            "type": "keyword"
                        },

                        # The actual IOC value
                        "indicator": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        },

                        # IOC type - MUST be keyword for aggregations
                        "ioc_type": {
                            "type": "keyword"
                        },

                        # Role/classification - MUST be keyword
                        "role": {
                            "type": "keyword"
                        },

                        # Confidence and reputation - numeric
                        "confidence": {
                            "type": "integer"
                        },
                        "reputation_score": {
                            "type": "integer"
                        },

                        # Source information - keyword for aggregations
                        "source": {
                            "type": "keyword"
                        },
                        "source_feed_name": {
                            "type": "keyword"
                        },
                        "source_reference_url": {
                            "type": "text"
                        },

                        # Timestamps
                        "first_seen": {
                            "type": "date"
                        },
                        "last_seen": {
                            "type": "date"
                        },
                        "last_updated": {
                            "type": "date"
                        },

                        # Traffic Light Protocol
                        "tlp": {
                            "type": "keyword"
                        },

                        # Status
                        "is_active": {
                            "type": "boolean"
                        },

                        # Text fields
                        "title": {
                            "type": "text"
                        },
                        "description": {
                            "type": "text"
                        },

                        # Tags - keyword for aggregations
                        "tags": {
                            "type": "keyword"
                        },

                        # Threat context - keyword for aggregations
                        "malware_families": {
                            "type": "keyword"
                        },
                        "threat_actors": {
                            "type": "keyword"
                        },
                        "campaigns": {
                            "type": "keyword"
                        },

                        # Metadata
                        "metadata": {
                            "type": "object",
                            "enabled": True
                        },

                        # GeoIP (if present)
                        "geoip": {
                            "properties": {
                                "location": {
                                    "type": "geo_point"
                                }
                            }
                        }
                    }
                }
            }
        }

        try:
            # Create or update template
            self.es.indices.put_index_template(
                name="ioc-template",
                body=template
            )
            logger.info("✓ Created Elasticsearch index template for IOCs")
            return True
        except Exception as e:
            logger.error(f"Error creating index template: {e}")
            return False

    def delete_old_indices(self):
        """
        Delete old indices so they're recreated with new template

        WARNING: This deletes all data!
        """
        try:
            # Get all ioc-* indices
            indices = self.es.indices.get(index="ioc-*")

            # Delete them
            for index_name in indices.keys():
                self.es.indices.delete(index=index_name)
                logger.info(f"Deleted old index: {index_name}")

            logger.info("✓ Deleted old IOC indices")
            return True
        except Exception as e:
            logger.warning(f"No old indices to delete or error: {e}")
            return False
