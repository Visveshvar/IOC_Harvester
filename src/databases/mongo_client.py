"""
MongoDB client for IOC storage and retrieval
"""

import logging
from typing import List, Dict, Optional, Any
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from datetime import datetime, timedelta
from src.models.ioc_model import IOC, IOCType

logger = logging.getLogger(__name__)


class MongoDBClient:
    """MongoDB client for IOC operations"""

    def __init__(self, connection_string: str, db_name: str):
        """
        Initialize MongoDB connection

        Args:
            connection_string: MongoDB URI (e.g., "mongodb://localhost:27017/")
            db_name: Database name (e.g., "threat_intelligence")
        """
        try:
            self.client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
            # Test connection
            self.client.admin.command('ping')
            self.db = self.client[db_name]
            self.collection = self.db["iocs"]
            logger.info(f"Connected to MongoDB database: {db_name}")
            self._create_indexes()
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise

    def _create_indexes(self):
        """Create database indexes for fast queries"""
        logger.info("Creating MongoDB indexes...")
        try:
            # Unique index on indicator + type
            self.collection.create_index(
                [("indicator", ASCENDING), ("ioc_type", ASCENDING)],
                unique=True
            )
            logger.info("  ✓ Created index: indicator + ioc_type")

            # Index by type
            self.collection.create_index([("ioc_type", ASCENDING)])
            logger.info("  ✓ Created index: ioc_type")

            # Index by source
            self.collection.create_index([("source", ASCENDING)])
            logger.info("  ✓ Created index: source")

            # Index by date (descending for recent first)
            self.collection.create_index([("first_seen", DESCENDING)])
            logger.info("  ✓ Created index: first_seen")

            # Index by confidence
            self.collection.create_index([("confidence", DESCENDING)])
            logger.info("  ✓ Created index: confidence")

            # Index by tags (for searching)
            self.collection.create_index([("tags", ASCENDING)])
            logger.info("  ✓ Created index: tags")

        except Exception as e:
            logger.error(f"Error creating indexes: {e}")

    def insert_ioc(self, ioc: IOC) -> bool:
        """
        Insert or update a single IOC

        Args:
            ioc: IOC object to store

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            ioc_dict = ioc.model_dump()

            result = self.collection.update_one(
                {
                    "indicator": ioc.indicator,
                    "ioc_type": ioc.ioc_type
                },
                {"$set": ioc_dict},
                upsert=True
            )

            if result.upserted_id:
                logger.debug(f"Inserted new IOC: {ioc.indicator}")
            else:
                logger.debug(f"Updated IOC: {ioc.indicator}")

            return True

        except Exception as e:
            logger.error(f"Error inserting IOC {ioc.indicator}: {e}")
            return False

    def insert_many_iocs(self, iocs: List[IOC]) -> int:
        """
        Insert multiple IOCs efficiently

        Args:
            iocs: List of IOC objects

        Returns:
            int: Number of IOCs inserted/updated
        """
        if not iocs:
            return 0

        try:
            from pymongo import UpdateOne

            operations = []
            for ioc in iocs:
                ioc_dict = ioc.model_dump()
                operations.append(
                    UpdateOne(
                        {
                            "indicator": ioc.indicator,
                            "ioc_type": ioc.ioc_type
                        },
                        {"$set": ioc_dict},
                        upsert=True
                    )
                )

            result = self.collection.bulk_write(operations, ordered=False)
            count = result.upserted_id + result.modified_count if result.upserted_id else result.modified_count
            logger.info(f"Bulk inserted/updated {count} IOCs")
            return count

        except Exception as e:
            logger.error(f"Error in bulk insert: {e}")
            return 0

    def get_ioc(self, indicator: str, ioc_type: str) -> Optional[IOC]:
        """
        Retrieve a single IOC

        Args:
            indicator: IOC value
            ioc_type: IOC type

        Returns:
            IOC object if found, None otherwise
        """
        try:
            data = self.collection.find_one({
                "indicator": indicator,
                "ioc_type": ioc_type
            })

            if data:
                data.pop("_id", None)  # Remove MongoDB's _id
                return IOC(**data)

            return None

        except Exception as e:
            logger.error(f"Error retrieving IOC {indicator}: {e}")
            return None

    def get_all_by_source(self, source: str, limit: int = 1000) -> List[IOC]:
        """
        Get all IOCs from a specific source

        Args:
            source: Source name (e.g., "OTX")
            limit: Max number of results

        Returns:
            List of IOC objects
        """
        try:
            results = self.collection.find({"source": source}, limit=limit)

            iocs = []
            for data in results:
                data.pop("_id", None)
                iocs.append(IOC(**data))

            logger.info(f"Retrieved {len(iocs)} IOCs from source: {source}")
            return iocs

        except Exception as e:
            logger.error(f"Error retrieving IOCs from {source}: {e}")
            return []

    def get_high_confidence_iocs(self, min_confidence: int = 80) -> List[IOC]:
        """
        Get IOCs with high confidence

        Args:
            min_confidence: Minimum confidence score (0-100)

        Returns:
            List of IOC objects sorted by confidence
        """
        try:
            results = self.collection.find(
                {"confidence": {"$gte": min_confidence}},
                sort=[("confidence", DESCENDING)]
            )

            iocs = []
            for data in results:
                data.pop("_id", None)
                iocs.append(IOC(**data))

            logger.info(f"Retrieved {len(iocs)} IOCs with confidence >= {min_confidence}")
            return iocs

        except Exception as e:
            logger.error(f"Error retrieving high confidence IOCs: {e}")
            return []

    def get_recent_iocs(self, days: int = 7, limit: int = 1000) -> List[IOC]:
        """
        Get recently seen IOCs

        Args:
            days: How many days back
            limit: Max results

        Returns:
            List of IOC objects
        """
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)

            results = self.collection.find(
                {"last_seen": {"$gte": cutoff}},
                sort=[("last_seen", DESCENDING)],
                limit=limit
            )

            iocs = []
            for data in results:
                data.pop("_id", None)
                iocs.append(IOC(**data))

            logger.info(f"Retrieved {len(iocs)} IOCs from last {days} days")
            return iocs

        except Exception as e:
            logger.error(f"Error retrieving recent IOCs: {e}")
            return []

    def count_by_type(self) -> Dict[str, int]:
        """
        Count IOCs by type

        Returns:
            Dict with IOC types as keys and counts as values
        """
        try:
            pipeline = [
                {"$group": {"_id": "$ioc_type", "count": {"$sum": 1}}}
            ]

            results = self.collection.aggregate(pipeline)
            counts = {}
            for result in results:
                counts[result["_id"]] = result["count"]

            logger.info(f"IOCs by type: {counts}")
            return counts

        except Exception as e:
            logger.error(f"Error counting by type: {e}")
            return {}

    def count_by_source(self) -> Dict[str, int]:
        """
        Count IOCs by source

        Returns:
            Dict with sources as keys and counts as values
        """
        try:
            pipeline = [
                {"$group": {"_id": "$source", "count": {"$sum": 1}}}
            ]

            results = self.collection.aggregate(pipeline)
            counts = {}
            for result in results:
                counts[result["_id"]] = result["count"]

            logger.info(f"IOCs by source: {counts}")
            return counts

        except Exception as e:
            logger.error(f"Error counting by source: {e}")
            return {}

    def total_count(self) -> int:
        """
        Get total number of IOCs

        Returns:
            Total count
        """
        try:
            count = self.collection.count_documents({})
            logger.info(f"Total IOCs in database: {count}")
            return count

        except Exception as e:
            logger.error(f"Error getting total count: {e}")
            return 0

    def close(self):
        """Close database connection"""
        try:
            self.client.close()
            logger.info("MongoDB connection closed")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")
