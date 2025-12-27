"""
Main script to run OTX collector with scheduling
"""

import sys
import os
import asyncio
import logging
import time
from datetime import datetime
from dotenv import load_dotenv

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.collectors.otx_collector import OTXCollector
from src.databases.mongo_client import MongoDBClient
from src.processors.normalizer import Normalizer
from src.processors.deduplicator import Deduplicator
from src.export.elasticsearch_exporter import ElasticsearchExporter  # ← ADD THIS
from src.schedulers.job_scheduler import JobScheduler
from src.utils.logger import setup_logger

# Load environment variables
load_dotenv()

# Setup logging
logger = setup_logger(__name__, "logs/collector.log")


class CollectionPipeline:
    """
    Main collection pipeline

    Steps:
    1. Collect from OTX
    2. Normalize
    3. Deduplicate
    4. Store in MongoDB
    5. Export to Elasticsearch
    """

    def __init__(self):
        """Initialize pipeline"""
        logger.info("Initializing collection pipeline...")

        # Get config from environment
        self.otx_api_key = os.getenv("OTX_API_KEY")
        self.mongodb_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
        self.mongodb_db = os.getenv("MONGODB_DB", "threat_intelligence")
        self.es_host = os.getenv("ELASTICSEARCH_HOST", "localhost")
        self.es_port = int(os.getenv("ELASTICSEARCH_PORT", "9200"))
        self.collection_interval = int(os.getenv("OTX_COLLECTION_INTERVAL_MINUTES", "30"))

        if not self.otx_api_key:
            raise ValueError("OTX_API_KEY environment variable not set!")

        # Initialize components
        self.collector = OTXCollector(api_key=self.otx_api_key)
        self.db = MongoDBClient(self.mongodb_uri, self.mongodb_db)
        self.normalizer = Normalizer()
        self.deduplicator = Deduplicator()

        # Initialize Elasticsearch exporter
        try:
            self.es_exporter = ElasticsearchExporter(host=self.es_host, port=self.es_port)
            logger.info(f"✓ Elasticsearch connection: {self.es_host}:{self.es_port}")
        except Exception as e:
            logger.warning(f"Could not connect to Elasticsearch: {e}")
            self.es_exporter = None

        logger.info(f"Collection interval: {self.collection_interval} minutes")
        logger.info("✓ Pipeline initialized")

    def run_collection(self):
        """
        Run one complete collection cycle

        Steps:
        1. Collect from OTX
        2. Normalize
        3. Deduplicate
        4. Store in MongoDB
        5. Export to Elasticsearch
        """
        try:
            start_time = datetime.utcnow()
            logger.info("=" * 70)
            logger.info(f"Starting collection cycle at {start_time}")
            logger.info("=" * 70)

            # Step 1: Collect
            logger.info("\n[Step 1/5] Collecting from OTX...")
            raw_iocs = asyncio.run(self.collector.collect())
            if not raw_iocs:
                logger.warning("No IOCs collected")
                return

            logger.info(f"  ✓ Collected {len(raw_iocs)} raw IOCs")

            # Step 2: Normalize
            logger.info("\n[Step 2/5] Normalizing IOCs...")
            normalized_iocs = self.normalizer.normalize_list(raw_iocs)
            logger.info(f"  ✓ Normalized {len(normalized_iocs)} IOCs")

            # Step 3: Deduplicate
            logger.info("\n[Step 3/5] Deduplicating IOCs...")
            unique_iocs = self.deduplicator.deduplicate(normalized_iocs)
            logger.info(f"  ✓ Unique IOCs: {len(unique_iocs)}")

            # Step 4: Store in MongoDB
            logger.info("\n[Step 4/5] Storing IOCs in MongoDB...")
            stored_count = self.db.insert_many_iocs(unique_iocs)
            logger.info(f"  ✓ Stored {stored_count} IOCs in MongoDB")

            # Step 5: Export to Elasticsearch
            if self.es_exporter:
                logger.info("\n[Step 5/5] Exporting to Elasticsearch...")
                es_count = self.es_exporter.bulk_index(unique_iocs)
                logger.info(f"  ✓ Exported {es_count} IOCs to Elasticsearch")
            else:
                logger.info("\n[Step 5/5] Elasticsearch not available (skipping)")

            # Print statistics
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            logger.info("\n" + "=" * 70)
            logger.info("Collection Cycle Complete")
            logger.info("=" * 70)
            logger.info(f"Duration: {duration:.2f} seconds")
            logger.info(f"IOCs collected: {len(raw_iocs)}")
            logger.info(f"IOCs stored: {stored_count}")

            # Print database stats
            logger.info("\nDatabase Statistics:")
            type_counts = self.db.count_by_type()
            if type_counts:
                for ioc_type, count in type_counts.items():
                    logger.info(f"  {ioc_type}: {count}")

            logger.info(f"  Total IOCs in DB: {self.db.total_count()}")

            # Print Elasticsearch stats
            if self.es_exporter:
                logger.info("\nElasticsearch Statistics:")
                es_stats = self.es_exporter.get_statistics()
                logger.info(f"  Total IOCs in ES: {es_stats.get('total_iocs', 0)}")
                if es_stats.get('by_type'):
                    for ioc_type, count in es_stats['by_type'].items():
                        logger.info(f"    {ioc_type}: {count}")

            logger.info("=" * 70 + "\n")

        except Exception as e:
            logger.error(f"Error in collection cycle: {e}", exc_info=True)

    def schedule_collection(self):
        """Schedule collection to run at intervals"""
        logger.info("\nSetting up scheduler...")

        scheduler = JobScheduler()

        # Add collection job
        scheduler.add_job(
            func=self.run_collection,
            job_id="otx_collection",
            interval_minutes=self.collection_interval,
            start_now=True
        )

        # Start scheduler
        scheduler.start()

        # Keep running
        try:
            logger.info("Scheduler is running. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("\nShutting down...")
            scheduler.stop()
            self.db.close()
            logger.info("✓ Shutdown complete")


def main():
    """Main entry point"""
    logger.info("\n" + "=" * 70)
    logger.info("IOC Harvester - OTX Collector with Scheduler")
    logger.info("=" * 70)

    try:
        pipeline = CollectionPipeline()
        pipeline.schedule_collection()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
