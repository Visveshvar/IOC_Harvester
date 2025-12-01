"""
Example usage of IOC models and MongoDB storage
"""

import sys
import os
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.models.ioc_model import (
    IOC, IOCType, IOCRole, IPAddressIOC, DomainIOC, FileHashIOC
)
from src.databases.mongo_client import MongoDBClient
from src.utils.logger import setup_logger

# Setup logging
logger = setup_logger(__name__, "logs/app.log")


def main():
    """Main example function"""

    logger.info("=" * 50)
    logger.info("IOC Harvester - Example Usage")
    logger.info("=" * 50)

    # ===== STEP 1: Connect to MongoDB =====
    logger.info("\n[Step 1] Connecting to MongoDB...")
    try:
        db = MongoDBClient(
            connection_string="mongodb://localhost:27017/",
            db_name="threat_intelligence"
        )
        logger.info("✓ Connected to MongoDB")
    except Exception as e:
        logger.error(f"✗ Failed to connect: {e}")
        return

    # ===== STEP 2: Create IOC objects =====
    logger.info("\n[Step 2] Creating IOC objects...")

    # Create a simple IOC
    ioc1 = IOC(
        indicator="8.8.8.8",
        ioc_type=IOCType.IPV4,
        role=IOCRole.COMMAND_AND_CONTROL,
        confidence=95,
        source="OTX",
        description="Known C&C server",
        tags=["malware", "c2"],
        malware_families=["emotet"],
        threat_actors=["TA542"]
    )
    logger.info(f"  ✓ Created IOC 1: {ioc1.indicator}")

    # Create an IP IOC with geolocation
    ioc2 = IPAddressIOC(
        indicator="192.168.1.1",
        ioc_type=IOCType.IPV4,
        role=IOCRole.BOTNET,
        confidence=88,
        source="AbuseIPDB",
        description="Botnet C&C",
        tags=["botnet"],
        is_botnet=True,
        is_c2_server=True
    )
    logger.info(f"  ✓ Created IOC 2: {ioc2.indicator}")

    # Create a domain IOC
    ioc3 = DomainIOC(
        indicator="evil.com",
        ioc_type=IOCType.DOMAIN,
        role=IOCRole.PHISHING,
        confidence=92,
        source="URLhaus",
        description="Phishing domain",
        tags=["phishing"],
        is_phishing=True,
        resolved_ips=["8.8.8.8"]
    )
    logger.info(f"  ✓ Created IOC 3: {ioc3.indicator}")

    # Create a file hash IOC
    ioc4 = FileHashIOC(
        indicator="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ioc_type=IOCType.FILE_HASH_SHA256,
        role=IOCRole.MALWARE,
        confidence=98,
        source="VirusTotal",
        description="Malware sample",
        tags=["malware", "trojan"],
        malware_families=["emotet"],
        av_detection_count=45,
        av_detection_ratio="45/68"
    )
    logger.info(f"  ✓ Created IOC 4: {ioc4.indicator[:16]}...")

    # ===== STEP 3: Store IOCs in database =====
    logger.info("\n[Step 3] Storing IOCs in database...")

    iocs = [ioc1, ioc2, ioc3, ioc4]

    for ioc in iocs:
        success = db.insert_ioc(ioc)
        if success:
            logger.info(f"  ✓ Stored: {ioc.indicator}")
        else:
            logger.error(f"  ✗ Failed to store: {ioc.indicator}")

    # ===== STEP 4: Retrieve IOCs from database =====
    logger.info("\n[Step 4] Retrieving IOCs from database...")

    # Get specific IOC
    retrieved_ioc = db.get_ioc("8.8.8.8", "ipv4")
    if retrieved_ioc:
        logger.info(f"  ✓ Retrieved IOC: {retrieved_ioc.indicator}")
        logger.info(f"    - Type: {retrieved_ioc.ioc_type}")
        logger.info(f"    - Role: {retrieved_ioc.role}")
        logger.info(f"    - Confidence: {retrieved_ioc.confidence}%")
        logger.info(f"    - Source: {retrieved_ioc.source}")

    # ===== STEP 5: Query IOCs =====
    logger.info("\n[Step 5] Querying IOCs...")

    # Get all OTX IOCs
    otx_iocs = db.get_all_by_source("OTX")
    logger.info(f"  ✓ OTX IOCs: {len(otx_iocs)}")

    # Get high confidence IOCs
    high_conf = db.get_high_confidence_iocs(min_confidence=90)
    logger.info(f"  ✓ High confidence IOCs (>90%): {len(high_conf)}")

    # Get recent IOCs
    recent = db.get_recent_iocs(days=1)
    logger.info(f"  ✓ Recent IOCs (last 24h): {len(recent)}")

    # ===== STEP 6: Statistics =====
    logger.info("\n[Step 6] Statistics...")

    type_counts = db.count_by_type()
    logger.info(f"  By Type: {type_counts}")

    source_counts = db.count_by_source()
    logger.info(f"  By Source: {source_counts}")

    total = db.total_count()
    logger.info(f"  Total IOCs: {total}")

    # ===== Done =====
    logger.info("\n" + "=" * 50)
    logger.info("Example completed successfully!")
    logger.info("=" * 50)

    # Close connection
    db.close()


if __name__ == "__main__":
    main()
