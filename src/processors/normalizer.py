"""
IOC Normalizer - Convert raw data to standard IOC format
"""

import logging
from typing import List, Dict, Any
from datetime import datetime
from src.models.ioc_model import IOC, IOCType, IOCRole

logger = logging.getLogger(__name__)


class Normalizer:
    """Normalize raw IOC data"""

    def normalize_list(self, raw_iocs: List[Dict]) -> List[IOC]:
        """
        Normalize list of raw IOCs to IOC objects

        Args:
            raw_iocs: List of raw IOC dictionaries

        Returns:
            List of IOC objects
        """
        normalized = []
        for raw_ioc in raw_iocs:
            try:
                ioc = IOC(**raw_ioc)
                normalized.append(ioc)
            except Exception as e:
                logger.warning(f"Error normalizing IOC: {e}")
                continue

        logger.info(f"Normalized {len(normalized)}/{len(raw_iocs)} IOCs")
        return normalized
