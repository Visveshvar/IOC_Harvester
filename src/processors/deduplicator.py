"""
Deduplicator - Remove duplicate IOCs
"""

import logging
from typing import List
from src.models.ioc_model import IOC

logger = logging.getLogger(__name__)


class Deduplicator:
    """Remove duplicate IOCs"""

    def deduplicate(self, iocs: List[IOC]) -> List[IOC]:
        """
        Remove duplicate IOCs (same indicator + type)

        Args:
            iocs: List of IOC objects

        Returns:
            Deduplicated list
        """
        seen = set()
        unique = []

        for ioc in iocs:
            key = (ioc.indicator, ioc.ioc_type)
            if key not in seen:
                seen.add(key)
                unique.append(ioc)

        removed = len(iocs) - len(unique)
        if removed > 0:
            logger.info(f"Removed {removed} duplicate IOCs")

        return unique
