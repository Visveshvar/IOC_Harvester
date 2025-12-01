"""
Base collector class - abstract parent for all collectors
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """
    Abstract base class for all IOC collectors.

    Every collector must:
    1. Fetch raw data from source
    2. Normalize to IOC format
    3. Handle errors gracefully
    """

    def __init__(self, name: str, api_key: Optional[str] = None):
        """
        Initialize collector

        Args:
            name: Name of collector (e.g., "OTX")
            api_key: API key for the source (if needed)
        """
        self.name = name
        self.api_key = api_key
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.last_collection_time: Optional[datetime] = None
        self.indicators_collected = 0

    @abstractmethod
    async def fetch(self) -> List[Dict[str, Any]]:
        """
        Fetch raw data from source

        Must be implemented by subclasses.

        Returns:
            List of raw IOC dictionaries
        """
        pass

    @abstractmethod
    def normalize(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize raw data to standard IOC format

        Must be implemented by subclasses.

        Args:
            raw_data: Raw data from source

        Returns:
            List of normalized IOC dictionaries
        """
        pass

    async def collect(self) -> List[Dict[str, Any]]:
        """
        Main collection method

        Handles:
        1. Fetching
        2. Normalizing
        3. Error handling
        4. Logging

        Returns:
            List of normalized IOCs
        """
        try:
            self.logger.info(f"Starting collection from {self.name}")

            # Step 1: Fetch raw data
            self.logger.info(f"  Fetching from {self.name}...")
            raw_data = await self.fetch()
            self.logger.info(f"  Fetched {len(raw_data)} raw items")

            # Step 2: Normalize
            self.logger.info(f"  Normalizing...")
            normalized = self.normalize(raw_data)
            self.logger.info(f"  Normalized {len(normalized)} IOCs")

            # Update tracking
            self.indicators_collected = len(normalized)
            self.last_collection_time = datetime.utcnow()

            self.logger.info(f"✓ Successfully collected {len(normalized)} IOCs from {self.name}")
            return normalized

        except Exception as e:
            self.logger.error(f"✗ Error collecting from {self.name}: {e}", exc_info=True)
            return []

    def get_status(self) -> Dict[str, Any]:
        """
        Get collector status

        Returns:
            Status information
        """
        return {
            "name": self.name,
            "last_collection": self.last_collection_time,
            "indicators_collected": self.indicators_collected,
            "enabled": True
        }
