import requests
import feedparser
from typing import Optional, Any
from pycti import OpenCTIConnectorHelper

from .config_loader import ConfigConnector


class RSSClient:
    """RSS client for fetching and parsing RSS feeds."""

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigConnector):
        """Initialize RSS client."""
        self.helper = helper
        self.config = config
        self.session = requests.Session()
        
        # Set up session headers
        self.session.headers.update({
            'User-Agent': 'OpenCTI-RSS-Connector/1.0'
        })

    def get_rss_feed(self) -> Optional[Any]:
        """Fetch and parse RSS feed."""
        try:
            rss_url = self.config.load["rss_connector"]["rss_url"]
            
            self.helper.connector_logger.info(f"Fetching RSS feed from: {rss_url}")
            
            # Fetch RSS feed
            response = self.session.get(rss_url, timeout=30)
            response.raise_for_status()
            
            # Parse RSS content
            feed = feedparser.parse(response.content)
            
            if feed.bozo:
                self.helper.connector_logger.warning(f"RSS feed parsing warnings: {feed.bozo_exception}")
            
            if not feed.entries:
                self.helper.connector_logger.warning("No entries found in RSS feed")
                return None
            
            self.helper.connector_logger.info(f"Successfully parsed RSS feed with {len(feed.entries)} entries")
            return feed
            
        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(f"Error fetching RSS feed: {e}")
            return None
        except Exception as e:
            self.helper.connector_logger.error(f"Unexpected error parsing RSS feed: {e}")
            return None

    def get_feed_info(self, feed) -> dict:
        """Extract basic information about the RSS feed."""
        if not feed:
            return {}
        
        return {
            "title": getattr(feed.feed, 'title', 'Unknown'),
            "description": getattr(feed.feed, 'description', ''),
            "link": getattr(feed.feed, 'link', ''),
            "language": getattr(feed.feed, 'language', ''),
            "updated": getattr(feed.feed, 'updated', ''),
            "entries_count": len(feed.entries) if hasattr(feed, 'entries') else 0
        }
