import os
import yaml
from typing import Dict, Any


class ConfigConnector:
    """Configuration loader for RSS PoC Connector."""

    def __init__(self):
        """Initialize configuration."""
        self.config_file_path = os.getenv("CONNECTOR_CONFIG_FILE", "./config.yml")
        self.load = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file and environment variables."""
        config = self._load_config_file()
        config = self._load_env_variables(config)
        return config

    def _load_config_file(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            if os.path.exists(self.config_file_path):
                with open(self.config_file_path, "r", encoding="utf-8") as file:
                    return yaml.safe_load(file)
            else:
                return {}
        except Exception as e:
            print(f"Error loading config file: {e}")
            return {}

    def _load_env_variables(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        # OpenCTI configuration
        config.setdefault("opencti", {})
        config["opencti"]["url"] = os.getenv("OPENCTI_URL", config["opencti"].get("url", "http://localhost:8080"))
        config["opencti"]["token"] = os.getenv("OPENCTI_TOKEN", config["opencti"].get("token", ""))

        # Connector configuration
        config.setdefault("connector", {})
        config["connector"]["id"] = os.getenv("CONNECTOR_ID", config["connector"].get("id", "rss-poc-connector"))
        config["connector"]["type"] = os.getenv("CONNECTOR_TYPE", config["connector"].get("type", "EXTERNAL_IMPORT"))
        config["connector"]["name"] = os.getenv("CONNECTOR_NAME", config["connector"].get("name", "RSS PoC Loader Connector"))
        config["connector"]["scope"] = os.getenv("CONNECTOR_SCOPE", config["connector"].get("scope", "rss-poc-loader"))
        config["connector"]["log_level"] = os.getenv("CONNECTOR_LOG_LEVEL", config["connector"].get("log_level", "info"))
        config["connector"]["duration_period"] = os.getenv("CONNECTOR_DURATION_PERIOD", config["connector"].get("duration_period", "PT10M"))
        
        # Optional connector parameters
        if os.getenv("CONNECTOR_QUEUE_THRESHOLD"):
            config["connector"]["queue_threshold"] = float(os.getenv("CONNECTOR_QUEUE_THRESHOLD"))
        if os.getenv("CONNECTOR_RUN_AND_TERMINATE"):
            config["connector"]["run_and_terminate"] = os.getenv("CONNECTOR_RUN_AND_TERMINATE")
        if os.getenv("CONNECTOR_SEND_TO_QUEUE"):
            config["connector"]["send_to_queue"] = os.getenv("CONNECTOR_SEND_TO_QUEUE")
        if os.getenv("CONNECTOR_SEND_TO_DIRECTORY"):
            config["connector"]["send_to_directory"] = os.getenv("CONNECTOR_SEND_TO_DIRECTORY")
        if os.getenv("CONNECTOR_SEND_TO_DIRECTORY_PATH"):
            config["connector"]["send_to_directory_path"] = os.getenv("CONNECTOR_SEND_TO_DIRECTORY_PATH")
        if os.getenv("CONNECTOR_SEND_TO_DIRECTORY_RETENTION"):
            config["connector"]["send_to_directory_retention"] = int(os.getenv("CONNECTOR_SEND_TO_DIRECTORY_RETENTION"))
        
        # Logging configuration
        if os.getenv("CONNECTOR_LOG_FILE"):
            config["connector"]["log_file"] = os.getenv("CONNECTOR_LOG_FILE")
        if os.getenv("CONNECTOR_LOG_ROTATION_INTERVAL"):
            config["connector"]["log_rotation_interval"] = int(os.getenv("CONNECTOR_LOG_ROTATION_INTERVAL"))

        # RSS connector specific configuration
        config.setdefault("rss_connector", {})
        config["rss_connector"]["rss_url"] = os.getenv("RSS_URL", config["rss_connector"].get("rss_url", "https://poc-in-github.motikan2010.net/rss/"))
        config["rss_connector"]["check_interval"] = int(os.getenv("RSS_CHECK_INTERVAL", config["rss_connector"].get("check_interval", 600)))
        config["rss_connector"]["max_retries"] = int(os.getenv("RSS_MAX_RETRIES", config["rss_connector"].get("max_retries", 3)))
        config["rss_connector"]["retry_delay"] = int(os.getenv("RSS_RETRY_DELAY", config["rss_connector"].get("retry_delay", 60)))
        config["rss_connector"]["bootstrap_count"] = int(os.getenv("RSS_BOOTSTRAP_COUNT", config["rss_connector"].get("bootstrap_count", 10)))
        config["rss_connector"]["max_file_size"] = int(os.getenv("RSS_MAX_FILE_SIZE", config["rss_connector"].get("max_file_size", 52428800)))
        config["rss_connector"]["min_file_size"] = int(os.getenv("RSS_MIN_FILE_SIZE", config["rss_connector"].get("min_file_size", 10)))
        config["rss_connector"]["tlp_level"] = os.getenv("RSS_TLP_LEVEL", config["rss_connector"].get("tlp_level", "amber+strict"))

        return config
