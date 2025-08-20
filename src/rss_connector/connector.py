import sys
import os
import re
import hashlib
import time
import json
import shutil
import uuid
import subprocess
from subprocess import TimeoutExpired
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

import feedparser
import requests
from pycti import OpenCTIConnectorHelper

from .config_loader import ConfigConnector
from .converter_to_stix import GraphQLConverter
from .rss_client import RSSClient
from .log_rotator import LogRotator


class RSSConnector:
    """
    RSS PoC Loader Connector for OpenCTI
    
    This connector fetches Proof-of-Concept files from GitHub repositories
    through RSS feeds and creates STIX objects in OpenCTI.
    """

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """Initialize the RSS Connector."""
        self.config = config
        self.helper = helper
        self.rss_client = RSSClient(self.helper, self.config)
        self.converter_to_stix = GraphQLConverter(self.helper)
        
        # Initialize work directory
        self.work_dir = os.path.join(os.getcwd(), "poc_downloads")
        os.makedirs(self.work_dir, exist_ok=True)
        
        # Cache for processed entries
        self.cache_file = "poc_cache.json"
        self.cache = self._load_cache()
        
        # Initialize log rotator
        log_file = self.config.load.get("connector", {}).get("log_file", "/opt/opencti-rss-connector/connector.log")
        rotation_interval = int(self.config.load.get("connector", {}).get("log_rotation_interval", 86400))
        self.log_rotator = LogRotator(log_file, rotation_interval)
        
        # Initialize metrics
        self._init_metrics()
    
    def _init_metrics(self):
        """Initialize metrics for monitoring."""
        # Set initial metric states
        self.helper.metric.state("idle")
        
        # Initialize counters
        if not hasattr(self.helper.metric, '_counters'):
            self.helper.metric._counters = {}
        
        # RSS specific metrics
        self.helper.metric._counters.update({
            'rss_entries_processed': 0,
            'repositories_cloned': 0,
            'files_processed': 0,
            'stix_objects_created': 0,
            'errors_total': 0,
            'cache_hits': 0,
            'cache_misses': 0
        })

    def _load_cache(self) -> Dict[str, Any]:
        """Load cache from file."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            self.helper.connector_logger.warning(f"Error loading cache: {e}")
            return {}

    def _save_cache(self) -> bool:
        """Save cache to file."""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self.helper.log_error(f"[RSS] Error saving cache: {e}")
            return False
    
    def _cleanup_old_cache_entries(self, max_age_days: int = 30):
        """Очистка старых записей кеша."""
        try:
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            entries_to_remove = []
            
            for entry_id, entry_data in self.cache.items():
                processed_at = entry_data.get("processed_at")
                if processed_at:
                    try:
                        entry_date = datetime.fromisoformat(processed_at.replace('Z', '+00:00'))
                        if entry_date < cutoff_date:
                            entries_to_remove.append(entry_id)
                    except Exception:
                        # Если не удается распарсить дату, оставляем запись
                        continue
            
            # Удаляем старые записи
            for entry_id in entries_to_remove:
                del self.cache[entry_id]
            
            if entries_to_remove:
                self.helper.log_info(f"[RSS] Cleaned up {len(entries_to_remove)} old cache entries")
                self._save_cache()
                
        except Exception as e:
            self.helper.log_warning(f"[RSS] Error cleaning up cache: {e}")
    
    def _increment_metric(self, metric_name: str, value: int = 1):
        """Increment a metric counter."""
        try:
            if hasattr(self.helper.metric, '_counters') and metric_name in self.helper.metric._counters:
                self.helper.metric._counters[metric_name] += value
        except Exception:
            pass  # Ignore metric errors
    
    def _set_metric_state(self, state: str):
        """Set metric state."""
        try:
            self.helper.metric.state(state)
        except Exception:
            pass  # Ignore metric errors
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        try:
            if hasattr(self.helper.metric, '_counters'):
                return {
                    'state': getattr(self.helper.metric, '_state', 'unknown'),
                    'counters': self.helper.metric._counters.copy()
                }
            return {'state': 'unknown', 'counters': {}}
        except Exception:
            return {'state': 'error', 'counters': {}}
    
    def health_check(self) -> Dict[str, Any]:
        """Проверка здоровья коннектора."""
        try:
            current_state = self.helper.get_state()
            metrics = self.get_metrics()
            
            # Проверка RSS клиента
            rss_status = "healthy"
            try:
                feed = self.rss_client.get_rss_feed()
                if not feed:
                    rss_status = "warning"
            except Exception:
                rss_status = "error"
            
            # Проверка кеша
            cache_status = "healthy"
            if len(self.cache) > 1000:  # Если кеш слишком большой
                cache_status = "warning"
            
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "rss_status": rss_status,
                "cache_status": cache_status,
                "cache_size": len(self.cache),
                "last_run": current_state.get("last_run"),
                "bootstrap_completed": current_state.get("bootstrap_completed", False),
                "metrics": metrics
            }
        except Exception as e:
            return {
                "status": "error",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Получить статистику по кешу."""
        try:
            status_counts = {}
            cve_counts = {}
            
            for entry_data in self.cache.values():
                status = entry_data.get("status", "unknown")
                status_counts[status] = status_counts.get(status, 0) + 1
                
                cve_id = entry_data.get("cve_id", "unknown")
                cve_counts[cve_id] = cve_counts.get(cve_id, 0) + 1
            
            return {
                "total_entries": len(self.cache),
                "status_distribution": status_counts,
                "unique_cves": len(cve_counts),
                "cve_distribution": dict(list(cve_counts.items())[:10]),  # Top 10 CVE
                "oldest_entry": min([entry.get("processed_at", "") for entry in self.cache.values()], default=""),
                "newest_entry": max([entry.get("processed_at", "") for entry in self.cache.values()], default="")
            }
        except Exception as e:
            return {
                "error": str(e),
                "total_entries": 0
            }

    def _extract_cve_id(self, entry) -> Optional[str]:
        """Extract CVE ID from RSS entry."""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        
        # Search fields in order of priority
        search_fields = [
            'title', 'description', 'summary', 'content', 'subtitle',
            'link', 'author', 'category', 'tags', 'dc_subject',
            'dc_description', 'dc_title', 'media_description',
            'media_title', 'media_keywords'
        ]
        
        # First check title (highest priority)
        title = getattr(entry, 'title', '')
        if title:
            match = re.search(cve_pattern, title, re.IGNORECASE)
            if match:
                return match.group(0)
        
        # Check other fields
        for field_name in search_fields[1:]:
            field_value = getattr(entry, field_name, '')
            if field_value:
                if isinstance(field_value, str):
                    match = re.search(cve_pattern, field_value, re.IGNORECASE)
                    if match:
                        return match.group(0)
                elif isinstance(field_value, list):
                    for item in field_value:
                        if isinstance(item, str):
                            match = re.search(cve_pattern, item, re.IGNORECASE)
                            if match:
                                return match.group(0)
        
        # Try to extract from URL
        return self._extract_cve_id_from_url(getattr(entry, 'link', ''))

    def _extract_cve_id_from_url(self, url: str) -> Optional[str]:
        """Extract CVE ID from repository URL."""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        
        # Check full URL
        match = re.search(cve_pattern, url, re.IGNORECASE)
        if match:
            return match.group(0)
        
        # Try repository name
        try:
            if "github.com" in url:
                repo_name = url.split("/")[-1]
                if repo_name:
                    match = re.search(cve_pattern, repo_name, re.IGNORECASE)
                    if match:
                        return match.group(0)
        except Exception:
            pass
        
        return None

    def _should_process_entry(self, entry, cve_id: str) -> bool:
        """Check if RSS entry should be processed."""
        entry_id = getattr(entry, 'id', getattr(entry, 'link', ''))
        
        # Check if CVE ID is valid
        if not cve_id:
            return False
        
        # Check if already processed
        if entry_id in self.cache:
            return False
        
        return True

    def _get_bootstrap_status(self) -> dict:
        """Get bootstrap status from state."""
        current_state = self.helper.get_state()
        if not current_state:
            return {"bootstrap_completed": False, "processed_count": 0}
        
        return {
            "bootstrap_completed": current_state.get("bootstrap_completed", False),
            "processed_count": current_state.get("bootstrap_processed_count", 0)
        }

    def _update_bootstrap_status(self, processed_count: int, bootstrap_completed: bool = False):
        """Update bootstrap status in state."""
        current_state = self.helper.get_state() or {}
        current_state.update({
            "bootstrap_processed_count": processed_count,
            "bootstrap_completed": bootstrap_completed
        })
        self.helper.set_state(current_state)

    def _clone_repository(self, repository_url: str, cve_id: str, max_retries: int = 3) -> Optional[str]:
        """Clone GitHub repository to local directory with retry mechanism."""
        try:
            # Extract owner and repo from URL
            parts = repository_url.replace("https://github.com/", "").split("/")
            if len(parts) < 2:
                return None
            
            owner, repo = parts[0], parts[1]
            repo_path = os.path.join(self.work_dir, f"{owner}_{repo}_{cve_id}")
            
            # Remove existing directory if exists
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            
            # Clone repository with retry mechanism
            for attempt in range(max_retries):
                try:
                    self.helper.log_debug(f"[RSS] Clone attempt {attempt + 1}/{max_retries} for {repository_url}")
                    
                    result = subprocess.run(
                        ["git", "clone", "--depth", "1", repository_url, repo_path],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    if result.returncode == 0:
                        self.helper.log_info(f"[RSS] Successfully cloned repository: {repository_url}")
                        return repo_path
                    else:
                        error_msg = f"Failed to clone repository (attempt {attempt + 1}): {result.stderr}"
                        if attempt < max_retries - 1:
                            self.helper.log_warning(f"[RSS] {error_msg}, retrying...")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            self.helper.log_error(f"[RSS] {error_msg}")
                            return None
                            
                except subprocess.TimeoutExpired:
                    error_msg = f"Timeout cloning repository (attempt {attempt + 1}): {repository_url}"
                    if attempt < max_retries - 1:
                        self.helper.log_warning(f"[RSS] {error_msg}, retrying...")
                        time.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        self.helper.log_error(f"[RSS] {error_msg}")
                        return None
                        
                except Exception as e:
                    error_msg = f"Unexpected error cloning repository (attempt {attempt + 1}): {e}"
                    if attempt < max_retries - 1:
                        self.helper.log_warning(f"[RSS] {error_msg}, retrying...")
                        time.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        self.helper.log_error(f"[RSS] {error_msg}")
                        return None
                
        except Exception as e:
            self.helper.log_error(f"[RSS] Error cloning repository: {e}")
            return None

    def _filter_files(self, repo_path: str) -> List[Dict[str, Any]]:
        """Filter files in repository based on configuration."""
        config = self.config.load["rss_connector"]
        excluded_extensions = set(ext.lower() for ext in config.get("excluded_extensions", []))
        excluded_file_names = set(name.lower() for name in config.get("excluded_file_name_patterns", []))
        excluded_dir_names = set(name.lower() for name in config.get("excluded_dir_names", []))
        max_file_size = config.get("max_file_size", 52428800)
        min_file_size = config.get("min_file_size", 10)
        
        suitable_files = []
        
        try:
            for root, dirs, files in os.walk(repo_path):
                # Filter directories
                dirs[:] = [d for d in dirs if d.lower() not in excluded_dir_names]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    
                    # Check file size
                    if file_size < min_file_size or file_size > max_file_size:
                        continue
                    
                    # Check file extension
                    file_ext = os.path.splitext(file)[1].lower()
                    if file_ext in excluded_extensions:
                        continue
                    
                    # Check file name patterns
                    file_name_lower = file.lower()
                    if any(pattern in file_name_lower for pattern in excluded_file_names):
                        continue
                    
                    # Calculate file hash
                    try:
                        with open(file_path, 'rb') as f:
                            file_content = f.read()
                            sha256_hash = hashlib.sha256(file_content).hexdigest()
                    except Exception:
                        continue
                    
                    suitable_files.append({
                        "local_path": file_path,
                        "name": file,
                        "size": file_size,
                        "hashes": {"sha256": sha256_hash},
                        "relative_path": os.path.relpath(file_path, repo_path)
                    })
                    
        except Exception as e:
            self.helper.log_error(f"[RSS] Error filtering files: {e}")
            self._increment_metric('errors_total')
        
        return suitable_files

    def _process_repository(self, entry, cve_id: str, repository_url: str, is_bootstrap: bool = False) -> List[Dict[str, Any]]:
        """Process a single repository with metrics tracking."""
        stix_objects = []
        work_id = None
        
        # Get publication date and description early
        pub_date = datetime.now().isoformat()
        if hasattr(entry, 'published_parsed'):
            try:
                pub_date = datetime(*entry.published_parsed[:6]).isoformat()
            except:
                pass
        
        original_description = getattr(entry, 'description', '')
        if not original_description:
            original_description = getattr(entry, 'title', 'Unknown')
        
        try:
            # Create work for this repository ONLY if it's bootstrap mode or new entry
            if is_bootstrap:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id,
                    f"RSS PoC Loader - Repository: {cve_id} - {repository_url}"
                )
                
                if not work_id:
                    self.helper.log_error(f"[RSS] Failed to initiate work for repository: {repository_url}")
                    self._increment_metric('errors_total')
                    return stix_objects
                
                self.helper.log_info(f"[RSS] Started work {work_id} for repository: {repository_url}")
                
                # Set initial work progress
                try:
                    # In OpenCTI, work progress is updated through the completion message
                    # We'll set it when completing the work
                    self.helper.log_info(f"[RSS] Work progress initialized for repository {cve_id}: 0/1 operations")
                except Exception as e:
                    self.helper.log_warning(f"[RSS] Could not initialize work progress for repository {cve_id}: {e}")
            
            try:
                # Clone repository
                repo_path = self._clone_repository(repository_url, cve_id)
                if not repo_path:
                    self.helper.log_warning(f"[RSS] Failed to clone repository: {repository_url}")
                    self._increment_metric('errors_total')
                    return stix_objects
                
                self._increment_metric('repositories_cloned')
                
                # Filter suitable files
                suitable_files = self._filter_files(repo_path)
                
                if suitable_files:
                    # Create GraphQL objects for files
                    for file_info in suitable_files:
                        # Create artifact description
                        artifact_description = f"Proof-of-Concept for {cve_id}\n\nSource: {repository_url}\nPublished: {pub_date}\nFile: {file_info['name']}\n\nAutomatically imported from GitHub PoC repository"
                        
                        file_objects = self.converter_to_stix.create_artifact_with_tool_and_vulnerability(
                            file_info['local_path'], 
                            artifact_description, 
                            file_info['hashes'], 
                            cve_id,
                            repository_url,
                            pub_date,
                            original_description,
                            repo_path
                        )
                        if file_objects:
                            stix_objects.append(file_objects)
                            self._increment_metric('stix_objects_created')
                    
                    self._increment_metric('files_processed', len(suitable_files))
                    
                    # Mark as processed
                    entry_id = getattr(entry, 'id', getattr(entry, 'link', ''))
                    self.cache[entry_id] = {
                        "status": "processed",
                        "cve_id": cve_id,
                        "repository_url": repository_url,
                        "files_count": len(suitable_files),
                        "stix_objects_count": len(stix_objects),
                        "work_id": work_id,
                        "processed_at": datetime.now().isoformat()
                    }
                    
                    self.helper.log_info(f"[RSS] Repository {cve_id} processed: {len(suitable_files)} files, {len(stix_objects)} STIX objects")
                else:
                    # Create GraphQL objects for empty repository (Tool + Vulnerability)
                    empty_success = self.converter_to_stix.create_tool_and_vulnerability_for_empty_repo(
                        cve_id, repository_url, pub_date, original_description, repo_path
                    )
                    if empty_success:
                        # Add empty repository to cache
                        entry_id = getattr(entry, 'id', getattr(entry, 'link', ''))
                        self.cache[entry_id] = {
                            "status": "no_suitable_files",
                            "cve_id": cve_id,
                            "repository_url": repository_url,
                            "stix_objects_count": 2,  # Tool + Vulnerability
                            "work_id": work_id,
                            "processed_at": datetime.now().isoformat()
                        }
                        
                        self._increment_metric('stix_objects_created', 2)
                        self.helper.log_info(f"[RSS] Repository {cve_id} processed: no suitable files, but created 2 STIX objects (Tool + Vulnerability)")
                    else:
                        self.helper.log_warning(f"[RSS] Failed to create objects for empty repository {cve_id}")
                        self._increment_metric('errors_total')
                        
            except Exception as e:
                self.helper.log_error(f"[RSS] Error during repository processing: {e}")
                self._increment_metric('errors_total')
                
                # Mark as error
                entry_id = getattr(entry, 'id', getattr(entry, 'link', ''))
                self.cache[entry_id] = {
                    "status": "error",
                    "cve_id": cve_id,
                    "repository_url": repository_url,
                    "error": str(e),
                    "work_id": work_id,
                    "processed_at": datetime.now().isoformat()
                }
            
        except Exception as e:
            self.helper.log_error(f"[RSS] Error processing repository {repository_url}: {e}")
            self._increment_metric('errors_total')
            
            # Mark as error
            entry_id = getattr(entry, 'id', getattr(entry, 'link', ''))
            self.cache[entry_id] = {
                "status": "error",
                "cve_id": cve_id,
                "repository_url": repository_url,
                "error": str(e),
                "work_id": work_id,
                "processed_at": datetime.now().isoformat()
            }
        
        finally:
            # Complete work for this repository ONLY if work was created
            if work_id:
                try:
                    # Get operation details from cache
                    entry_id = getattr(entry, 'id', getattr(entry, 'link', ''))
                    cache_entry = self.cache.get(entry_id, {})
                    
                    # Update work progress for this repository
                    try:
                        # In OpenCTI, work progress is updated through the completion message
                        # We'll include progress information in the completion message
                        self.helper.log_info(f"[RSS] Work progress updated for repository {cve_id}: 1/1 operations")
                    except Exception as e:
                        self.helper.log_warning(f"[RSS] Could not update work progress for repository {cve_id}: {e}")
                    
                    if cache_entry.get("status") == "processed":
                        completion_message = f"Repository {cve_id} completed: 1/1 operations - {cache_entry.get('files_count', 0)} files processed, {cache_entry.get('stix_objects_count', 0)} STIX objects created"
                    elif cache_entry.get("status") == "no_suitable_files":
                        completion_message = f"Repository {cve_id} completed: 1/1 operations - no suitable files, {cache_entry.get('stix_objects_count', 0)} STIX objects created (Tool + Vulnerability)"
                    elif cache_entry.get("status") == "error":
                        completion_message = f"Repository {cve_id} failed: 0/1 operations - {cache_entry.get('error', 'Unknown error')}"
                    else:
                        completion_message = f"Repository {cve_id} completed: 1/1 operations - status {cache_entry.get('status', 'unknown')}"
                    
                    self.helper.api.work.to_processed(work_id, completion_message)
                    self.helper.log_info(f"[RSS] Work {work_id} completed for repository: {repository_url}")
                except Exception as e:
                    self.helper.log_warning(f"[RSS] Could not complete work for repository {repository_url}: {e}")
        
        return stix_objects

    def _collect_intelligence(self) -> List[Dict[str, Any]]:
        """Collect intelligence from RSS feed and convert to STIX objects."""
        stix_objects = []
        
        try:
            # Parse RSS feed
            feed = self.rss_client.get_rss_feed()
            if not feed:
                return stix_objects
            
            # Get bootstrap status
            bootstrap_status = self._get_bootstrap_status()
            bootstrap_completed = bootstrap_status["bootstrap_completed"]
            bootstrap_processed = bootstrap_status["processed_count"]
            bootstrap_count = self.config.load["rss_connector"]["bootstrap_count"]
            
            self.helper.log_info(f"[RSS] Bootstrap status: completed={bootstrap_completed}, processed={bootstrap_processed}/{bootstrap_count}")
            
            # Process entries
            processed_count = 0
            entries_to_process = []
            
            # Collect entries to process
            for entry in feed.entries:
                try:
                    # Extract CVE ID
                    cve_id = self._extract_cve_id(entry)
                    if not cve_id:
                        continue
                    
                    # Check if should process
                    if not self._should_process_entry(entry, cve_id):
                        continue
                    
                    entries_to_process.append((entry, cve_id))
                    
                except Exception as e:
                    self.helper.log_error(f"[RSS] Error processing entry: {e}")
                    self._increment_metric('errors_total')
                    continue
            
            # Process entries based on bootstrap status
            if not bootstrap_completed:
                # Bootstrap mode: process up to bootstrap_count entries
                entries_to_process = entries_to_process[:bootstrap_count - bootstrap_processed]
                self.helper.log_info(f"[RSS] Bootstrap mode: processing {len(entries_to_process)} entries")
            else:
                # Monitoring mode: process only new entries
                self.helper.log_info(f"[RSS] Monitoring mode: processing {len(entries_to_process)} new entries")
            
            # Process selected entries
            for entry, cve_id in entries_to_process:
                try:
                    # Get repository URL
                    repository_url = getattr(entry, 'link', '')
                    if not repository_url:
                        continue
                    
                    # Log whether this is bootstrap or monitoring mode
                    if not bootstrap_completed:
                        self.helper.log_info(f"[RSS] Processing repository {cve_id} in BOOTSTRAP mode (will create work)")
                    else:
                        self.helper.log_info(f"[RSS] Processing repository {cve_id} in MONITORING mode (no work created)")
                    
                    # Process repository with individual work tracking
                    # is_bootstrap = True for bootstrap mode, False for monitoring mode
                    repository_objects = self._process_repository(entry, cve_id, repository_url, is_bootstrap=not bootstrap_completed)
                    stix_objects.extend(repository_objects)
                    
                    # Always increment counters, regardless of whether objects were created
                    # (empty repositories still create Tool + Vulnerability)
                    processed_count += 1
                    bootstrap_processed += 1
                    
                except Exception as e:
                    self.helper.log_error(f"[RSS] Error processing entry: {e}")
                    self._increment_metric('errors_total')
                    continue
            
            # Update bootstrap status
            if not bootstrap_completed and bootstrap_processed >= bootstrap_count:
                bootstrap_completed = True
                self.helper.log_info(f"[RSS] Bootstrap completed! Processed {bootstrap_processed} entries")
            
            self._update_bootstrap_status(bootstrap_processed, bootstrap_completed)
            
            # Save cache
            self._save_cache()
            
            # Cleanup old cache entries (once per day)
            current_date = datetime.now().date()
            current_state = self.helper.get_state()
            last_cleanup = current_state.get("last_cleanup_date") if current_state else None
            if not last_cleanup or last_cleanup != current_date.isoformat():
                self._cleanup_old_cache_entries()
                self.helper.set_state({"last_cleanup_date": current_date.isoformat()})
            
            # Note: STIX objects are created directly via GraphQL API with their own identities and markings
            
            self.helper.log_info(f"[RSS] Collected {len(stix_objects)} STIX objects from {processed_count} entries")
            
            # Update metrics
            self._increment_metric('rss_entries_processed', processed_count)
            
        except Exception as e:
            self.helper.log_error(f"[RSS] Error collecting intelligence: {e}")
            self._increment_metric('errors_total')
        
        return stix_objects

    def process_message(self) -> None:
        """Main connector process."""
        self.helper.log_info(
            "[RSS] Starting RSS PoC Loader connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Set metric state to running
            self._set_metric_state("running")
            
            # Check and rotate logs if needed
            if self.log_rotator.check_and_rotate():
                self.helper.log_info("[RSS] Log rotation completed")
            
            # Get current state
            now = datetime.now()
            current_state = self.helper.get_state()
            
            # Check if it's time to run
            last_run = current_state.get("last_run") if current_state else None
            bootstrap_completed = current_state.get("bootstrap_completed", False) if current_state else False
            
            # If bootstrap not completed, run immediately
            if not bootstrap_completed:
                self.helper.log_info("[RSS] Bootstrap not completed, running immediately")
            elif last_run:
                last_run_date = datetime.fromisoformat(last_run.replace('Z', '+00:00'))
                time_diff = now - last_run_date.replace(tzinfo=timezone.utc).replace(tzinfo=None)
                
                if time_diff.total_seconds() < self.config.load["rss_connector"]["check_interval"]:
                    self.helper.log_info("[RSS] Not yet time to run connector")
                    return
            
            # Update work status if work_id exists
            if hasattr(self.helper, 'work_id') and self.helper.work_id:
                try:
                    self.helper.api.work.to_received(
                        self.helper.work_id, 
                        f"RSS PoC Loader processing RSS feed - {now.isoformat()}"
                    )
                except Exception:
                    pass  # Ignore work update errors
            
            try:
                # Collect intelligence
                stix_objects = self._collect_intelligence()
                
                if stix_objects:
                    # STIX objects are already created via GraphQL API
                    self.helper.log_info(f"[RSS] Created {len(stix_objects)} STIX objects via GraphQL API")
                    
                else:
                    self.helper.log_info("[RSS] No STIX objects to create")
                
                # Update state
                self.helper.set_state({"last_run": now.isoformat()})
                
                # Update work status if work_id exists
                if hasattr(self.helper, 'work_id') and self.helper.work_id:
                    try:
                        # Count total operations from cache for this run
                        total_operations = len(self.cache)
                        operations_completed = 0
                        
                        for entry_data in self.cache.values():
                            if entry_data.get("status") in ["processed", "no_suitable_files"]:
                                operations_completed += 1
                        
                        # Update work progress with operations count
                        try:
                            # In OpenCTI, work progress is updated through the completion message
                            # We'll include progress information in the completion message
                            self.helper.log_info(f"[RSS] Work progress updated: {operations_completed}/{total_operations} operations")
                        except Exception as e:
                            self.helper.log_warning(f"[RSS] Could not update work progress: {e}")
                        
                        # Complete work with detailed information
                        completion_message = f"RSS PoC Loader completed: {operations_completed}/{total_operations} operations completed"
                        if stix_objects:
                            completion_message += f", {len(stix_objects)} STIX objects created"
                        
                        # Add progress information in the message for OpenCTI to parse
                        completion_message += f" | Progress: {operations_completed}/{total_operations} operations"
                        
                        self.helper.api.work.to_processed(self.helper.work_id, completion_message)
                        self.helper.log_info(f"[RSS] Work completed: {operations_completed}/{total_operations} operations")
                    except Exception as e:
                        self.helper.log_warning(f"[RSS] Could not complete work: {e}")
                
            except Exception as e:
                self.helper.log_error(f"[RSS] Error during work execution: {e}")
                self._increment_metric('errors_total')
                
                # Update work status if work_id exists
                if hasattr(self.helper, 'work_id') and self.helper.work_id:
                    try:
                        self.helper.api.work.to_processed(
                            self.helper.work_id, 
                            f"RSS PoC Loader error: {str(e)}"
                        )
                    except Exception:
                        pass  # Ignore work update errors
                
        except Exception as e:
            self.helper.log_error(f"[RSS] Error in process_message: {e}")
            self._increment_metric('errors_total')
        finally:
            # Set metric state back to idle
            self._set_metric_state("idle")

    def run(self) -> None:
        """Run the connector."""
        # Check and rotate logs if needed
        if self.log_rotator.check_and_rotate():
            self.helper.log_info("[RSS] Log rotation completed")
        
        self.helper.log_info("[RSS] Starting RSS PoC Loader connector")
        
        # Schedule the connector to run periodically
        self.helper.schedule_iso(self.process_message, self.config.load["connector"]["duration_period"]) 
        
        # Start the connector event loop
        self.helper.listen()
