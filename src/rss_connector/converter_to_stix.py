"""
GraphQL-based Converter for RSS PoC Connector
Implements exact functionality from RSS_Linux.py using GraphQL API
"""

import os
import hashlib
import json
import subprocess
import shutil
import time
import yaml
from datetime import datetime
from typing import Dict, Any, List, Optional
import requests


class GraphQLConverter:
    """Converts processed data into OpenCTI objects using GraphQL API (like RSS_Linux.py)."""
    
    def __init__(self, helper):
        self.helper = helper
        self.logger = helper.connector_logger
        
        # OpenCTI connection details
        self.opencti_url = helper.api.api_url
        self.opencti_token = helper.api.api_token
        
        # Cache for labels and identities
        self._label_cache = {}
        self._identity_cache = {}
        self._tlp_red_marking_id = None
        self._pap_red_marking_id = None
        
        # Initialize markings
        self._init_markings()
    
    def _init_markings(self):
        """Initialize TLP:RED and PAP:RED markings."""
        try:
            self._tlp_red_marking_id = self._get_tlp_red_marking_id()
            self._pap_red_marking_id = self._get_pap_red_marking_id()
        except Exception as e:
            self.logger.warning(f"Could not initialize markings: {e}")
    
    def _get_nvd_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVE data from NVD API with rate limiting and retries."""
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        # Get NVD API settings from config
        max_retries = 3
        base_delay = 2
        request_delay = 5
        
        try:
            # Try to get config from environment or use defaults
            config_file = os.getenv("CONNECTOR_CONFIG_FILE", "./config.yml")
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    nvd_config = config.get('nvd_api', {})
                    max_retries = nvd_config.get('max_retries', 3)
                    base_delay = nvd_config.get('base_delay', 2)
                    request_delay = nvd_config.get('request_delay', 5)
        except Exception as e:
            self.logger.warning(f"Failed to load NVD config, using defaults: {e}")
        
        for attempt in range(max_retries):
            try:
                self.logger.info(f"[NVD] Querying NVD API for {cve_id} (attempt {attempt + 1}/{max_retries})")
                
                # Add delay between requests to respect rate limit
                if attempt > 0:
                    time.sleep(request_delay)
                
                response = requests.get(nvd_url, timeout=10)
                
                # Handle rate limiting
                if response.status_code == 429:
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)  # Exponential backoff
                        self.logger.warning(f"[NVD] Rate limit exceeded for {cve_id}, waiting {delay} seconds before retry...")
                        time.sleep(delay)
                        continue
                    else:
                        self.logger.error(f"[NVD] Rate limit exceeded for {cve_id} after {max_retries} attempts")
                        return None
                
                response.raise_for_status()
                data = response.json()
                
                if "vulnerabilities" not in data or len(data["vulnerabilities"]) == 0:
                    self.logger.warning(f"[NVD] No data found for {cve_id} in NVD")
                    return None
                    
                cve_item = data["vulnerabilities"][0]["cve"]
                
                # Extract English description
                descriptions = [desc["value"] for desc in cve_item["descriptions"] if desc["lang"] == "en"]
                description = descriptions[0] if descriptions else "No description available"
                
                # Extract CVSSv3.1 metrics
                cvss_metrics = cve_item.get("metrics", {}).get("cvssMetricV31", [])
                if not cvss_metrics:
                    cvss_metrics = cve_item.get("metrics", {}).get("cvssMetricV30", [])
                
                cvss_data = {}
                if cvss_metrics:
                    cvss_data = cvss_metrics[0]["cvssData"]
                
                # Extract and format dates
                published = cve_item.get("published", "")
                modified = cve_item.get("lastModified", "")
                
                # Add timezone (UTC)
                if published: published += "Z"
                if modified: modified += "Z"
                
                # Form result
                result = {
                    "name": cve_id,
                    "description": description,
                    "base_score": cvss_data.get("baseScore", 0.0),
                    "base_severity": cvss_data.get("baseSeverity", "MEDIUM"),
                    "attack_vector": cvss_data.get("attackVector", "NETWORK"),
                    "confidentiality_impact": cvss_data.get("confidentialityImpact", "HIGH"),
                    "integrity_impact": cvss_data.get("integrityImpact", "HIGH"),
                    "availability_impact": cvss_data.get("availabilityImpact", "HIGH"),
                    "published": published,
                    "modified": modified
                }
                
                # Convert values to uppercase for OpenCTI compatibility
                for key in ["base_severity", "attack_vector", "confidentiality_impact", 
                            "integrity_impact", "availability_impact"]:
                    if key in result and isinstance(result[key], str):
                        result[key] = result[key].upper()
                
                self.logger.info(f"[NVD] Retrieved CVE data for {cve_id} on attempt {attempt + 1}")
                return result
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        self.logger.warning(f"[NVD] Rate limit exceeded for {cve_id}, waiting {delay} seconds before retry...")
                        time.sleep(delay)
                        continue
                    else:
                        self.logger.error(f"[NVD] Rate limit exceeded for {cve_id} after {max_retries} attempts")
                        return None
                else:
                    self.logger.error(f"[NVD] HTTP error for {cve_id}: {e}")
                    return None
            except Exception as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    self.logger.warning(f"[NVD] Error for {cve_id} (attempt {attempt + 1}): {e}, retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                else:
                    self.logger.error(f"[NVD] Failed to get CVE data for {cve_id} after {max_retries} attempts: {str(e)}")
                    return None
        
        return None
    
    def execute_graphql(self, query: str, variables: Dict = None) -> Optional[Dict]:
        """Execute GraphQL query."""
        data = {"query": query}
        if variables:
            data["variables"] = variables
            
        try:
            response = requests.post(
                f"{self.opencti_url}/graphql",
                headers={
                    "Authorization": f"Bearer {self.opencti_token}",
                    "Content-Type": "application/json"
                },
                data=json.dumps(data),
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            
            if "errors" in result:
                self.logger.error(f"GraphQL Error: {json.dumps(result['errors'], indent=2)}")
                return None
                
            return result.get("data")
        except Exception as e:
            self.logger.error(f"GraphQL request failed: {str(e)}")
            return None
    
    def _get_tlp_red_marking_id(self) -> Optional[str]:
        """Get TLP:RED marking ID."""
        query = """
        query MarkingDefinitions($filters: FilterGroup) {
            markingDefinitions(filters: $filters) {
                edges {
                    node {
                        id
                        definition
                        definition_type
                    }
                }
            }
        }
        """
        
        variables = {
            "filters": {
                "mode": "and",
                "filters": [{"key": "definition", "values": ["TLP:RED"]}],
                "filterGroups": []
            }
        }
        
        result = self.execute_graphql(query, variables)
        if result and "markingDefinitions" in result:
            edges = result["markingDefinitions"].get("edges", [])
            if edges:
                marking_id = edges[0]["node"]["id"]
                self.logger.info(f"Using existing TLP:RED marking: {marking_id}")
                return marking_id
        
        self.logger.error("TLP:RED marking not found in OpenCTI")
        return None
    
    def _get_pap_red_marking_id(self) -> Optional[str]:
        """Get PAP:RED marking ID."""
        query = """
        query MarkingDefinitions($filters: FilterGroup) {
            markingDefinitions(filters: $filters) {
                edges {
                    node {
                        id
                        definition
                        definition_type
                    }
                }
            }
        }
        """
        
        variables = {
            "filters": {
                "mode": "and",
                "filters": [{"key": "definition", "values": ["PAP:RED"]}],
                "filterGroups": []
            }
        }
        
        result = self.execute_graphql(query, variables)
        if result and "markingDefinitions" in result:
            edges = result["markingDefinitions"].get("edges", [])
            if edges:
                marking_id = edges[0]["node"]["id"]
                self.logger.info(f"Using existing PAP:RED marking: {marking_id}")
                return marking_id
        
        self.logger.error("PAP:RED marking not found in OpenCTI")
        return None
    
    def _get_or_create_label(self, label_name: str, color: str = "#ff9800") -> Optional[str]:
        """Get or create label with specified name and color."""
        if label_name in self._label_cache:
            return self._label_cache[label_name]
        
        # Try to find existing label
        query = """
        query Labels($filters: FilterGroup) {
            labels(filters: $filters) {
                edges {
                    node {
                        id
                        value
                        color
                    }
                }
            }
        }
        """
        
        variables = {
            "filters": {
                "mode": "and",
                "filters": [{"key": "value", "values": [label_name]}],
                "filterGroups": []
            }
        }
        
        result = self.execute_graphql(query, variables)
        if result and "labels" in result:
            edges = result["labels"].get("edges", [])
            if edges:
                label_id = edges[0]["node"]["id"]
                self._label_cache[label_name] = label_id
                self.logger.info(f"Using existing label: {label_name} (ID: {label_id})")
                return label_id
        
        # Create new label
        create_query = """
        mutation LabelAdd($input: LabelAddInput!) {
            labelAdd(input: $input) {
                id
                value
                color
            }
        }
        """
        
        create_variables = {
            "input": {
                "value": label_name,
                "color": color
            }
        }
        
        result = self.execute_graphql(create_query, create_variables)
        if result and "labelAdd" in result:
            new_label = result["labelAdd"]
            label_id = new_label["id"]
            self._label_cache[label_name] = label_id
            self.logger.info(f"Created new label: {label_name} (ID: {label_id})")
            return label_id
        
        self.logger.error(f"Failed to get or create label: {label_name}")
        return None
    
    def _get_cve_label_id(self, cve_id: str) -> Optional[str]:
        """Get or create label for CVE ID with unique color."""
        # Generate color from CVE ID for uniqueness
        hash_object = hashlib.md5(cve_id.encode())
        hash_hex = hash_object.hexdigest()
        color = f"#{hash_hex[:6]}"
        
        return self._get_or_create_label(cve_id, color)
    
    def _get_author_label_id(self, author_name: str) -> Optional[str]:
        """Get or create label for author with unique color."""
        # Generate color from author name for uniqueness
        hash_object = hashlib.md5(author_name.encode())
        hash_hex = hash_object.hexdigest()
        color = f"#{hash_hex[:6]}"
        
        return self._get_or_create_label(author_name, color)
    
    def _create_identity(self, owner_name: str, cve_id: str = None) -> Optional[Dict]:
        """Create Identity (repository owner) with labels."""
        cache_key = f"{owner_name}_{cve_id or 'default'}"
        if cache_key in self._identity_cache:
            return self._identity_cache[cache_key]
        
        # Get label IDs
        identity_label_ids = []
        
        # PoC label (blue)
        poc_label_id = self._get_or_create_label("PoC", "#2196F3")
        if poc_label_id:
            identity_label_ids.append(poc_label_id)
        
        # CVE ID label (unique color) - if CVE ID provided
        if cve_id:
            cve_label_id = self._get_cve_label_id(cve_id)
            if cve_label_id:
                identity_label_ids.append(cve_label_id)
        
        query = """
        mutation IdentityAdd($input: IdentityAddInput!) {
            identityAdd(input: $input) {
                id
                standard_id
                name
                description
                objectLabel {
                    id
                    value
                    color
                }
            }
        }
        """
        
        input_data = {
            "name": owner_name,
            "description": f"GitHub repository owner: {owner_name}",
            "type": "Individual"
        }
        
        if identity_label_ids:
            input_data["objectLabel"] = identity_label_ids
        
        if self._tlp_red_marking_id:
            input_data["objectMarking"] = [self._tlp_red_marking_id]
        
        variables = {"input": input_data}
        
        result = self.execute_graphql(query, variables)
        if result and "identityAdd" in result:
            identity = result["identityAdd"]
            self._identity_cache[cache_key] = identity
            self.logger.info(f"Created Identity: {identity['id']} for {owner_name} with {len(identity_label_ids)} labels")
            return identity
        
        return None
    
    def _create_external_reference(self, repository_url: str, description: str) -> Optional[Dict]:
        """Create External Reference for repository."""
        query = """
        mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) {
            externalReferenceAdd(input: $input) {
                id
                source_name
                url
                description
            }
        }
        """
        
        variables = {
            "input": {
                "source_name": "GitHub Repository",
                "url": repository_url,
                "description": description
            }
        }
        
        result = self.execute_graphql(query, variables)
        if result and "externalReferenceAdd" in result:
            ref = result["externalReferenceAdd"]
            self.logger.info(f"Created External Reference: {ref['id']} for {repository_url}")
            return ref
        
        return None
    
    def _create_cve_external_reference(self, cve_id: str) -> Optional[Dict]:
        """Create External Reference for CVE."""
        try:
            self.logger.info(f"[NVD] Creating NVD external reference for {cve_id}")
            
            query = """
            mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) {
                externalReferenceAdd(input: $input) {
                    id
                    source_name
                    url
                    description
                }
            }
            """
            
            variables = {
                "input": {
                    "source_name": "CVE Reference",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "description": f"Official NVD reference for {cve_id}"
                }
            }
            
            result = self.execute_graphql(query, variables)
            if result and "externalReferenceAdd" in result:
                ref = result["externalReferenceAdd"]
                self.logger.info(f"Created CVE External Reference: {ref['id']} for {cve_id}")
                return ref
            else:
                self.logger.error(f"[NVD] Failed to create external reference for {cve_id}: GraphQL error")
                return None
                
        except Exception as e:
            self.logger.error(f"[NVD] Error creating external reference for {cve_id}: {e}")
            return None
    
    def _extract_tool_version(self, repository_url: str, cve_id: str) -> Optional[str]:
        """Extract tool version from repository locally."""
        try:
            # Extract owner and repo from URL
            parts = repository_url.replace("https://github.com/", "").split("/")
            if len(parts) < 2:
                return None
            
            owner, repo = parts[0], parts[1]
            
            # Check files that might contain version
            version_files = [
                "package.json", "setup.py", "pyproject.toml", "Cargo.toml",
                "go.mod", "requirements.txt", "VERSION", "version.txt"
            ]
            
            # Look for version files in already cloned repository
            for file_name in version_files:
                try:
                    # Look for file in working directory
                    file_path = os.path.join("/opt/opencti-rss-connector/work", f"{owner}_{repo}_{cve_id}", file_name)
                    if os.path.isfile(file_path):
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content_text = f.read()
                            
                            # Look for version in different formats
                            import re
                            
                            # package.json
                            if file_name == "package.json":
                                version_match = re.search(r'"version"\s*:\s*"([^"]+)"', content_text)
                                if version_match:
                                    return version_match.group(1)
                            
                            # setup.py
                            elif file_name == "setup.py":
                                version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content_text)
                                if version_match:
                                    return version_match.group(1)
                            
                            # pyproject.toml
                            elif file_name == "pyproject.toml":
                                version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content_text)
                                if version_match:
                                    return version_match.group(1)
                            
                            # Cargo.toml
                            elif file_name == "Cargo.toml":
                                version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content_text)
                                if version_match:
                                    return version_match.group(1)
                            
                            # go.mod
                            elif file_name == "go.mod":
                                version_match = re.search(r'v(\d+\.\d+\.\d+)', content_text)
                                if version_match:
                                    return version_match.group(1)
                            
                            # Simple version files
                            elif file_name in ["VERSION", "version.txt"]:
                                version_match = re.search(r'(\d+\.\d+\.\d+)', content_text)
                                if version_match:
                                    return version_match.group(1)
                except Exception as e:
                    self.logger.debug(f"Error checking {file_name}: {e}")
                    continue
            
            return None
        except Exception as e:
            self.logger.debug(f"Error extracting version: {e}")
            return None
    
    def _create_tool(self, cve_id: str, repository_url: str, description: str, 
                     tool_version: str = None, identity_id: str = None, 
                     external_ref_id: str = None, additional_labels: List[str] = None) -> Optional[Dict]:
        """Create Tool object for PoC with labels."""
        # Extract owner and repo from URL
        parts = repository_url.replace("https://github.com/", "").split("/")
        if len(parts) < 2:
            self.logger.error(f"Invalid GitHub URL: {repository_url}")
            return None
        
        owner, repo = parts[0], parts[1]
        tool_name = f"{repo}/{cve_id}"
        
        # Get or create labels
        label_ids = []
        
        # PoC label (blue)
        poc_label_id = self._get_or_create_label("PoC", "#2196F3")
        if poc_label_id:
            label_ids.append(poc_label_id)
        
        # CVE ID label (unique color)
        cve_label_id = self._get_cve_label_id(cve_id)
        if cve_label_id:
            label_ids.append(cve_label_id)
        
        # Author label (unique color)
        author_label_id = self._get_author_label_id(owner)
        if author_label_id:
            label_ids.append(author_label_id)
        
        # Add additional labels if provided
        if additional_labels:
            for label_id in additional_labels:
                if label_id and label_id not in label_ids:
                    label_ids.append(label_id)
        
        query = """
        mutation ToolAdd($input: ToolAddInput!) {
            toolAdd(input: $input) {
                id
                name
                description
                tool_version
                tool_types
                createdBy {
                    id
                    name
                }
                externalReferences {
                    edges {
                        node {
                            id
                            source_name
                            url
                        }
                    }
                }
                objectLabel {
                    id
                    value
                    color
                }
            }
        }
        """
        
        # Prepare input data
        input_data = {
            "name": tool_name,
            "description": description,
            "tool_types": ["Proof of Concept", "Exploit"]
        }
        
        if tool_version:
            input_data["tool_version"] = tool_version
        
        if identity_id:
            input_data["createdBy"] = identity_id
        
        if external_ref_id:
            input_data["externalReferences"] = [external_ref_id]
        
        if label_ids:
            input_data["objectLabel"] = label_ids
        
        if self._tlp_red_marking_id:
            input_data["objectMarking"] = [self._tlp_red_marking_id]
        
        variables = {"input": input_data}
        
        result = self.execute_graphql(query, variables)
        if result and "toolAdd" in result:
            tool = result["toolAdd"]
            self.logger.info(f"Created Tool: {tool['id']} for {cve_id} with {len(label_ids)} labels")
            return tool
        
        return None
    
    def _create_vulnerability_minimal(self, cve_id: str, external_ref_id: str = None, 
                                    labels: List[str] = None, description: str = None) -> Optional[Dict]:
        """Create Vulnerability object with minimal data."""
        # Try to get NVD data first
        nvd_data = self._get_nvd_data(cve_id)
        
        # Get or create labels
        label_ids = []
        if labels:
            for label_name in labels:
                label_id = self._get_or_create_label(label_name)
                if label_id:
                    label_ids.append(label_id)
        
        # Use NVD data if available, otherwise use current time
        if nvd_data:
            created_time = nvd_data.get("published", datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
            modified_time = nvd_data.get("modified", datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))
            description = nvd_data.get("description", description)
            
            # Note: CVSS data will be added to Vulnerability fields, not as labels
        else:
            created_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            modified_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            if not description:
                description = f"Vulnerability {cve_id} identified through PoC repository analysis. No NVD data available."
        
        # Always create NVD external reference for CVE
        nvd_external_ref = self._create_cve_external_reference(cve_id)
        
        if nvd_external_ref:
            self.logger.info(f"[NVD] Successfully created NVD external reference for {cve_id}")
        else:
            self.logger.warning(f"[NVD] Failed to create NVD external reference for {cve_id}")
        
        # Prepare external references list
        external_refs = []
        if nvd_external_ref:
            external_refs.append(nvd_external_ref["id"])
        if external_ref_id:
            external_refs.append(external_ref_id)
        
        query = """
        mutation VulnerabilityAdd($input: VulnerabilityAddInput!) {
            vulnerabilityAdd(input: $input) {
                id
                name
                description
                x_opencti_cvss_base_score
                x_opencti_cvss_base_severity
                x_opencti_cvss_attack_vector
                x_opencti_cvss_integrity_impact
                x_opencti_cvss_availability_impact
                x_opencti_cvss_confidentiality_impact
                created
                modified
                externalReferences {
                    edges {
                        node {
                            id
                            source_name
                            url
                        }
                    }
                }
                objectLabel {
                    id
                    value
                    color
                }
            }
        }
        """
        
        variables = {
            "input": {
                "name": cve_id,
                "description": description,
                "created": created_time,
                "modified": modified_time,
                "objectLabel": label_ids
            }
        }
        
        # Add CVSS data to Vulnerability fields if available from NVD
        if nvd_data:
            if "base_score" in nvd_data:
                variables["input"]["x_opencti_cvss_base_score"] = nvd_data["base_score"]
            if "base_severity" in nvd_data:
                variables["input"]["x_opencti_cvss_base_severity"] = nvd_data["base_severity"]
            if "attack_vector" in nvd_data:
                variables["input"]["x_opencti_cvss_attack_vector"] = nvd_data["attack_vector"]
            if "integrity_impact" in nvd_data:
                variables["input"]["x_opencti_cvss_integrity_impact"] = nvd_data["integrity_impact"]
            if "availability_impact" in nvd_data:
                variables["input"]["x_opencti_cvss_availability_impact"] = nvd_data["availability_impact"]
            if "confidentiality_impact" in nvd_data:
                variables["input"]["x_opencti_cvss_confidentiality_impact"] = nvd_data["confidentiality_impact"]
        
        # Add External References (NVD + repository if provided)
        if external_refs:
            variables["input"]["externalReferences"] = external_refs
        
        if self._tlp_red_marking_id:
            variables["input"]["objectMarking"] = [self._tlp_red_marking_id]
        
        result = self.execute_graphql(query, variables)
        if result and "vulnerabilityAdd" in result:
            vuln = result["vulnerabilityAdd"]
            self.logger.info(f"Created minimal Vulnerability: {vuln['id']} for {cve_id}")
            return vuln
        
        return None
    
    def _create_relation(self, from_id: str, to_id: str, relationship_type: str, 
                        identity_id: str, description: str = None) -> Optional[Dict]:
        """Create relationship between objects."""
        query = """
        mutation RelationAdd($input: StixCoreRelationshipAddInput!) {
            stixCoreRelationshipAdd(input: $input) {
                id
                standard_id
                entity_type
                from {
                    ... on BasicObject {
                        id
                    }
                }
                to {
                    ... on BasicObject {
                        id
                    }
                }
                relationship_type
            }
        }
        """
        
        input_data = {
            "fromId": from_id,
            "toId": to_id,
            "relationship_type": relationship_type,
            "createdBy": identity_id
        }
        
        if description:
            input_data["description"] = description
        
        if self._tlp_red_marking_id:
            input_data["objectMarking"] = [self._tlp_red_marking_id]
        
        variables = {"input": input_data}
        
        result = self.execute_graphql(query, variables)
        if result and "stixCoreRelationshipAdd" in result:
            relation = result["stixCoreRelationshipAdd"]
            self.logger.info(f"Created Relation: {relation['id']} ({relationship_type})")
            return relation
        
        return None
    
    def _attach_file_to_object(self, stix_core_object_id: str, file_path: str) -> bool:
        """Attach file to existing object using GraphQL introspection."""
        try:
            if not os.path.isfile(file_path):
                self.logger.error(f"File not found for attachment: {file_path}")
                return False

            # Discover valid upload fields for current OpenCTI version
            nested_upload_candidates = [
                "addFile", "fileAdd", "fileUpload", "upload", "importPush"
            ]
            editor_mutations = [
                ("stixCoreObjectEdit", "StixCoreObjectEditMutations"),
                ("stixDomainObjectEdit", "StixDomainObjectEditMutations"),
            ]
            graphql_candidates = []

            # Try nested editor mutations first
            for root_field, type_name in editor_mutations:
                available = self._graphql_introspect_fields(type_name)
                for nested in nested_upload_candidates:
                    if nested in available:
                        graphql_candidates.append({
                            "kind": "nested",
                            "root": root_field,
                            "nested": nested,
                        })
                        break  # pick first match per editor type

            # Fallback: direct mutation names at root
            root_fields = self._graphql_list_mutations()
            for direct in ["stixCoreObjectAddFile", "stixDomainObjectAddFile"]:
                if direct in root_fields:
                    graphql_candidates.append({
                        "kind": "direct",
                        "name": direct,
                    })

            if not graphql_candidates:
                self.logger.warning("No suitable file upload mutation discovered in schema; skipping file attachment")
                return False

            file_map = json.dumps({"0": ["variables.file"]})

            with open(file_path, 'rb') as f:
                for cand in graphql_candidates:
                    f.seek(0)
                    if cand["kind"] == "nested":
                        query = f"""
                        mutation AttachFile($id: ID!, $file: Upload!) {{
                          {cand['root']}(id: $id) {{
                            {cand['nested']}(file: $file) {{
                              id
                            }}
                          }}
                        }}
                        """
                    else:
                        query = f"""
                        mutation AttachFile($id: ID!, $file: Upload!) {{
                          {cand['name']}(id: $id, file: $file) {{ id }}
                        }}
                        """

                    operations = json.dumps({
                        "query": query,
                        "variables": {"id": stix_core_object_id, "file": None},
                    })
                    files = {
                        "operations": (None, operations, "application/json"),
                        "map": (None, file_map, "application/json"),
                        "0": (os.path.basename(file_path), f, "application/octet-stream"),
                    }
                    try:
                        response = requests.post(
                            f"{self.opencti_url}/graphql",
                            headers={"Authorization": f"Bearer {self.opencti_token}"},
                            files=files,
                            timeout=60
                        )
                        response.raise_for_status()
                        result = response.json()
                        if "errors" in result:
                            self.logger.warning(f"Attach attempt failed ({cand}): {json.dumps(result['errors'])}")
                            continue
                        self.logger.info(f"File '{os.path.basename(file_path)}' attached to object {stix_core_object_id}")
                        return True
                    except Exception as e:
                        self.logger.warning(f"Attach attempt raised exception for {cand}: {str(e)}")
                        continue

            self.logger.warning("Failed to attach file to object with discovered mutations")
            return False

        except Exception as e:
            self.logger.error(f"Failed to attach file: {str(e)}")
            return False
    
    def _graphql_introspect_fields(self, type_name: str) -> List[str]:
        """Introspect GraphQL fields for a type."""
        try:
            query = '''
            query Introspect($type: String!) {
              __type(name: $type) {
                name
                fields { name }
              }
            }'''
            data = {"query": query, "variables": {"type": type_name}}
            resp = requests.post(
                f"{self.opencti_url}/graphql",
                headers={"Authorization": f"Bearer {self.opencti_token}", "Content-Type": "application/json"},
                data=json.dumps(data),
                timeout=30
            )
            resp.raise_for_status()
            j = resp.json()
            fields = j.get('data', {}).get('__type', {}).get('fields', [])
            return [f.get('name') for f in fields]
        except Exception:
            return []
    
    def _graphql_list_mutations(self) -> List[str]:
        """List available GraphQL mutations."""
        try:
            query = '{ __schema { mutationType { fields { name } } } }'
            resp = requests.post(
                f"{self.opencti_url}/graphql",
                headers={"Authorization": f"Bearer {self.opencti_token}", "Content-Type": "application/json"},
                data=json.dumps({"query": query}),
                timeout=30
            )
            resp.raise_for_status()
            j = resp.json()
            fields = j.get('data', {}).get('__schema', {}).get('mutationType', {}).get('fields', [])
            return [f.get('name') for f in fields]
        except Exception:
            return []
    
    def create_artifact_with_tool_and_vulnerability(self, file_path: str, description: str, hashes: Dict[str, str], 
                                                  cve_id: str, repository_url: str, pub_date: str, 
                                                  original_description: str, repo_path: str = None) -> Optional[str]:
        """Create Artifact, Tool and Vulnerability in OpenCTI and link them (like RSS_Linux.py)."""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return None
            
            # Extract owner from URL
            parts = repository_url.replace("https://github.com/", "").split("/")
            if len(parts) < 2:
                self.logger.error(f"Invalid GitHub URL: {repository_url}")
                return None
            
            owner, repo = parts[0], parts[1]
            
            # Create Identity (repository owner)
            identity = self._create_identity(owner, cve_id)
            identity_id = identity["id"] if identity else None
            
            # Create External Reference (repository link)
            ext_ref_description = f"GitHub repository for {cve_id} PoC. Published: {pub_date}"
            external_ref = self._create_external_reference(repository_url, ext_ref_description)
            external_ref_id = external_ref["id"] if external_ref else None
            
            # Extract tool version
            tool_version = self._extract_tool_version(repository_url, cve_id)
            
            # Create Tool
            tool = self._create_tool(cve_id, repository_url, original_description, tool_version, identity_id, external_ref_id)
            
            if not tool:
                self.logger.error(f"Failed to create Tool for {cve_id}")
                return None
            
            tool_id = tool["id"]
            
            # Attach repository archive to Tool (if repository path exists)
            try:
                if repo_path and os.path.isdir(repo_path):
                    # Create repository archive for attachment
                    archive_path = os.path.join("/tmp", f"{cve_id}_repository.tar.gz")
                    try:
                        # Create tar.gz archive
                        result = subprocess.run([
                            'tar', '-czf', archive_path, '-C', os.path.dirname(repo_path), os.path.basename(repo_path)
                        ], capture_output=True, text=True, timeout=60)
                        
                        if result.returncode == 0 and os.path.isfile(archive_path):
                            self.logger.info(f"Attaching repository archive to Tool {tool_id}: {os.path.basename(archive_path)}")
                            attach_ok = self._attach_file_to_object(tool_id, archive_path)
                            if attach_ok:
                                # Remove archive after attachment
                                os.remove(archive_path)
                                self.logger.info(f"Removed archive after attachment: {archive_path}")
                            else:
                                self.logger.warning("Could not attach repository archive to Tool")
                        else:
                            self.logger.warning(f"Failed to create repository archive: {result.stderr}")
                    except Exception as e:
                        self.logger.warning(f"Failed to create repository archive: {e}")
                else:
                    self.logger.warning("Repository path is missing; skipping attachment to Tool")
            except Exception as e:
                self.logger.warning(f"Failed to attach repository to Tool: {e}")
            
            # Create Vulnerability (will automatically try to get NVD data)
            vuln_labels = ["PoC", cve_id]
            vuln_description = f"Vulnerability {cve_id} identified through PoC repository analysis."
            
            vulnerability = self._create_vulnerability_minimal(cve_id, None, vuln_labels, vuln_description)
            
            if vulnerability:
                vuln_id = vulnerability["id"]
                self.logger.info(f"Created Vulnerability for {cve_id}")
            else:
                self.logger.warning(f"Failed to create Vulnerability for {cve_id}")
                vuln_id = None
            
            # Create relationship between Tool and Vulnerability
            if vulnerability and vuln_id:
                tool_vuln_relation = self._create_relation(
                    tool_id, 
                    vuln_id, 
                    "targets", 
                    identity_id,
                    f"PoC tool targets {cve_id} vulnerability"
                )
                
                if tool_vuln_relation:
                    self.logger.info(f"Created relation between Tool and Vulnerability for {cve_id}")
                else:
                    self.logger.warning(f"Failed to create relation for {cve_id}")
            
            # Get or create labels for artifact
            artifact_label_ids = []
            
            # PoC label (blue)
            poc_label_id = self._get_or_create_label("PoC", "#2196F3")
            if poc_label_id:
                artifact_label_ids.append(poc_label_id)
            
            # CVE ID label (unique color)
            cve_label_id = self._get_cve_label_id(cve_id)
            if cve_label_id:
                artifact_label_ids.append(cve_label_id)
            
            # Author label (unique color)
            author_label_id = self._get_author_label_id(owner)
            if author_label_id:
                artifact_label_ids.append(author_label_id)
            
            # Create Artifact with labels, author and markings
            operations = {
                "query": """
                    mutation AddArtifact($file: Upload!, $description: String, $objectLabel: [String], $createdBy: String, $objectMarking: [String]) {
                        artifactImport(file: $file, x_opencti_description: $description, objectLabel: $objectLabel, createdBy: $createdBy, objectMarking: $objectMarking) {
                            id
                            standard_id
                            objectLabel {
                                id
                                value
                                color
                            }
                            createdBy {
                                id
                                name
                            }
                            objectMarking {
                                id
                                definition
                                definition_type
                            }
                        }
                    }
                """,
                "variables": {
                    "description": description,
                    "file": None,
                    "objectLabel": artifact_label_ids,
                    "createdBy": identity_id,
                    "objectMarking": []
                }
            }
            
            # Add markings if found
            marking_ids = []
            if self._tlp_red_marking_id:
                marking_ids.append(self._tlp_red_marking_id)
            if self._pap_red_marking_id:
                marking_ids.append(self._pap_red_marking_id)
            
            if marking_ids:
                operations["variables"]["objectMarking"] = marking_ids
            
            # Prepare map for file
            map_data = {"0": ["variables.file"]}
            
            # Get file name
            file_name = os.path.basename(file_path)
            
            # Create multipart request
            files = {
                "operations": (None, json.dumps(operations), "application/json"),
                "map": (None, json.dumps(map_data), "application/json"),
                "0": (file_name, open(file_path, "rb"), "application/octet-stream")
            }
            
            headers = {
                "Authorization": f"Bearer {self.opencti_token}",
                "Accept": "application/json",
            }
            
            # Send request
            response = requests.post(
                f"{self.opencti_url}/graphql",
                files=files,
                headers=headers,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                if "errors" in result:
                    self.logger.error(f"Artifact creation failed: {json.dumps(result['errors'], indent=2)}")
                    return None
                else:
                    artifact_id = result["data"]["artifactImport"]["id"]
                    self.logger.info(f"Artifact created successfully! ID: {artifact_id} with {len(artifact_label_ids)} labels")
                    
                    # Create relationship between Artifact and Tool
                    try:
                        artifact_tool_relation = self._create_relation(
                            artifact_id,
                            tool_id,
                            "related-to",
                            identity_id,
                            f"PoC artifact for {cve_id} tool"
                        )
                        if artifact_tool_relation:
                            self.logger.info(f"Created relation between artifact and tool for {cve_id}")
                        else:
                            self.logger.warning("Failed to create relation between artifact and tool")
                    except Exception as e:
                        self.logger.warning(f"Failed to create relation: {e}")
                    
                    return artifact_id
            else:
                self.logger.error(f"Request failed with status {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error during artifact creation: {str(e)}")
            return None
        finally:
            # Close file if it was opened
            if 'files' in locals() and '0' in files and hasattr(files['0'][1], 'close'):
                files['0'][1].close()
    
    def create_tool_and_vulnerability_for_empty_repo(self, cve_id: str, repository_url: str, pub_date: str, 
                                                   original_description: str, repo_path: str = None) -> bool:
        """Create Tool and Vulnerability for empty repository (without artifacts)."""
        try:
            self.logger.info(f"Creating Tool and Vulnerability for empty repository {cve_id}")
            
            # Extract owner from URL
            parts = repository_url.replace("https://github.com/", "").split("/")
            if len(parts) < 2:
                self.logger.error(f"Invalid GitHub URL: {repository_url}")
                return False
            
            owner, repo = parts[0], parts[1]
            
            # Create Identity (repository owner)
            identity = self._create_identity(owner, cve_id)
            identity_id = identity["id"] if identity else None
            
            # Create External Reference (repository link)
            ext_ref_description = f"GitHub repository for {cve_id} PoC. Published: {pub_date}. Note: Repository contains only documentation/media files."
            external_ref = self._create_external_reference(repository_url, ext_ref_description)
            external_ref_id = external_ref["id"] if external_ref else None
            
            # Create Tool with additional label for empty repository
            # First get or create special label
            empty_repo_label_id = self._get_or_create_label("Empty Repository", "#9E9E9E")  # Gray color
            
            # Create Tool with additional label
            tool = self._create_tool(cve_id, repository_url, original_description, None, identity_id, external_ref_id, [empty_repo_label_id])
            
            if not tool:
                self.logger.error(f"Failed to create Tool for empty repository {cve_id}")
                return False
            
            tool_id = tool["id"]
            self.logger.info(f"Created Tool for empty repository {cve_id}")
            
            # Create minimal Vulnerability (will automatically try to get NVD data)
            vuln_labels = ["PoC", cve_id]
            vuln_description = f"Vulnerability {cve_id} identified through PoC repository analysis. Repository contains only documentation/media files."
            
            vulnerability = self._create_vulnerability_minimal(cve_id, None, vuln_labels, vuln_description)
            
            if vulnerability:
                vuln_id = vulnerability["id"]
                # Log vulnerability creation
                self.logger.info(f"Created Vulnerability for empty repository {cve_id}")
            else:
                self.logger.warning(f"Failed to create minimal Vulnerability for empty repository {cve_id}")
                vuln_id = None
            
            # Create relationship between Tool and Vulnerability
            if vulnerability and vuln_id:
                tool_vuln_relation = self._create_relation(
                    tool_id, 
                    vuln_id, 
                    "targets", 
                    identity_id,
                    f"PoC tool targets {cve_id} vulnerability (empty repository - documentation only)"
                )
                
                if tool_vuln_relation:
                    self.logger.info(f"Created relation between Tool and Vulnerability for empty repository {cve_id}")
                else:
                    self.logger.warning(f"Failed to create relation for empty repository {cve_id}")
            
            # Attach repository archive to Tool (if repository path exists)
            try:
                if repo_path and os.path.isdir(repo_path):
                    # Create repository archive for attachment
                    archive_path = os.path.join("/tmp", f"{cve_id}_repository.tar.gz")
                    try:
                        # Create tar.gz archive
                        result = subprocess.run([
                            'tar', '-czf', archive_path, '-C', os.path.dirname(repo_path), os.path.basename(repo_path)
                        ], capture_output=True, text=True, timeout=60)
                        
                        if result.returncode == 0 and os.path.isfile(archive_path):
                            self.logger.info(f"Attaching repository archive to Tool {tool_id}: {os.path.basename(archive_path)}")
                            attach_ok = self._attach_file_to_object(tool_id, archive_path)
                            if attach_ok:
                                # Remove archive after attachment
                                os.remove(archive_path)
                                self.logger.info(f"Removed archive after attachment: {archive_path}")
                            else:
                                self.logger.warning("Could not attach repository archive to Tool")
                        else:
                            self.logger.warning(f"Failed to create repository archive: {result.stderr}")
                    except Exception as e:
                        self.logger.warning(f"Failed to create repository archive: {e}")
                else:
                    self.logger.warning("Repository path is missing; skipping attachment to Tool")
            except Exception as e:
                self.logger.warning(f"Failed to attach repository to Tool: {e}")
            
            self.logger.info(f"Successfully processed empty repository {cve_id} (Tool + Vulnerability created)")
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing empty repository {cve_id}: {str(e)}")
            return False
