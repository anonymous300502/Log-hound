"""
SentinelGraph OCSF Mapper
Transforms raw Windows events into OCSF v1.1.0 compliant JSON objects.
"""

import yaml
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OCSFMapper:
    """
    Maps raw Windows event logs to OCSF v1.1.0 schema.
    Uses declarative YAML configuration for event mappings.
    """
    
    # Windows Logon Type to OCSF Auth Protocol mapping
    LOGON_TYPE_MAPPING = {
        '2': {'auth_protocol': 'Interactive', 'auth_protocol_id': 1},
        '3': {'auth_protocol': 'Network', 'auth_protocol_id': 2},
        '4': {'auth_protocol': 'Batch', 'auth_protocol_id': 3},
        '5': {'auth_protocol': 'Service', 'auth_protocol_id': 4},
        '7': {'auth_protocol': 'Unlock', 'auth_protocol_id': 5},
        '8': {'auth_protocol': 'NetworkCleartext', 'auth_protocol_id': 6},
        '9': {'auth_protocol': 'NewCredentials', 'auth_protocol_id': 7},
        '10': {'auth_protocol': 'RemoteInteractive', 'auth_protocol_id': 8},
        '11': {'auth_protocol': 'CachedInteractive', 'auth_protocol_id': 9}
    }
    
    def __init__(self, mappings_path: str):
        """
        Initialize the OCSF mapper.
        
        Args:
            mappings_path: Path to the YAML mappings configuration file
        """
        self.mappings_path = mappings_path
        self.event_mappings = {}
        self.load_mappings()
    
    def load_mappings(self):
        """Load event mappings from YAML configuration."""
        try:
            with open(self.mappings_path, 'r') as f:
                config = yaml.safe_load(f)
                self.event_mappings = config.get('event_mapping', {})
            logger.info(f"Loaded {len(self.event_mappings)} event mappings from {self.mappings_path}")
        except FileNotFoundError:
            logger.error(f"Mappings file not found: {self.mappings_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML: {str(e)}")
            raise
    
    def map_event(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Map a raw Windows event to OCSF format.
        
        Args:
            raw_event: Dictionary containing parsed System and EventData
            
        Returns:
            OCSF-compliant event dictionary or None if mapping not found
        """
        # Extract Event ID
        event_id = raw_event.get('System', {}).get('EventID')
        if not event_id:
            logger.warning("Event missing EventID, skipping")
            return None
        
        event_id_str = str(event_id)
        
        # Check if mapping exists
        if event_id_str not in self.event_mappings:
            logger.debug(f"No mapping found for Event ID {event_id_str}")
            return None
        
        mapping_config = self.event_mappings[event_id_str]
        ocsf_class = mapping_config.get('ocsf_class')
        field_mappings = mapping_config.get('mapping', {})
        
        # Build OCSF base structure
        ocsf_event = {
            'class_uid': ocsf_class,
            'class_name': self._get_class_name(ocsf_class),
            'category_uid': self._get_category_uid(ocsf_class),
            'severity_id': 1,  # Informational by default
            'severity': 'Informational',
            'metadata': {
                'version': '1.1.0',
                'product': {
                    'name': 'Windows Event Log',
                    'vendor_name': 'Microsoft'
                },
                'uid': str(uuid.uuid4()),
                'logged_time': self._parse_timestamp(raw_event.get('System', {}).get('TimeCreated_SystemTime')),
                'original_time': raw_event.get('System', {}).get('TimeCreated_SystemTime')
            },
            'time': self._parse_timestamp(raw_event.get('System', {}).get('TimeCreated_SystemTime')),
            'raw_data': raw_event.get('raw_xml', ''),
            'unmapped': {}
        }
        
        # Apply field mappings
        self._apply_mappings(ocsf_event, raw_event, field_mappings)
        
        # Apply event-specific enrichment
        self._enrich_event(ocsf_event, raw_event, event_id_str)
        
        return ocsf_event
    
    def _apply_mappings(self, ocsf_event: Dict[str, Any], raw_event: Dict[str, Any], 
                       field_mappings: Dict[str, str]):
        """
        Apply field mappings from raw event to OCSF event.
        
        Args:
            ocsf_event: OCSF event being built
            raw_event: Raw source event
            field_mappings: Dictionary of source_field -> ocsf_path mappings
        """
        event_data = raw_event.get('EventData', {})
        system_data = raw_event.get('System', {})
        
        for source_field, ocsf_path in field_mappings.items():
            # Get value from EventData or System
            value = event_data.get(source_field) or system_data.get(source_field)
            
            if value is not None:
                self._set_nested_value(ocsf_event, ocsf_path, value)
    
    def _set_nested_value(self, obj: Dict[str, Any], path: str, value: Any):
        """
        Set a nested dictionary value using dot notation path.
        
        Args:
            obj: Dictionary to modify
            path: Dot-separated path (e.g., 'user.name')
            value: Value to set
        """
        keys = path.split('.')
        current = obj
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def _enrich_event(self, ocsf_event: Dict[str, Any], raw_event: Dict[str, Any], event_id: str):
        """
        Apply event-specific enrichment logic.
        
        Args:
            ocsf_event: OCSF event being enriched
            raw_event: Raw source event
            event_id: Windows Event ID
        """
        event_data = raw_event.get('EventData', {})
        
        # Enrich authentication events (Class 3002)
        if ocsf_event.get('class_uid') == 3002:
            self._enrich_authentication(ocsf_event, event_data, event_id)
        
        # Enrich process events (Class 1007)
        elif ocsf_event.get('class_uid') == 1007:
            self._enrich_process(ocsf_event, event_data)
        
        # Enrich account change events (Class 3006)
        elif ocsf_event.get('class_uid') == 3006:
            self._enrich_account_change(ocsf_event, event_data, event_id)
        
        # Enrich network events (Class 4001)
        elif ocsf_event.get('class_uid') == 4001:
            self._enrich_network(ocsf_event, event_data)
    
    def _enrich_authentication(self, ocsf_event: Dict[str, Any], event_data: Dict[str, Any], event_id: str):
        """Enrich authentication events with logon type and outcome."""
        # Set activity and outcome based on Event ID
        if event_id == '4624':
            ocsf_event['activity_id'] = 1  # Logon
            ocsf_event['activity_name'] = 'Logon'
            ocsf_event['status'] = 'Success'
            ocsf_event['status_id'] = 1
        elif event_id == '4625':
            ocsf_event['activity_id'] = 1  # Logon
            ocsf_event['activity_name'] = 'Logon'
            ocsf_event['status'] = 'Failure'
            ocsf_event['status_id'] = 2
            ocsf_event['severity_id'] = 2  # Low severity for failed logon
            ocsf_event['severity'] = 'Low'
        elif event_id == '4768':
            ocsf_event['activity_id'] = 3  # Authentication Ticket
            ocsf_event['activity_name'] = 'Authentication Ticket'
            ocsf_event['status'] = 'Success'
            ocsf_event['status_id'] = 1
        
        # Map Windows Logon Type to OCSF auth_protocol
        logon_type = event_data.get('LogonType', '')
        if logon_type in self.LOGON_TYPE_MAPPING:
            auth_info = self.LOGON_TYPE_MAPPING[logon_type]
            ocsf_event['auth_protocol'] = auth_info['auth_protocol']
            ocsf_event['auth_protocol_id'] = auth_info['auth_protocol_id']
        
        # Add logon process information
        if 'LogonProcessName' in event_data:
            if 'session' not in ocsf_event:
                ocsf_event['session'] = {}
            ocsf_event['session']['logon_process'] = event_data['LogonProcessName']
    
    def _enrich_process(self, ocsf_event: Dict[str, Any], event_data: Dict[str, Any]):
        """Enrich process creation events."""
        ocsf_event['activity_id'] = 1  # Launch
        ocsf_event['activity_name'] = 'Launch'
        
        # Extract process details
        if 'process' not in ocsf_event:
            ocsf_event['process'] = {}
        
        # Add parent process if available
        if 'ParentProcessName' in event_data:
            ocsf_event['parent_process'] = {
                'name': event_data['ParentProcessName']
            }
        
        # Add process integrity level
        if 'MandatoryLabel' in event_data:
            ocsf_event['process']['integrity'] = event_data['MandatoryLabel']
    
    def _enrich_account_change(self, ocsf_event: Dict[str, Any], event_data: Dict[str, Any], event_id: str):
        """Enrich account change events."""
        if event_id == '4720':
            ocsf_event['activity_id'] = 1  # Create
            ocsf_event['activity_name'] = 'Create'
        elif event_id == '4732':
            ocsf_event['activity_id'] = 2  # Add to Group
            ocsf_event['activity_name'] = 'Add to Group'
        
        # Add target account info
        if 'TargetUserName' in event_data:
            ocsf_event['target_user'] = {
                'name': event_data['TargetUserName']
            }
            if 'TargetDomainName' in event_data:
                ocsf_event['target_user']['domain'] = event_data['TargetDomainName']
    
    def _enrich_network(self, ocsf_event: Dict[str, Any], event_data: Dict[str, Any]):
        """Enrich network activity events."""
        ocsf_event['activity_id'] = 6  # Share Access
        ocsf_event['activity_name'] = 'Share Access'
        
        # Add share information
        if 'ShareName' in event_data:
            ocsf_event['share_name'] = event_data['ShareName']
    
    def _get_class_name(self, class_uid: int) -> str:
        """Get OCSF class name from UID."""
        class_names = {
            3002: 'Authentication',
            1007: 'Process Activity',
            3006: 'Account Change',
            4001: 'Network Activity'
        }
        return class_names.get(class_uid, 'Unknown')
    
    def _get_category_uid(self, class_uid: int) -> int:
        """Get OCSF category UID from class UID."""
        # Category mappings based on OCSF v1.1.0
        category_map = {
            3002: 3,  # Identity & Access Management
            1007: 1,  # System Activity
            3006: 3,  # Identity & Access Management
            4001: 4   # Network Activity
        }
        return category_map.get(class_uid, 0)
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> int:
        """
        Parse Windows timestamp to Unix epoch milliseconds.
        
        Args:
            timestamp_str: ISO format timestamp string
            
        Returns:
            Unix epoch time in milliseconds
        """
        if not timestamp_str:
            return int(datetime.utcnow().timestamp() * 1000)
        
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return int(dt.timestamp() * 1000)
        except Exception as e:
            logger.warning(f"Failed to parse timestamp {timestamp_str}: {str(e)}")
            return int(datetime.utcnow().timestamp() * 1000)


if __name__ == "__main__":
    logger.info("OCSF Mapper module loaded successfully")
