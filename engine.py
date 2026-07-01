"""
SentinelGraph Behavioral Detection Engine
Implements stateful correlation and detection using sliding time windows.
"""

import yaml
import logging
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Alert:
    """Represents a detection alert."""
    
    def __init__(self, rule_id: str, rule_name: str, severity: str, 
                 description: str, events: List[Dict[str, Any]], metadata: Dict[str, Any]):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.description = description
        self.events = events
        self.metadata = metadata
        self.timestamp = datetime.utcnow()
        self.alert_id = f"{rule_id}_{int(self.timestamp.timestamp() * 1000)}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for storage."""
        return {
            'alert_id': self.alert_id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'event_count': len(self.events),
            'events': self.events,
            'metadata': self.metadata
        }


class BehavioralEngine:
    """
    Stateful detection engine supporting multiple detection patterns.
    Maintains sliding windows for temporal correlation.
    """
    
    def __init__(self, rules_path: str):
        """
        Initialize the behavioral engine.
        
        Args:
            rules_path: Path to YAML rules configuration
        """
        self.rules_path = rules_path
        self.detection_rules = []
        self.event_buffer = defaultdict(lambda: deque(maxlen=10000))  # Sliding window per rule
        self.alerts = []
        self.stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'rules_loaded': 0
        }
        self.load_rules()
    
    def load_rules(self):
        """Load detection rules from YAML configuration."""
        try:
            with open(self.rules_path, 'r') as f:
                config = yaml.safe_load(f)
                self.detection_rules = config.get('detection_rules', [])
            
            self.stats['rules_loaded'] = len(self.detection_rules)
            logger.info(f"Loaded {len(self.detection_rules)} detection rules from {self.rules_path}")
            
            # Validate rules
            for rule in self.detection_rules:
                self._validate_rule(rule)
                
        except FileNotFoundError:
            logger.error(f"Rules file not found: {self.rules_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML: {str(e)}")
            raise
    
    def _validate_rule(self, rule: Dict[str, Any]):
        """Validate rule structure."""
        required_fields = ['id', 'name', 'type']
        for field in required_fields:
            if field not in rule:
                raise ValueError(f"Rule missing required field: {field}")
        
        rule_type = rule['type']
        if rule_type not in ['atomic', 'threshold', 'chain']:
            raise ValueError(f"Invalid rule type: {rule_type}")
    
    def process_event(self, event: Dict[str, Any]) -> List[Alert]:
        """
        Process a single OCSF event through all detection rules.
        
        Args:
            event: OCSF-formatted event
            
        Returns:
            List of triggered alerts
        """
        self.stats['events_processed'] += 1
        triggered_alerts = []
        
        for rule in self.detection_rules:
            rule_id = rule['id']
            rule_type = rule['type']
            
            try:
                # Apply detection logic based on rule type
                if rule_type == 'atomic':
                    alert = self._check_atomic(event, rule)
                elif rule_type == 'threshold':
                    alert = self._check_threshold(event, rule)
                elif rule_type == 'chain':
                    alert = self._check_chain(event, rule)
                else:
                    continue
                
                if alert:
                    triggered_alerts.append(alert)
                    self.alerts.append(alert)
                    self.stats['alerts_generated'] += 1
                    logger.warning(f"ALERT: {alert.rule_name} ({alert.alert_id})")
                    
            except Exception as e:
                logger.error(f"Error processing rule {rule_id}: {str(e)}")
                continue
        
        return triggered_alerts
    
    def _check_atomic(self, event: Dict[str, Any], rule: Dict[str, Any]) -> Optional[Alert]:
        """
        Check atomic (single-event) detection rule.
        
        Args:
            event: OCSF event
            rule: Detection rule configuration
            
        Returns:
            Alert if rule matches, None otherwise
        """
        # Check class match
        if 'class' in rule and event.get('class_uid') != rule['class']:
            return None
        
        # Check filter conditions
        if 'filter' in rule:
            if not self._evaluate_filter(event, rule['filter']):
                return None
        
        # Rule matched - create alert
        return Alert(
            rule_id=rule['id'],
            rule_name=rule['name'],
            severity=rule.get('severity', 'medium'),
            description=rule.get('description', f"Atomic rule {rule['name']} triggered"),
            events=[event],
            metadata={
                'rule_type': 'atomic',
                'matched_fields': self._extract_matched_fields(event, rule)
            }
        )
    
    def _check_threshold(self, event: Dict[str, Any], rule: Dict[str, Any]) -> Optional[Alert]:
        """
        Check threshold-based detection rule (aggregation over time).
        
        Args:
            event: OCSF event
            rule: Detection rule configuration
            
        Returns:
            Alert if threshold exceeded, None otherwise
        """
        # Check class match
        if 'class' in rule and event.get('class_uid') != rule['class']:
            return None
        
        # Check filter conditions
        if 'filter' in rule:
            if not self._evaluate_filter(event, rule['filter']):
                return None
        
        # Add event to buffer
        rule_id = rule['id']
        window_seconds = rule.get('window', 300)
        threshold = rule.get('threshold', 10)
        group_by = rule.get('group_by', None)
        
        # Get grouping key
        group_key = self._get_group_key(event, group_by) if group_by else 'default'
        buffer_key = f"{rule_id}_{group_key}"
        
        # Add event with timestamp
        event_time = datetime.fromtimestamp(event.get('time', 0) / 1000)
        self.event_buffer[buffer_key].append({
            'event': event,
            'timestamp': event_time
        })
        
        # Clean old events outside window
        cutoff_time = event_time - timedelta(seconds=window_seconds)
        while self.event_buffer[buffer_key] and \
              self.event_buffer[buffer_key][0]['timestamp'] < cutoff_time:
            self.event_buffer[buffer_key].popleft()
        
        # Check if threshold exceeded
        event_count = len(self.event_buffer[buffer_key])
        
        if event_count >= threshold:
            # Extract all events in window
            matching_events = [item['event'] for item in self.event_buffer[buffer_key]]
            
            # Create alert
            alert = Alert(
                rule_id=rule['id'],
                rule_name=rule['name'],
                severity=rule.get('severity', 'high'),
                description=f"Threshold exceeded: {event_count} events in {window_seconds}s window",
                events=matching_events,
                metadata={
                    'rule_type': 'threshold',
                    'threshold': threshold,
                    'actual_count': event_count,
                    'window_seconds': window_seconds,
                    'group_key': group_key
                }
            )
            
            # Clear buffer to avoid duplicate alerts
            self.event_buffer[buffer_key].clear()
            
            return alert
        
        return None
    
    def _check_chain(self, event: Dict[str, Any], rule: Dict[str, Any]) -> Optional[Alert]:
        """
        Check chained (multi-step correlation) detection rule.
        
        Args:
            event: OCSF event
            rule: Detection rule configuration
            
        Returns:
            Alert if chain completes, None otherwise
        """
        rule_id = rule['id']
        window_seconds = rule.get('window', 60)
        match_on = rule.get('match_on', 'host.hostname')
        
        # Get steps
        step_1 = rule.get('step_1', {})
        step_2 = rule.get('step_2', {})
        
        # Check if current event matches step 2
        if self._matches_step(event, step_2):
            # Look for step 1 in buffer
            event_time = datetime.fromtimestamp(event.get('time', 0) / 1000)
            cutoff_time = event_time - timedelta(seconds=window_seconds)
            
            # Get correlation key
            correlation_value = self._get_nested_value(event, match_on)
            if not correlation_value:
                return None
            
            buffer_key = f"{rule_id}_step1"
            
            # Search for matching step 1 events
            matching_step1_events = []
            if buffer_key in self.event_buffer:
                for item in self.event_buffer[buffer_key]:
                    if item['timestamp'] >= cutoff_time:
                        step1_event = item['event']
                        step1_value = self._get_nested_value(step1_event, match_on)
                        if step1_value == correlation_value:
                            matching_step1_events.append(step1_event)
            
            # If we found matching step 1, create alert
            if matching_step1_events:
                return Alert(
                    rule_id=rule['id'],
                    rule_name=rule['name'],
                    severity=rule.get('severity', 'critical'),
                    description=f"Chained behavior detected: {rule['name']}",
                    events=matching_step1_events + [event],
                    metadata={
                        'rule_type': 'chain',
                        'correlation_field': match_on,
                        'correlation_value': correlation_value,
                        'window_seconds': window_seconds
                    }
                )
        
        # Check if current event matches step 1 - add to buffer
        elif self._matches_step(event, step_1):
            buffer_key = f"{rule_id}_step1"
            event_time = datetime.fromtimestamp(event.get('time', 0) / 1000)
            
            self.event_buffer[buffer_key].append({
                'event': event,
                'timestamp': event_time
            })
            
            # Clean old events
            cutoff_time = event_time - timedelta(seconds=window_seconds)
            while self.event_buffer[buffer_key] and \
                  self.event_buffer[buffer_key][0]['timestamp'] < cutoff_time:
                self.event_buffer[buffer_key].popleft()
        
        return None
    
    def _matches_step(self, event: Dict[str, Any], step: Dict[str, Any]) -> bool:
        """Check if event matches a chain step definition."""
        # Check class
        if 'class' in step and event.get('class_uid') != step['class']:
            return False
        
        # Check filter
        if 'filter' in step:
            return self._evaluate_filter(event, step['filter'])
        
        return True
    
    def _evaluate_filter(self, event: Dict[str, Any], filter_str: str) -> bool:
        """
        Evaluate a filter expression against an event.
        
        Args:
            event: OCSF event
            filter_str: Filter expression (e.g., "status == 'Failure'")
            
        Returns:
            True if filter matches
        """
        try:
            # Parse simple filter expressions
            # Supports: ==, !=, IN, >, <, >=, <=, AND, OR
            
            # Handle AND/OR
            if ' AND ' in filter_str:
                parts = filter_str.split(' AND ')
                return all(self._evaluate_filter(event, part.strip()) for part in parts)
            
            if ' OR ' in filter_str:
                parts = filter_str.split(' OR ')
                return any(self._evaluate_filter(event, part.strip()) for part in parts)
            
            # Handle IN operator
            if ' IN ' in filter_str:
                parts = filter_str.split(' IN ')
                field_path = parts[0].strip()
                value_list_str = parts[1].strip().strip('[]')
                value_list = [v.strip().strip("'\"") for v in value_list_str.split(',')]
                
                field_value = self._get_nested_value(event, field_path)
                return str(field_value) in value_list
            
            # Handle comparison operators
            for op in ['==', '!=', '>=', '<=', '>', '<']:
                if op in filter_str:
                    parts = filter_str.split(op)
                    if len(parts) == 2:
                        field_path = parts[0].strip()
                        expected_value = parts[1].strip().strip("'\"")
                        
                        field_value = str(self._get_nested_value(event, field_path) or '')
                        
                        if op == '==':
                            return field_value == expected_value
                        elif op == '!=':
                            return field_value != expected_value
                        elif op == '>':
                            try:
                                return float(field_value) > float(expected_value)
                            except ValueError:
                                return False
                        elif op == '<':
                            try:
                                return float(field_value) < float(expected_value)
                            except ValueError:
                                return False
                        elif op == '>=':
                            try:
                                return float(field_value) >= float(expected_value)
                            except ValueError:
                                return False
                        elif op == '<=':
                            try:
                                return float(field_value) <= float(expected_value)
                            except ValueError:
                                return False
            
            return False
            
        except Exception as e:
            logger.warning(f"Error evaluating filter '{filter_str}': {str(e)}")
            return False
    
    def _get_nested_value(self, obj: Dict[str, Any], path: str) -> Any:
        """Get nested dictionary value using dot notation."""
        keys = path.split('.')
        current = obj
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    def _get_group_key(self, event: Dict[str, Any], group_by: str) -> str:
        """Extract grouping key from event."""
        value = self._get_nested_value(event, group_by)
        return str(value) if value else 'unknown'
    
    def _extract_matched_fields(self, event: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant fields from matched event."""
        fields = {}
        
        # Extract common fields
        fields['class_uid'] = event.get('class_uid')
        fields['time'] = event.get('time')
        
        if 'user' in event:
            fields['user'] = event['user']
        if 'host' in event:
            fields['host'] = event['host']
        if 'process' in event:
            fields['process'] = event['process']
        
        return fields
    
    def get_alerts(self) -> List[Dict[str, Any]]:
        """Get all alerts as dictionaries."""
        return [alert.to_dict() for alert in self.alerts]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return self.stats


if __name__ == "__main__":
    logger.info("Behavioral Engine module loaded successfully")
