"""
SentinelGraph Neo4j Visualizer
Creates and maintains a graph database for threat hunting and blast radius analysis.
"""

from neo4j import GraphDatabase
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class GraphVisualizer:
    """
    Neo4j graph database interface for SentinelGraph.
    Creates nodes and relationships for security events and alerts.
    """
    
    def __init__(self, uri: str = "bolt://localhost:7687", 
                 user: str = "neo4j", 
                 password: str = "password"):
        """
        Initialize Neo4j connection.
        
        Args:
            uri: Neo4j bolt URI
            user: Database username
            password: Database password
        """
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        self.stats = {
            'nodes_created': 0,
            'relationships_created': 0,
            'events_synced': 0,
            'alerts_synced': 0
        }
    
    def connect(self):
        """Establish connection to Neo4j database."""
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            logger.info(f"Connected to Neo4j at {self.uri}")
            self._create_indexes()
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {str(e)}")
            raise
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def _create_indexes(self):
        """Create indexes for better query performance."""
        indexes = [
            "CREATE INDEX user_name_idx IF NOT EXISTS FOR (u:User) ON (u.name)",
            "CREATE INDEX host_hostname_idx IF NOT EXISTS FOR (h:Host) ON (h.hostname)",
            "CREATE INDEX ip_address_idx IF NOT EXISTS FOR (i:IP) ON (i.address)",
            "CREATE INDEX process_name_idx IF NOT EXISTS FOR (p:Process) ON (p.name)",
            "CREATE INDEX alert_id_idx IF NOT EXISTS FOR (a:Alert) ON (a.alert_id)",
            "CREATE INDEX event_uid_idx IF NOT EXISTS FOR (e:Event) ON (e.uid)"
        ]
        
        with self.driver.session() as session:
            for index_query in indexes:
                try:
                    session.run(index_query)
                except Exception as e:
                    logger.warning(f"Index creation warning: {str(e)}")
        
        logger.info("Neo4j indexes created/verified")
    
    def sync_event(self, event: Dict[str, Any]):
        """
        Sync an OCSF event to the graph database.
        
        Args:
            event: OCSF-formatted event dictionary
        """
        try:
            with self.driver.session() as session:
                class_uid = event.get('class_uid')
                
                # Route to appropriate handler based on event class
                if class_uid == 3002:  # Authentication
                    self._sync_authentication_event(session, event)
                elif class_uid == 1007:  # Process Activity
                    self._sync_process_event(session, event)
                elif class_uid == 3006:  # Account Change
                    self._sync_account_change_event(session, event)
                elif class_uid == 4001:  # Network Activity
                    self._sync_network_event(session, event)
                else:
                    logger.debug(f"No specific handler for class {class_uid}")
                
                self.stats['events_synced'] += 1
                
        except Exception as e:
            logger.error(f"Error syncing event: {str(e)}")
    
    def _sync_authentication_event(self, session, event: Dict[str, Any]):
        """Sync authentication event to graph."""
        user_name = event.get('user', {}).get('name', 'Unknown')
        src_ip = event.get('src_endpoint', {}).get('ip', 'Unknown')
        host_name = event.get('dst_endpoint', {}).get('hostname', 'Unknown')
        status = event.get('status', 'Unknown')
        auth_protocol = event.get('auth_protocol', 'Unknown')
        timestamp = event.get('time', 0)
        
        # Create User node
        session.run("""
            MERGE (u:User {name: $user_name})
            ON CREATE SET u.created_at = $timestamp
        """, user_name=user_name, timestamp=timestamp)
        
        # Create IP node
        session.run("""
            MERGE (ip:IP {address: $ip_address})
            ON CREATE SET ip.created_at = $timestamp
        """, ip_address=src_ip, timestamp=timestamp)
        
        # Create Host node
        session.run("""
            MERGE (h:Host {hostname: $hostname})
            ON CREATE SET h.created_at = $timestamp
        """, hostname=host_name, timestamp=timestamp)
        
        # Create LOGGED_INTO relationship
        session.run("""
            MATCH (u:User {name: $user_name})
            MATCH (h:Host {hostname: $hostname})
            MATCH (ip:IP {address: $ip_address})
            MERGE (u)-[r:LOGGED_INTO]->(h)
            ON CREATE SET r.first_seen = $timestamp,
                          r.count = 1,
                          r.status = $status,
                          r.auth_protocol = $auth_protocol
            ON MATCH SET r.last_seen = $timestamp,
                         r.count = r.count + 1
            MERGE (ip)-[:ORIGINATED_FROM]->(u)
        """, user_name=user_name, hostname=host_name, ip_address=src_ip,
             timestamp=timestamp, status=status, auth_protocol=auth_protocol)
        
        self.stats['nodes_created'] += 3
        self.stats['relationships_created'] += 2
    
    def _sync_process_event(self, session, event: Dict[str, Any]):
        """Sync process creation event to graph."""
        process_name = event.get('process', {}).get('name', 'Unknown')
        process_cmd = event.get('process', {}).get('cmd_line', '')
        user_name = event.get('user', {}).get('name', 'Unknown')
        host_name = event.get('host', {}).get('hostname', 'Unknown')
        timestamp = event.get('time', 0)
        
        # Create Process node
        session.run("""
            MERGE (p:Process {name: $process_name, cmd_line: $cmd_line})
            ON CREATE SET p.created_at = $timestamp
        """, process_name=process_name, cmd_line=process_cmd, timestamp=timestamp)
        
        # Create User node
        session.run("""
            MERGE (u:User {name: $user_name})
            ON CREATE SET u.created_at = $timestamp
        """, user_name=user_name, timestamp=timestamp)
        
        # Create Host node
        session.run("""
            MERGE (h:Host {hostname: $hostname})
            ON CREATE SET h.created_at = $timestamp
        """, hostname=host_name, timestamp=timestamp)
        
        # Create EXECUTED relationship
        session.run("""
            MATCH (u:User {name: $user_name})
            MATCH (h:Host {hostname: $hostname})
            MATCH (p:Process {name: $process_name, cmd_line: $cmd_line})
            MERGE (u)-[r:EXECUTED]->(p)
            ON CREATE SET r.first_seen = $timestamp, r.count = 1
            ON MATCH SET r.last_seen = $timestamp, r.count = r.count + 1
            MERGE (p)-[:RAN_ON]->(h)
        """, user_name=user_name, hostname=host_name, process_name=process_name,
             cmd_line=process_cmd, timestamp=timestamp)
        
        self.stats['nodes_created'] += 3
        self.stats['relationships_created'] += 2
    
    def _sync_account_change_event(self, session, event: Dict[str, Any]):
        """Sync account change event to graph."""
        actor_user = event.get('user', {}).get('name', 'Unknown')
        target_user = event.get('target_user', {}).get('name', 'Unknown')
        activity_name = event.get('activity_name', 'Unknown')
        timestamp = event.get('time', 0)
        
        # Create User nodes
        session.run("""
            MERGE (actor:User {name: $actor})
            ON CREATE SET actor.created_at = $timestamp
            MERGE (target:User {name: $target})
            ON CREATE SET target.created_at = $timestamp
        """, actor=actor_user, target=target_user, timestamp=timestamp)
        
        # Create MODIFIED relationship
        session.run("""
            MATCH (actor:User {name: $actor})
            MATCH (target:User {name: $target})
            MERGE (actor)-[r:MODIFIED]->(target)
            ON CREATE SET r.first_seen = $timestamp,
                          r.activity = $activity,
                          r.count = 1
            ON MATCH SET r.last_seen = $timestamp,
                         r.count = r.count + 1
        """, actor=actor_user, target=target_user, activity=activity_name, timestamp=timestamp)
        
        self.stats['nodes_created'] += 2
        self.stats['relationships_created'] += 1
    
    def _sync_network_event(self, session, event: Dict[str, Any]):
        """Sync network activity event to graph."""
        user_name = event.get('user', {}).get('name', 'Unknown')
        src_ip = event.get('src_endpoint', {}).get('ip', 'Unknown')
        dst_ip = event.get('dst_endpoint', {}).get('ip', 'Unknown')
        share_name = event.get('share_name', 'Unknown')
        timestamp = event.get('time', 0)
        
        # Create nodes
        session.run("""
            MERGE (u:User {name: $user_name})
            ON CREATE SET u.created_at = $timestamp
            MERGE (src:IP {address: $src_ip})
            ON CREATE SET src.created_at = $timestamp
            MERGE (dst:IP {address: $dst_ip})
            ON CREATE SET dst.created_at = $timestamp
        """, user_name=user_name, src_ip=src_ip, dst_ip=dst_ip, timestamp=timestamp)
        
        # Create ACCESSED_SHARE relationship
        session.run("""
            MATCH (u:User {name: $user_name})
            MATCH (dst:IP {address: $dst_ip})
            MERGE (u)-[r:ACCESSED_SHARE {share: $share}]->(dst)
            ON CREATE SET r.first_seen = $timestamp, r.count = 1
            ON MATCH SET r.last_seen = $timestamp, r.count = r.count + 1
        """, user_name=user_name, dst_ip=dst_ip, share=share_name, timestamp=timestamp)
        
        self.stats['nodes_created'] += 3
        self.stats['relationships_created'] += 1
    
    def sync_alert(self, alert: Dict[str, Any]):
        """
        Sync a detection alert to the graph database.
        
        Args:
            alert: Alert dictionary
        """
        try:
            with self.driver.session() as session:
                alert_id = alert.get('alert_id')
                rule_id = alert.get('rule_id')
                rule_name = alert.get('rule_name')
                severity = alert.get('severity')
                timestamp = alert.get('timestamp')
                event_count = alert.get('event_count')
                
                # Create Alert node
                session.run("""
                    MERGE (a:Alert {alert_id: $alert_id})
                    ON CREATE SET a.rule_id = $rule_id,
                                  a.rule_name = $rule_name,
                                  a.severity = $severity,
                                  a.timestamp = $timestamp,
                                  a.event_count = $event_count,
                                  a.description = $description
                """, alert_id=alert_id, rule_id=rule_id, rule_name=rule_name,
                     severity=severity, timestamp=timestamp, event_count=event_count,
                     description=alert.get('description', ''))
                
                # Link alert to involved entities
                self._link_alert_to_entities(session, alert)
                
                self.stats['alerts_synced'] += 1
                logger.info(f"Alert {alert_id} synced to graph")
                
        except Exception as e:
            logger.error(f"Error syncing alert: {str(e)}")
    
    def _link_alert_to_entities(self, session, alert: Dict[str, Any]):
        """Link alert to users, hosts, and IPs involved."""
        alert_id = alert.get('alert_id')
        events = alert.get('events', [])
        
        # Extract unique entities from all events
        users = set()
        hosts = set()
        ips = set()
        processes = set()
        
        for event in events:
            if 'user' in event and 'name' in event['user']:
                users.add(event['user']['name'])
            
            if 'host' in event and 'hostname' in event['host']:
                hosts.add(event['host']['hostname'])
            elif 'dst_endpoint' in event and 'hostname' in event['dst_endpoint']:
                hosts.add(event['dst_endpoint']['hostname'])
            
            if 'src_endpoint' in event and 'ip' in event['src_endpoint']:
                ips.add(event['src_endpoint']['ip'])
            
            if 'process' in event and 'name' in event['process']:
                processes.add(event['process']['name'])
        
        # Create TRIGGERED relationships
        for user in users:
            session.run("""
                MATCH (a:Alert {alert_id: $alert_id})
                MATCH (u:User {name: $user})
                MERGE (u)-[:TRIGGERED]->(a)
            """, alert_id=alert_id, user=user)
        
        for host in hosts:
            session.run("""
                MATCH (a:Alert {alert_id: $alert_id})
                MATCH (h:Host {hostname: $hostname})
                MERGE (h)-[:TRIGGERED]->(a)
            """, alert_id=alert_id, hostname=host)
        
        for ip in ips:
            session.run("""
                MATCH (a:Alert {alert_id: $alert_id})
                MATCH (i:IP {address: $ip})
                MERGE (i)-[:TRIGGERED]->(a)
            """, alert_id=alert_id, ip=ip)
        
        for process in processes:
            session.run("""
                MATCH (a:Alert {alert_id: $alert_id})
                MATCH (p:Process {name: $process})
                MERGE (p)-[:TRIGGERED]->(a)
            """, alert_id=alert_id, process=process)
    
    def query_blast_radius(self, entity_type: str, entity_value: str) -> List[Dict[str, Any]]:
        """
        Query the blast radius for a compromised entity.
        
        Args:
            entity_type: Type of entity ('user', 'host', 'ip')
            entity_value: Value to search for
            
        Returns:
            List of connected entities
        """
        with self.driver.session() as session:
            if entity_type.lower() == 'user':
                result = session.run("""
                    MATCH (u:User {name: $value})-[*1..3]-(connected)
                    RETURN DISTINCT labels(connected) as type, 
                           properties(connected) as props
                    LIMIT 100
                """, value=entity_value)
            elif entity_type.lower() == 'host':
                result = session.run("""
                    MATCH (h:Host {hostname: $value})-[*1..3]-(connected)
                    RETURN DISTINCT labels(connected) as type, 
                           properties(connected) as props
                    LIMIT 100
                """, value=entity_value)
            elif entity_type.lower() == 'ip':
                result = session.run("""
                    MATCH (i:IP {address: $value})-[*1..3]-(connected)
                    RETURN DISTINCT labels(connected) as type, 
                           properties(connected) as props
                    LIMIT 100
                """, value=entity_value)
            else:
                return []
            
            return [{'type': record['type'], 'properties': record['props']} 
                    for record in result]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get visualizer statistics."""
        return self.stats
    
    def clear_database(self):
        """Clear all nodes and relationships (use with caution!)."""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
        logger.warning("Database cleared")


if __name__ == "__main__":
    logger.info("Graph Visualizer module loaded successfully")
