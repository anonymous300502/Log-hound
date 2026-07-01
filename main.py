"""
SentinelGraph Main Orchestrator
Coordinates the complete ETL pipeline: Ingest -> Normalize -> Detect -> Visualize
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional
import json

from ingestor import LogIngestor
from mapper import OCSFMapper
from engine import BehavioralEngine
from visualizer import GraphVisualizer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sentinelgraph.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class SentinelGraph:
    """
    Main orchestrator for the SentinelGraph threat hunting framework.
    Manages the complete ETL pipeline from ingestion to visualization.
    """
    
    def __init__(self, 
                 mappings_path: str = 'config/mappings.yaml',
                 rules_path: str = 'config/rules.yaml',
                 neo4j_uri: str = 'bolt://localhost:7687',
                 neo4j_user: str = 'neo4j',
                 neo4j_password: str = 'password',
                 chunk_size: int = 1000):
        """
        Initialize SentinelGraph.
        
        Args:
            mappings_path: Path to OCSF mappings YAML
            rules_path: Path to detection rules YAML
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            chunk_size: Number of rows to process per chunk
        """
        self.mappings_path = mappings_path
        self.rules_path = rules_path
        self.chunk_size = chunk_size
        
        # Initialize components
        logger.info("Initializing SentinelGraph components...")
        
        self.ingestor = LogIngestor(chunk_size=chunk_size)
        self.mapper = OCSFMapper(mappings_path=mappings_path)
        self.engine = BehavioralEngine(rules_path=rules_path)
        self.visualizer = GraphVisualizer(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
        
        # Statistics
        self.stats = {
            'raw_events': 0,
            'mapped_events': 0,
            'skipped_events': 0,
            'alerts_generated': 0
        }
        
        logger.info("SentinelGraph initialized successfully")
    
    def run(self, csv_path: str, sync_to_graph: bool = True, export_alerts: Optional[str] = None):
        """
        Run the complete threat hunting pipeline.
        
        Args:
            csv_path: Path to CSV file containing raw event logs
            sync_to_graph: Whether to sync events and alerts to Neo4j
            export_alerts: Optional path to export alerts JSON file
        """
        logger.info("=" * 80)
        logger.info("Starting SentinelGraph Pipeline")
        logger.info("=" * 80)
        logger.info(f"Input CSV: {csv_path}")
        logger.info(f"Mappings: {self.mappings_path}")
        logger.info(f"Rules: {self.rules_path}")
        logger.info(f"Graph Sync: {sync_to_graph}")
        logger.info("=" * 80)
        
        # Connect to Neo4j if syncing
        if sync_to_graph:
            try:
                self.visualizer.connect()
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {str(e)}")
                logger.warning("Continuing without graph synchronization")
                sync_to_graph = False
        
        try:
            # Stage 1: Ingestion
            logger.info("\n[Stage 1/4] INGESTION - Reading raw CSV logs")
            logger.info("-" * 80)
            
            for raw_event in self.ingestor.ingest(csv_path):
                self.stats['raw_events'] += 1
                
                # Stage 2: Normalization
                ocsf_event = self.mapper.map_event(raw_event)
                
                if ocsf_event:
                    self.stats['mapped_events'] += 1
                    
                    # Stage 3: Behavioral Detection
                    alerts = self.engine.process_event(ocsf_event)
                    
                    if alerts:
                        self.stats['alerts_generated'] += len(alerts)
                        
                        # Sync alerts to graph
                        if sync_to_graph:
                            for alert in alerts:
                                self.visualizer.sync_alert(alert.to_dict())
                    
                    # Stage 4: Graph Synchronization
                    if sync_to_graph:
                        self.visualizer.sync_event(ocsf_event)
                else:
                    self.stats['skipped_events'] += 1
                
                # Progress logging
                if self.stats['raw_events'] % 1000 == 0:
                    self._log_progress()
            
            # Final statistics
            self._log_final_stats()
            
            # Export alerts if requested
            if export_alerts:
                self._export_alerts(export_alerts)
            
        except KeyboardInterrupt:
            logger.warning("\nPipeline interrupted by user")
            self._log_final_stats()
        except Exception as e:
            logger.error(f"Pipeline error: {str(e)}", exc_info=True)
            raise
        finally:
            if sync_to_graph:
                self.visualizer.close()
    
    def _log_progress(self):
        """Log current progress."""
        logger.info(f"Progress: {self.stats['raw_events']} raw events | "
                   f"{self.stats['mapped_events']} mapped | "
                   f"{self.stats['alerts_generated']} alerts")
    
    def _log_final_stats(self):
        """Log final pipeline statistics."""
        logger.info("\n" + "=" * 80)
        logger.info("PIPELINE COMPLETE - Final Statistics")
        logger.info("=" * 80)
        logger.info(f"Raw Events Processed:    {self.stats['raw_events']}")
        logger.info(f"Events Mapped to OCSF:   {self.stats['mapped_events']}")
        logger.info(f"Events Skipped:          {self.stats['skipped_events']}")
        logger.info(f"Alerts Generated:        {self.stats['alerts_generated']}")
        logger.info("-" * 80)
        logger.info("Ingestor Stats:")
        logger.info(f"  Total Processed: {self.ingestor.total_processed}")
        logger.info("-" * 80)
        logger.info("Engine Stats:")
        engine_stats = self.engine.get_stats()
        for key, value in engine_stats.items():
            logger.info(f"  {key}: {value}")
        logger.info("-" * 80)
        logger.info("Visualizer Stats:")
        viz_stats = self.visualizer.get_stats()
        for key, value in viz_stats.items():
            logger.info(f"  {key}: {value}")
        logger.info("=" * 80)
    
    def _export_alerts(self, export_path: str):
        """Export alerts to JSON file."""
        try:
            alerts = self.engine.get_alerts()
            with open(export_path, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
            logger.info(f"Exported {len(alerts)} alerts to {export_path}")
        except Exception as e:
            logger.error(f"Failed to export alerts: {str(e)}")
    
    def query_blast_radius(self, entity_type: str, entity_value: str):
        """
        Query blast radius for a compromised entity.
        
        Args:
            entity_type: Type of entity ('user', 'host', 'ip')
            entity_value: Entity value to search for
        """
        logger.info(f"Querying blast radius for {entity_type}: {entity_value}")
        
        try:
            self.visualizer.connect()
            results = self.visualizer.query_blast_radius(entity_type, entity_value)
            
            logger.info(f"Found {len(results)} connected entities:")
            for result in results:
                logger.info(f"  {result['type']}: {result['properties']}")
            
            return results
            
        except Exception as e:
            logger.error(f"Blast radius query failed: {str(e)}")
            raise
        finally:
            self.visualizer.close()


def main():
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description='SentinelGraph - Offline Windows Threat Hunting Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full pipeline with graph sync
  python main.py --csv logs.csv
  
  # Run without graph sync, export alerts
  python main.py --csv logs.csv --no-graph --export-alerts alerts.json
  
  # Query blast radius
  python main.py --blast-radius user Administrator
  
  # Custom Neo4j connection
  python main.py --csv logs.csv --neo4j-uri bolt://10.0.0.5:7687 --neo4j-user neo4j --neo4j-password mypass
        """
    )
    
    # Pipeline arguments
    parser.add_argument('--csv', type=str, help='Path to CSV file with raw event logs')
    parser.add_argument('--mappings', type=str, default='config/mappings.yaml',
                       help='Path to OCSF mappings YAML (default: config/mappings.yaml)')
    parser.add_argument('--rules', type=str, default='config/rules.yaml',
                       help='Path to detection rules YAML (default: config/rules.yaml)')
    parser.add_argument('--chunk-size', type=int, default=1000,
                       help='Number of rows to process per chunk (default: 1000)')
    parser.add_argument('--no-graph', action='store_true',
                       help='Disable graph synchronization')
    parser.add_argument('--export-alerts', type=str,
                       help='Export alerts to JSON file')
    
    # Neo4j arguments
    parser.add_argument('--neo4j-uri', type=str, default='bolt://localhost:7687',
                       help='Neo4j URI (default: bolt://localhost:7687)')
    parser.add_argument('--neo4j-user', type=str, default='neo4j',
                       help='Neo4j username (default: neo4j)')
    parser.add_argument('--neo4j-password', type=str, default='password',
                       help='Neo4j password (default: password)')
    
    # Query arguments
    parser.add_argument('--blast-radius', nargs=2, metavar=('TYPE', 'VALUE'),
                       help='Query blast radius: TYPE (user/host/ip) VALUE')
    
    args = parser.parse_args()
    
    # Create config directory if it doesn't exist
    Path('config').mkdir(exist_ok=True)
    
    # Initialize SentinelGraph
    sg = SentinelGraph(
        mappings_path=args.mappings,
        rules_path=args.rules,
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        chunk_size=args.chunk_size
    )
    
    # Run blast radius query
    if args.blast_radius:
        entity_type, entity_value = args.blast_radius
        sg.query_blast_radius(entity_type, entity_value)
        return
    
    # Run pipeline
    if args.csv:
        sg.run(
            csv_path=args.csv,
            sync_to_graph=not args.no_graph,
            export_alerts=args.export_alerts
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
