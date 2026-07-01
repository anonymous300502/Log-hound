"""
SentinelGraph Ingestion Layer
Handles raw CSV log ingestion and XML parsing with chunked processing.
"""

import pandas as pd
from lxml import etree
from typing import Iterator, Dict, Any
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class LogIngestor:
    """
    Ingests raw Windows event logs from CSV files.
    Performs chunked reading for memory efficiency and XML flattening.
    """
    
    def __init__(self, chunk_size: int = 1000):
        """
        Initialize the ingestor.
        
        Args:
            chunk_size: Number of rows to process per chunk for memory efficiency
        """
        self.chunk_size = chunk_size
        self.total_processed = 0
    
    def ingest(self, csv_path: str) -> Iterator[Dict[str, Any]]:
        """
        Read CSV file in chunks and yield parsed log entries.
        
        Args:
            csv_path: Path to the CSV file containing raw logs
            
        Yields:
            Dictionary containing parsed log data with System and EventData fields
        """
        logger.info(f"Starting ingestion from {csv_path} with chunk size {self.chunk_size}")
        
        try:
            # Read CSV in chunks for memory efficiency
            for chunk_num, chunk in enumerate(pd.read_csv(csv_path, chunksize=self.chunk_size)):
                logger.info(f"Processing chunk {chunk_num + 1} ({len(chunk)} records)")
                
                for idx, row in chunk.iterrows():
                    try:
                        parsed_event = self._parse_event_xml(row)
                        if parsed_event:
                            self.total_processed += 1
                            yield parsed_event
                    except Exception as e:
                        logger.error(f"Failed to parse row {idx}: {str(e)}")
                        continue
                        
        except FileNotFoundError:
            logger.error(f"CSV file not found: {csv_path}")
            raise
        except Exception as e:
            logger.error(f"Error during ingestion: {str(e)}")
            raise
        
        logger.info(f"Ingestion complete. Total processed: {self.total_processed}")
    
    def _parse_event_xml(self, row: pd.Series) -> Dict[str, Any]:
        """
        Parse XML event data from a CSV row.
        
        Args:
            row: Pandas Series containing the CSV row data
            
        Returns:
            Flattened dictionary with System and EventData fields
        """
        # Handle different possible column names
        xml_column = None
        for col in ['EventXML', 'Event', 'RawXML', 'XML']:
            if col in row.index and pd.notna(row[col]):
                xml_column = col
                break
        
        if not xml_column:
            logger.warning("No XML column found in row")
            return None
        
        xml_data = str(row[xml_column])
        
        try:
            # Parse XML
            root = etree.fromstring(xml_data.encode('utf-8'))
            
            # Extract namespace
            ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Initialize result dictionary
            result = {
                'System': {},
                'EventData': {},
                'raw_xml': xml_data
            }
            
            # Parse System section
            system = root.find('evt:System', ns)
            if system is not None:
                result['System'] = self._flatten_element(system, ns)
            
            # Parse EventData section
            event_data = root.find('evt:EventData', ns)
            if event_data is not None:
                result['EventData'] = self._flatten_event_data(event_data, ns)
            
            # Add any additional metadata from CSV
            for col in row.index:
                if col not in [xml_column] and pd.notna(row[col]):
                    result[col] = row[col]
            
            return result
            
        except etree.XMLSyntaxError as e:
            logger.error(f"XML parsing error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing XML: {str(e)}")
            return None
    
    def _flatten_element(self, element: etree.Element, ns: Dict[str, str]) -> Dict[str, Any]:
        """
        Flatten an XML element into a dictionary.
        
        Args:
            element: lxml Element to flatten
            ns: XML namespace dictionary
            
        Returns:
            Flattened dictionary
        """
        result = {}
        
        for child in element:
            # Remove namespace prefix from tag
            tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
            
            # Get text content or attributes
            if child.text and child.text.strip():
                result[tag] = child.text.strip()
            elif child.attrib:
                # If element has attributes, use them
                for attr_name, attr_value in child.attrib.items():
                    attr_key = f"{tag}_{attr_name}" if attr_name != 'Name' else tag
                    result[attr_key] = attr_value
            
            # Handle nested elements
            if len(child) > 0:
                nested = self._flatten_element(child, ns)
                for key, value in nested.items():
                    result[f"{tag}_{key}"] = value
        
        return result
    
    def _flatten_event_data(self, event_data: etree.Element, ns: Dict[str, str]) -> Dict[str, Any]:
        """
        Flatten EventData section which uses Data elements with Name attributes.
        
        Args:
            event_data: EventData XML element
            ns: XML namespace dictionary
            
        Returns:
            Dictionary with Name:Value pairs
        """
        result = {}
        
        for data_elem in event_data:
            # Handle <Data Name="...">value</Data> format
            if 'Name' in data_elem.attrib:
                name = data_elem.attrib['Name']
                value = data_elem.text.strip() if data_elem.text else ''
                result[name] = value
            # Handle direct child elements
            else:
                tag = data_elem.tag.split('}')[-1] if '}' in data_elem.tag else data_elem.tag
                result[tag] = data_elem.text.strip() if data_elem.text else ''
        
        return result


def test_ingestor():
    """Test function for the ingestor."""
    # Example test with sample CSV
    ingestor = LogIngestor(chunk_size=100)
    
    # This would be called with actual CSV path
    # for event in ingestor.ingest('logs.csv'):
    #     print(event)
    
    logger.info("Ingestor module loaded successfully")


if __name__ == "__main__":
    test_ingestor()
