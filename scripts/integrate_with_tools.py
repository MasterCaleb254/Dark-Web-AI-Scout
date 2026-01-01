#!/usr/bin/env python3
"""
Integration scripts for connecting with other research tools.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import asyncio

from src.utils.logger import setup_logger, get_logger
from src.utils.config import load_config
from src.storage.database import create_database
from src.integration.api import export_graphml

logger = get_logger(__name__)


class ToolIntegrator:
    """Integrates with various cybersecurity tools."""
    
    def __init__(self, config_path: str = 'configs/default.yaml'):
        """Initialize integrator.
        
        Args:
            config_path: Configuration file path
        """
        self.config = load_config(config_path)
    
    async def export_to_maltego(self, output_file: str, query: Optional[Dict[str, Any]] = None):
        """Export data for Maltego.
        
        Args:
            output_file: Output file path
            query: Query to filter sites
        """
        db = await create_database(self.config.database)
        
        try:
            async with db.get_session() as session:
                # Build query
                conditions = []
                params = {}
                
                if query:
                    if 'category' in query:
                        conditions.append("category = :category")
                        params['category'] = query['category']
                    
                    if 'risk_level' in query:
                        conditions.append("risk_level = :risk_level")
                        params['risk_level'] = query['risk_level']
                
                where_clause = " AND ".join(conditions) if conditions else "1=1"
                
                sql = f"""
                    SELECT * FROM sites
                    WHERE {where_clause}
                    ORDER BY last_checked DESC
                    LIMIT 1000
                """
                
                result = await session.execute(sql, params)
                sites = [dict(row._mapping) for row in result.fetchall()]
                
                # Export to Maltego CSV format
                output_path = Path(output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                if output_path.suffix == '.csv':
                    self._export_maltego_csv(sites, output_path)
                elif output_path.suffix == '.json':
                    self._export_maltego_json(sites, output_path)
                else:
                    logger.error(f"Unsupported format: {output_path.suffix}")
                
                logger.info(f"Exported {len(sites)} sites to {output_file}")
        
        finally:
            await db.disconnect()
    
    def _export_maltego_csv(self, sites: List[Dict[str, Any]], output_path: Path):
        """Export to Maltego CSV format.
        
        Args:
            sites: Sites to export
            output_path: Output file path
        """
        import csv
        
        # Prepare CSV rows
        rows = []
        for site in sites:
            row = {
                'Type': 'arachne.OnionSite',
                'Value': site['onion_address'],
                'Title': site.get('title', ''),
                'Category': site.get('category', ''),
                'RiskLevel': site.get('risk_level', ''),
                'RiskScore': site.get('risk_score', 0),
                'FirstSeen': site.get('first_seen', ''),
                'LastChecked': site.get('last_checked', ''),
            }
            rows.append(row)
        
        if rows:
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
    
    def _export_maltego_json(self, sites: List[Dict[str, Any]], output_path: Path):
        """Export to Maltego JSON format.
        
        Args:
            sites: Sites to export
            output_path: Output file path
        """
        import json
        
        # Convert to Maltego entity format
        entities = []
        for site in sites:
            entity = {
                'Type': 'arachne.OnionSite',
                'Value': site['onion_address'],
                'Weight': int(site.get('risk_score', 0) * 100),
                'AdditionalFields': {
                    'title': site.get('title', ''),
                    'category': site.get('category', ''),
                    'risk_level': site.get('risk_level', ''),
                    'first_seen': site.get('first_seen', ''),
                    'last_checked': site.get('last_checked', ''),
                }
            }
            entities.append(entity)
        
        with open(output_path, 'w') as f:
            json.dump({'Entities': entities}, f, indent=2)
    
    async def export_to_elasticsearch(self, index_name: str = 'arachne-sites'):
        """Export data to Elasticsearch.
        
        Args:
            index_name: Elasticsearch index name
        """
        from elasticsearch import AsyncElasticsearch
        
        db = await create_database(self.config.database)
        
        try:
            # Connect to Elasticsearch
            es_config = self.config.get('elasticsearch', {})
            hosts = es_config.get('hosts', ['localhost:9200'])
            
            es = AsyncElasticsearch(hosts=hosts)
            
            # Check connection
            if not await es.ping():
                logger.error("Cannot connect to Elasticsearch")
                return
            
            async with db.get_session() as session:
                # Get all sites
                result = await session.execute(
                    "SELECT * FROM sites ORDER BY last_checked DESC LIMIT 10000"
                )
                
                sites = [dict(row._mapping) for row in result.fetchall()]
                
                # Index each site
                for i, site in enumerate(sites):
                    try:
                        # Prepare document
                        doc = {
                            'onion_address': site['onion_address'],
                            'title': site.get('title'),
                            'description': site.get('description'),
                            'category': site.get('category'),
                            'risk_level': site.get('risk_level'),
                            'risk_score': site.get('risk_score'),
                            'status': site.get('status'),
                            'first_seen': site.get('first_seen'),
                            'last_checked': site.get('last_checked'),
                            'metadata': site.get('metadata', {}),
                            'timestamp': site.get('last_checked') or site.get('first_seen'),
                        }
                        
                        # Index in Elasticsearch
                        await es.index(
                            index=index_name,
                            id=site['id'],
                            document=doc
                        )
                        
                        if (i + 1) % 100 == 0:
                            logger.info(f"Indexed {i + 1} sites")
                    
                    except Exception as e:
                        logger.error(f"Failed to index site {site['id']}: {e}")
                
                logger.info(f"Completed indexing {len(sites)} sites to Elasticsearch")
        
        finally:
            await db.disconnect()
            if 'es' in locals():
                await es.close()
    
    async def generate_network_graph(self, output_file: str, max_sites: int = 500):
        """Generate network graph for visualization.
        
        Args:
            output_file: Output file path
            max_sites: Maximum sites to include
        """
        db = await create_database(self.config.database)
        
        try:
            async with db.get_session() as session:
                # Get sites with their discovered links
                result = await session.execute("""
                    SELECT s1.onion_address as source, s2.onion_address as target
                    FROM discovery_results dr1
                    JOIN sites s1 ON dr1.site_id = s1.id
                    JOIN discovery_results dr2 ON dr2.source_url LIKE '%' || s1.onion_address || '%'
                    JOIN sites s2 ON dr2.site_id = s2.id
                    WHERE s1.onion_address != s2.onion_address
                    LIMIT :limit
                """, {'limit': max_sites * 10})
                
                links = result.fetchall()
                
                # Get unique sites
                sites = set()
                for link in links:
                    sites.add(link[0])
                    sites.add(link[1])
                
                # Get site details
                sites_list = list(sites)[:max_sites]
                site_details = {}
                
                for site_addr in sites_list:
                    result = await session.execute(
                        "SELECT * FROM sites WHERE onion_address = :address",
                        {'address': site_addr}
                    )
                    row = result.fetchone()
                    if row:
                        site_details[site_addr] = dict(row._mapping)
                
                # Create network data
                network_data = {
                    'nodes': [
                        {
                            'id': addr,
                            'label': details.get('title', addr[:16]),
                            'group': details.get('category', 'unknown'),
                            'value': details.get('risk_score', 0.5) * 10,
                        }
                        for addr, details in site_details.items()
                    ],
                    'edges': [
                        {
                            'from': link[0],
                            'to': link[1],
                            'value': 1,
                        }
                        for link in links if link[0] in site_details and link[1] in site_details
                    ][:1000]  # Limit edges
                }
                
                # Export based on format
                output_path = Path(output_file)
                
                if output_path.suffix == '.json':
                    with open(output_path, 'w') as f:
                        json.dump(network_data, f, indent=2)
                
                elif output_path.suffix == '.graphml':
                    # Convert to GraphML
                    graphml_data = export_graphml([
                        {'id': node['id'], 'category': node['group']}
                        for node in network_data['nodes']
                    ])
                    
                    with open(output_path, 'w') as f:
                        f.write(graphml_data)
                
                elif output_path.suffix == '.html':
                    # Generate interactive HTML visualization
                    self._generate_network_html(network_data, output_path)
                
                else:
                    logger.error(f"Unsupported format: {output_path.suffix}")
                
                logger.info(f"Generated network graph with {len(network_data['nodes'])} nodes and {len(network_data['edges'])} edges")
        
        finally:
            await db.disconnect()
    
    def _generate_network_html(self, network_data: Dict[str, Any], output_path: Path):
        """Generate interactive HTML network visualization.
        
        Args:
            network_data: Network data
            output_path: Output file path
        """
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Arachne Network Visualization</title>
            <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
            <style>
                body { margin: 0; padding: 0; font-family: Arial, sans-serif; }
                #network { width: 100vw; height: 100vh; }
                #info { position: absolute; top: 10px; left: 10px; background: white; padding: 10px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
            </style>
        </head>
        <body>
            <div id="info">
                <h3>Dark Web Network</h3>
                <p>Nodes: <span id="node-count">0</span></p>
                <p>Edges: <span id="edge-count">0</span></p>
                <p>Click a node for details</p>
            </div>
            <div id="network"></div>
            
            <script>
                // Network data
                const nodes = new vis.DataSet(%(nodes)s);
                const edges = new vis.DataSet(%(edges)s);
                
                // Update counters
                document.getElementById('node-count').textContent = nodes.length;
                document.getElementById('edge-count').textContent = edges.length;
                
                // Create network
                const container = document.getElementById('network');
                const data = { nodes, edges };
                const options = {
                    nodes: {
                        shape: 'dot',
                        size: 16,
                        font: { size: 12 },
                        borderWidth: 2,
                    },
                    edges: {
                        width: 1,
                        color: { inherit: 'from' },
                        smooth: { type: 'continuous' },
                    },
                    physics: {
                        stabilization: true,
                        barnesHut: {
                            gravitationalConstant: -8000,
                            springConstant: 0.04,
                            springLength: 95,
                        },
                    },
                    interaction: {
                        hover: true,
                        tooltipDelay: 200,
                    },
                };
                
                const network = new vis.Network(container, data, options);
                
                // Handle node clicks
                network.on('click', function(params) {
                    if (params.nodes.length > 0) {
                        const nodeId = params.nodes[0];
                        const node = nodes.get(nodeId);
                        
                        alert(
                            'Node Details:\\n' +
                            'Address: ' + node.id + '\\n' +
                            'Category: ' + node.group + '\\n' +
                            'Label: ' + node.label
                        );
                    }
                });
            </script>
        </body>
        </html>
        """
        
        html_content = html_template % {
            'nodes': json.dumps(network_data['nodes']),
            'edges': json.dumps(network_data['edges']),
        }
        
        with open(output_path, 'w') as f:
            f.write(html_content)


async def main():
    """Main integration function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Integrate with research tools")
    parser.add_argument('--tool', required=True, 
                       choices=['maltego', 'elasticsearch', 'network', 'all'],
                       help='Tool to integrate with')
    parser.add_argument('--output', help='Output file or index name')
    parser.add_argument('--query', help='JSON query for filtering')
    parser.add_argument('--config', default='configs/default.yaml', help='Config file')
    
    args = parser.parse_args()
    
    setup_logger(level="INFO")
    
    integrator = ToolIntegrator(args.config)
    
    # Parse query if provided
    query = None
    if args.query:
        try:
            query = json.loads(args.query)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid query JSON: {e}")
            sys.exit(1)
    
    # Default output files
    if not args.output:
        if args.tool == 'maltego':
            args.output = 'exports/maltego_export.csv'
        elif args.tool == 'network':
            args.output = 'exports/network.html'
    
    try:
        if args.tool == 'maltego':
            await integrator.export_to_maltego(args.output, query)
        
        elif args.tool == 'elasticsearch':
            index_name = args.output or 'arachne-sites'
            await integrator.export_to_elasticsearch(index_name)
        
        elif args.tool == 'network':
            await integrator.generate_network_graph(args.output)
        
        elif args.tool == 'all':
            # Run all integrations
            await integrator.export_to_maltego('exports/maltego_export.csv', query)
            await integrator.export_to_elasticsearch('arachne-sites')
            await integrator.generate_network_graph('exports/network.html')
        
        logger.info(f"Integration with {args.tool} completed successfully")
    
    except Exception as e:
        logger.error(f"Integration failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())