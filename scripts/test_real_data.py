#!/usr/bin/env python3
"""
Test with real dark web data (requires legal permission and proper environment).
WARNING: For authorized research use only.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import List, Dict, Any
import hashlib

from src.utils.logger import setup_logger, get_logger
from src.utils.config import load_config
from src.classification.pipeline import ClassificationPipeline
from src.classification.storage import ClassificationStorage
from src.storage.database import create_database

logger = get_logger(__name__)


class RealDataTester:
    """Test framework for real dark web data."""
    
    def __init__(self, config_path: str = 'configs/default.yaml'):
        """Initialize tester.
        
        WARNING: Only use with legally obtained data.
        """
        self.config = load_config(config_path)
        self.pipeline = ClassificationPipeline()
        
        # Safety reminder
        logger.warning("=" * 70)
        logger.warning("REAL DATA TESTING - LEGAL COMPLIANCE REQUIRED")
        logger.warning("=" * 70)
        logger.warning("Ensure you have:")
        logger.warning("1. Legal authorization for this research")
        logger.warning("2. Proper data handling procedures")
        logger.warning("3. Institutional review board approval if required")
        logger.warning("4. Air-gapped environment for sensitive data")
        logger.warning("=" * 70)
    
    async def test_with_dataset(self, dataset_path: str):
        """Test with a dataset of onion site snapshots.
        
        Args:
            dataset_path: Path to dataset directory
        """
        dataset_path = Path(dataset_path)
        if not dataset_path.exists():
            logger.error(f"Dataset not found: {dataset_path}")
            return
        
        # Find site files
        site_files = list(dataset_path.glob("**/*.html")) + \
                    list(dataset_path.glob("**/*.txt")) + \
                    list(dataset_path.glob("**/*.json"))
        
        logger.info(f"Found {len(site_files)} site files in dataset")
        
        if not site_files:
            logger.error("No site files found")
            return
        
        results = []
        
        # Process each site
        for i, file_path in enumerate(site_files[:100]):  # Limit to 100 for testing
            try:
                # Read content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract URL from filename or metadata
                url = self._extract_url_from_file(file_path, content)
                
                logger.info(f"Processing {i+1}/{len(site_files)}: {url}")
                
                # Run through pipeline
                result = await self.pipeline.process(
                    url=url,
                    content=content,
                    content_type_hint='text/html',
                )
                
                # Store results
                results.append({
                    'file': str(file_path),
                    'url': url,
                    'result': result.to_dict(),
                })
                
                # Print summary
                self._print_result_summary(result)
                
                # Save progress periodically
                if (i + 1) % 10 == 0:
                    self._save_results(results, dataset_path / "results_partial.json")
            
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
                results.append({
                    'file': str(file_path),
                    'error': str(e),
                })
        
        # Save final results
        self._save_results(results, dataset_path / "results_final.json")
        
        # Generate statistics
        self._generate_statistics(results)
    
    def _extract_url_from_file(self, file_path: Path, content: str) -> str:
        """Extract URL from file."""
        # Try to find URL in content
        import re
        
        # Look for onion URLs in content
        onion_pattern = r'http://[a-z2-7]{56}\.onion'
        matches = re.findall(onion_pattern, content)
        if matches:
            return matches[0]
        
        # Look in filename
        filename = file_path.stem
        if filename.endswith('.onion'):
            return f"http://{filename}"
        
        # Generate from hash
        content_hash = hashlib.md5(content.encode()).hexdigest()[:16]
        return f"http://{content_hash}.onion"
    
    def _print_result_summary(self, result):
        """Print summary of classification result."""
        if result.classification_result:
            category = result.classification_result.category.value
            confidence = result.classification_result.confidence
            safety = result.safety_result.action.value
            
            risk = result.risk_score.level.value if result.risk_score else "unknown"
            
            print(f"  → Category: {category} ({confidence:.2f}) | Safety: {safety} | Risk: {risk}")
            
            if result.requires_review:
                print("  ⚠️  REQUIRES HUMAN REVIEW")
        else:
            print(f"  → No classification | Safety: {result.safety_result.action.value}")
    
    def _save_results(self, results: List[Dict[str, Any]], output_path: Path):
        """Save results to JSON file."""
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Results saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def _generate_statistics(self, results: List[Dict[str, Any]]):
        """Generate statistics from results."""
        total = len(results)
        classified = sum(1 for r in results if 'result' in r and r['result']['classification'])
        safe = sum(1 for r in results if 'result' in r and r['result']['safety']['action'] == 'allow')
        
        categories = {}
        for r in results:
            if 'result' in r and r['result']['classification']:
                category = r['result']['classification']['category']
                categories[category] = categories.get(category, 0) + 1
        
        print("\n" + "="*60)
        print("DATASET STATISTICS")
        print("="*60)
        print(f"Total sites: {total}")
        print(f"Successfully classified: {classified} ({classified/total*100:.1f}%)")
        print(f"Safe content: {safe} ({safe/total*100:.1f}%)")
        
        print("\nCategory distribution:")
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"  {category}: {count} ({count/total*100:.1f}%)")
        
        # Save statistics
        stats = {
            'total_sites': total,
            'classified': classified,
            'safe_content': safe,
            'categories': categories,
        }
        
        output_path = Path("test_results") / "statistics.json"
        output_path.parent.mkdir(exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(stats, f, indent=2)
        
        logger.info(f"Statistics saved to {output_path}")
    
    async def test_with_live_sites(self, urls_file: str, limit: int = 10):
        """Test with live onion sites (requires Tor).
        
        Args:
            urls_file: File with onion URLs
            limit: Maximum number of sites to test
        """
        from src.core.tor_manager import create_tor_manager
        
        # Start Tor
        tor_manager = create_tor_manager(self.config.dict())
        tor_manager.start()
        
        try:
            # Read URLs
            with open(urls_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()][:limit]
            
            logger.info(f"Testing {len(urls)} live sites")
            
            # Test each URL
            for i, url in enumerate(urls):
                logger.info(f"Testing {i+1}/{len(urls)}: {url}")
                
                try:
                    # Fetch content
                    with tor_manager.get_http_session() as session:
                        response = session.get(url, timeout=30)
                        
                        if response.status_code == 200:
                            content = response.text
                            
                            # Classify
                            result = await self.pipeline.process(
                                url=url,
                                content=content,
                                content_type_hint='text/html',
                            )
                            
                            self._print_result_summary(result)
                        else:
                            logger.warning(f"  → HTTP {response.status_code}")
                
                except Exception as e:
                    logger.error(f"  → Error: {e}")
        
        finally:
            tor_manager.stop()


async def main():
    """Main testing function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test with real dark web data")
    parser.add_argument('--dataset', help='Path to dataset directory')
    parser.add_argument('--urls', help='File with onion URLs for live testing')
    parser.add_argument('--limit', type=int, default=10, help='Limit for live testing')
    parser.add_argument('--config', default='configs/default.yaml', help='Config file')
    
    args = parser.parse_args()
    
    setup_logger(level="INFO")
    
    tester = RealDataTester(args.config)
    
    if args.dataset:
        await tester.test_with_dataset(args.dataset)
    elif args.urls:
        await tester.test_with_live_sites(args.urls, args.limit)
    else:
        print("Please specify --dataset or --urls")
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())