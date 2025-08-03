"""
API Candidate Filtering Module

This module filters API candidates collected by CodeQL queries to prepare them for 
LLM labeling. It focuses on security-relevant APIs following IRIS methodology.

The filtered candidates are prepared for identifying:
- Sources: Entry points where untrusted data enters the system
- Sinks: Exit points where data flows to sensitive operations  
- Taint-propagators: Methods that pass data between sources and sinks
"""

import asyncio
import argparse
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

import pandas as pd

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
PYSAST_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PYSAST_ROOT / "output"


@dataclass
class APICandidate:
    """Represents an API candidate for security analysis."""
    package: str
    class_name: str
    method: str
    signature: str
    file_path: str = ""
    line_number: str = ""


class SecurityFilter:
    """Filters API candidates based on security relevance."""
    
    def __init__(self):
        """Initialize security filter with predefined patterns."""
        # Security-relevant modules for Python projects
        self.security_modules = {
            'flask', 'django', 'fastapi', 'tornado', 'pyramid', 'bottle',
            'requests', 'urllib', 'httplib', 'http', 'httpx', 'aiohttp',
            'sqlite3', 'pymongo', 'psycopg2', 'mysql', 'sqlalchemy',
            'os', 'sys', 'subprocess', 'pathlib', 'shutil',
            'pickle', 'json', 'yaml', 'xml', 'lxml',
            'jinja2', 'mako', 'template',
            'hashlib', 'hmac', 'base64', 'cryptography', 'jwt', 'ssl',
            'logging', 'logger'
        }
        
        # Data flow methods that participate in security-relevant operations
        self.data_flow_methods = {
            'get', 'put', 'set', 'add', 'remove', 'pop', 'append', 'insert',
            'format', 'replace', 'substitute', 'join', 'split', 'strip',
            'read', 'write', 'open', 'load', 'save', 'dump', 'close',
            'send', 'recv', 'connect', 'request', 'response',
            'execute', 'eval', 'exec', 'system', 'call', 'run',
            'query', 'select', 'insert', 'update', 'delete'
        }
        
        # Methods to always exclude (Python dunder methods and built-ins)
        self.blacklist_methods = {
            '__init__', '__new__', '__del__', '__str__', '__repr__', '__hash__',
            '__len__', '__iter__', '__next__', '__contains__', '__getitem__',
            '__eq__', '__ne__', '__lt__', '__le__', '__gt__', '__ge__',
            '__add__', '__sub__', '__mul__', '__div__', '__mod__', '__bool__',
            '__getattribute__', '__setattr__', '__getattr__', '__delattr__'
        }
        
        # Packages to always exclude
        self.blacklist_packages = {
            '__doc__', '__name__', '__module__', '__class__', '__dict__',
            'object', 'type', 'property', 'staticmethod', 'classmethod'
        }

    def is_security_relevant(self, candidate: APICandidate) -> bool:
        """
        Determine if an API candidate is security-relevant.
        
        Args:
            candidate: The API candidate to evaluate
            
        Returns:
            True if the candidate is security-relevant, False otherwise
        """
        pkg = candidate.package.lower()
        method = candidate.method.lower()
        
        # Apply blacklist first
        if method in self.blacklist_methods or pkg in self.blacklist_packages:
            return False
        
        # Check for security-relevant modules
        if any(module in pkg for module in self.security_modules):
            return True
        
        # Check for data flow methods
        if method in self.data_flow_methods:
            return True
        
        # Check signature for security patterns
        signature = candidate.signature.lower()
        security_patterns = [
            'request', 'response', 'param', 'query', 'header', 'cookie',
            'auth', 'login', 'password', 'token', 'encrypt', 'decrypt',
            'file', 'path', 'url', 'uri', 'sql', 'db', 'exec', 'eval'
        ]
        
        return any(pattern in signature for pattern in security_patterns)


class CandidateProcessor:
    """Main processor for API candidate filtering."""
    
    def __init__(self, output_dir: Path = OUTPUT_DIR):
        """
        Initialize the candidate processor.
        
        Args:
            output_dir: Directory to save filtered results
        """
        self.output_dir = Path(output_dir)
        self.security_filter = SecurityFilter()
        self.logger = logger.getChild('processor')

    def load_candidates_from_project(self, project_path: Path) -> List[APICandidate]:
        """
        Load API candidates from a project directory.
        
        Args:
            project_path: Path to the project directory
            
        Returns:
            List of loaded API candidates
        """
        candidates = []
        
        # Look for external API query results
        external_patterns = ["01_fetch_external_apis", "fetch_external_apis", "*external*"]
        
        for pattern in external_patterns:
            for external_dir in project_path.glob(pattern):
                if not external_dir.is_dir():
                    continue
                    
                for csv_file in external_dir.glob("*.csv"):
                    try:
                        df = pd.read_csv(csv_file, keep_default_na=False)
                        
                        # Process Python-style results
                        if 'module_name' in df.columns and 'function_name' in df.columns:
                            for _, row in df.iterrows():
                                candidate = APICandidate(
                                    package=str(row.get('module_name', '')),
                                    class_name=str(row.get('module_name', '')),  # Use module as class for Python
                                    method=str(row.get('function_name', '')),
                                    signature=str(row.get('full_signature', '')),
                                    file_path=str(row.get('file_path', '')),
                                    line_number=str(row.get('line_number', ''))
                                )
                                
                                # Basic validation
                                if all([candidate.package, candidate.method, candidate.signature]):
                                    candidates.append(candidate)
                                    
                    except Exception as e:
                        self.logger.warning(f"Failed to load {csv_file}: {e}")
                        continue
        
        return candidates

    def deduplicate_candidates(self, candidates: List[APICandidate]) -> List[APICandidate]:
        """
        Remove duplicate candidates while preserving semantic diversity.
        
        Args:
            candidates: List of candidates to deduplicate
            
        Returns:
            Deduplicated list of candidates
        """
        seen = set()
        unique_candidates = []
        
        for candidate in candidates:
            # Create a signature for exact matching
            signature = (candidate.package, candidate.class_name, candidate.method, candidate.signature)
            
            if signature not in seen:
                seen.add(signature)
                unique_candidates.append(candidate)
        
        return unique_candidates

    def filter_candidates(self, candidates: List[APICandidate]) -> List[APICandidate]:
        """
        Apply security filtering to candidates.
        
        Args:
            candidates: List of candidates to filter
            
        Returns:
            Filtered list of security-relevant candidates
        """
        return [c for c in candidates if self.security_filter.is_security_relevant(c)]

    def save_results(self, project_name: str, candidates: List[APICandidate]) -> None:
        """
        Save filtered candidates in IRIS format.
        
        Args:
            project_name: Name of the project
            candidates: List of filtered candidates to save
        """
        project_output_dir = self.output_dir / project_name / "api_candidates"
        project_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Convert to IRIS format
        candidate_dicts = []
        for candidate in candidates:
            candidate_dict = {
                "package": candidate.package,
                "clazz": candidate.class_name,      # IRIS uses 'clazz'
                "func": candidate.method,           # IRIS uses 'func'
                "full_signature": candidate.signature  # IRIS uses 'full_signature'
            }
            candidate_dicts.append(candidate_dict)
        
        # Save as CSV
        csv_path = project_output_dir / "filtered_api_candidates.csv"
        df = pd.DataFrame(candidate_dicts)
        df.to_csv(csv_path, index=False, encoding='utf-8')
        
        # Save as JSON
        json_path = project_output_dir / "filtered_api_candidates.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(candidate_dicts, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Saved {len(candidates)} candidates for {project_name}")

    def process_project(self, project_path: Path) -> Dict[str, int]:
        """
        Process a single project through the complete filtering pipeline.
        
        Args:
            project_path: Path to the project directory
            
        Returns:
            Dictionary with processing metrics
        """
        project_name = project_path.name
        start_time = time.time()
        
        self.logger.info(f"Processing project: {project_name}")
        
        # Load candidates
        candidates = self.load_candidates_from_project(project_path)
        if not candidates:
            self.logger.warning(f"No candidates found for {project_name}")
            return {"total": 0, "filtered": 0, "processing_time": 0.0}
        
        # Remove duplicates
        unique_candidates = self.deduplicate_candidates(candidates)
        
        # Apply security filtering
        filtered_candidates = self.filter_candidates(unique_candidates)
        
        # Save results
        if filtered_candidates:
            self.save_results(project_name, filtered_candidates)
        
        processing_time = time.time() - start_time
        metrics = {
            "total": len(candidates),
            "unique": len(unique_candidates),
            "filtered": len(filtered_candidates),
            "processing_time": processing_time
        }
        
        acceptance_rate = (len(filtered_candidates) / len(candidates)) * 100 if candidates else 0
        self.logger.info(
            f"Project {project_name}: {metrics['filtered']}/{metrics['total']} "
            f"candidates accepted ({acceptance_rate:.1f}%) in {processing_time:.2f}s"
        )
        
        return metrics

    async def process_projects_async(self, project_paths: List[Path], max_concurrent: int = 4) -> Dict[str, Dict[str, int]]:
        """
        Process multiple projects asynchronously.
        
        Args:
            project_paths: List of project paths to process
            max_concurrent: Maximum number of concurrent operations
            
        Returns:
            Dictionary mapping project names to their metrics
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def bounded_process(project_path: Path) -> tuple[str, Dict[str, int]]:
            async with semaphore:
                loop = asyncio.get_event_loop()
                metrics = await loop.run_in_executor(None, self.process_project, project_path)
                return project_path.name, metrics
        
        self.logger.info(f"Processing {len(project_paths)} projects with concurrency {max_concurrent}")
        
        tasks = [bounded_process(path) for path in project_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        metrics_by_project = {}
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Project processing failed: {result}")
                continue
            project_name, metrics = result
            metrics_by_project[project_name] = metrics
        
        return metrics_by_project


def discover_projects(output_dir: Path = OUTPUT_DIR) -> List[Path]:
    """
    Discover all project directories in the output folder.
    
    Args:
        output_dir: Directory to search for projects
        
    Returns:
        List of project directory paths
    """
    if not output_dir.exists():
        raise FileNotFoundError(f"Output directory not found: {output_dir}")
    
    projects = [d for d in output_dir.iterdir() if d.is_dir()]
    if not projects:
        raise FileNotFoundError("No project directories found")
    
    return projects


async def main() -> None:
    """Main entry point for the filtering application."""
    parser = argparse.ArgumentParser(description='Filter API candidates for LLM labeling')
    parser.add_argument('--project', type=str, default='all',
                        help='Project name to filter (default: all)')
    parser.add_argument('--max-concurrent', type=int, default=4,
                        help='Maximum concurrent operations (default: 4)')
    
    args = parser.parse_args()
    
    try:
        # Discover projects
        all_projects = discover_projects()
        
        # Filter projects if specific project requested
        if args.project != 'all':
            all_projects = [p for p in all_projects if p.name == args.project]
            if not all_projects:
                logger.error(f"Project '{args.project}' not found")
                available = [p.name for p in discover_projects()]
                logger.info(f"Available projects: {available}")
                return
        
        logger.info(f"Found {len(all_projects)} projects to process")
        
        # Process projects
        processor = CandidateProcessor()
        
        if len(all_projects) == 1:
            # Single project - process synchronously
            metrics = processor.process_project(all_projects[0])
            metrics_by_project = {all_projects[0].name: metrics}
        else:
            # Multiple projects - process asynchronously
            metrics_by_project = await processor.process_projects_async(all_projects, args.max_concurrent)
        
        # Print summary
        total_candidates = sum(m.get("total", 0) for m in metrics_by_project.values())
        total_filtered = sum(m.get("filtered", 0) for m in metrics_by_project.values())
        successful_projects = sum(1 for m in metrics_by_project.values() if m.get("filtered", 0) > 0)
        
        logger.info("=" * 50)
        logger.info("FILTERING SUMMARY")
        logger.info("=" * 50)
        logger.info(f"Projects processed: {len(metrics_by_project)}")
        logger.info(f"Successful projects: {successful_projects}")
        logger.info(f"Total candidates: {total_candidates}")
        logger.info(f"Filtered candidates: {total_filtered}")
        logger.info(f"Results saved in: {OUTPUT_DIR}/<project_name>/api_candidates/")
        
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        raise


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
    except Exception as e:
        logger.error(f"Application failed: {e}")
        raise
