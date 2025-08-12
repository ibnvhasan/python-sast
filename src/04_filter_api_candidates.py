"""
API Candidate Filtering Module

This module filters API candidates collected by CodeQL queries to prepare them for 
LLM labeling. It focuses on security-relevant APIs following IRIS methodology.

The filtered candidates are prepared for identifying:
- Sources: Entry points where untrusted data enters the system
- Sinks: Exit points where data flows to sensitive operations  
- Taint-propagators: Methods that pass data between sources and sinks
"""

import argparse
import json
import time
from pathlib import Path
from typing import Dict, List, Set

import pandas as pd

import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SecurityFilter:
    """Simple and effective filter for identifying security-relevant APIs."""
    
    def __init__(self):
        """Initialize security filtering patterns."""
        
        # Security-related modules
        self.security_modules = {
            'auth', 'oauth', 'jwt', 'session', 'login', 'security',
            'permission', 'role', 'access', 'requests', 'urllib', 'http',
            'sqlalchemy', 'django', 'flask', 'fastapi', 'crypto', 'hashlib',
            'subprocess', 'os', 'pickle', 'json', 'xml', 'yaml'
        }
        
        # Security-relevant methods
        self.security_methods = {
            'authenticate', 'authorize', 'login', 'logout', 'verify',
            'validate', 'sanitize', 'escape', 'encrypt', 'decrypt',
            'execute', 'query', 'get', 'post', 'put', 'delete',
            'read', 'write', 'save', 'load', 'parse', 'render'
        }
        
        # Blacklisted methods to exclude
        self.blacklist_methods = {
            '__init__', '__str__', '__repr__', '__len__', '__iter__',
            '__next__', '__enter__', '__exit__', '__new__', '__del__'
        }
        
        # Blacklisted packages
        self.blacklist_packages = {
            'builtins', 'collections', 'itertools', 'functools',
            'math', 'decimal', 'datetime', 'time', 'unittest', 'test'
        }

    def is_security_relevant(self, row: Dict[str, str]) -> bool:
        """
        Simple security relevance check.
        
        Args:
            row: Dictionary containing API candidate data
            
        Returns:
            True if candidate is security-relevant
        """
        module_name = row.get('module_name', '').lower()
        func_name = row.get('func_name', '').lower()
        signature = row.get('full_signature', '').lower()
        
        # Skip blacklisted items
        if func_name in self.blacklist_methods:
            return False
        
        if any(bp in module_name for bp in self.blacklist_packages):
            return False
        
        # Check for security modules
        if any(sm in module_name for sm in self.security_modules):
            return True
        
        # Check for security methods
        if any(sm in func_name for sm in self.security_methods):
            return True
        
        # Check for security patterns in signature
        security_keywords = [
            'request', 'response', 'user', 'session', 'token',
            'password', 'auth', 'sql', 'query', 'file', 'path'
        ]
        
        if any(keyword in signature for keyword in security_keywords):
            return True
        
        return False


def filter_api_candidates(input_csv_path: str, output_csv_path: str = None) -> str:
    """
    Filter API candidates from CSV file.
    
    Args:
        input_csv_path: Path to input CSV file (fetch_apis_results.csv)
        output_csv_path: Path to output CSV file (optional)
        
    Returns:
        Path to the filtered output CSV file
    """
    input_path = Path(input_csv_path)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    # Determine output path - save under output/<project>/api_candidates/
    if output_csv_path is None:
        # Extract project name from input path (e.g., output/apache_airflow_cwe-22/fetch_apis/...)
        # Go up to project directory and create api_candidates folder
        project_dir = input_path.parent.parent  # from fetch_apis to project directory
        api_candidates_dir = project_dir / "api_candidates"
        api_candidates_dir.mkdir(exist_ok=True)
        output_path = api_candidates_dir / "filtered_api_candidates.csv"
        json_output_path = api_candidates_dir / "filtered_api_candidates.json"
    else:
        output_path = Path(output_csv_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # Also create JSON version
        json_output_path = output_path.with_suffix('.json')
    
    logger.info(f"Reading API candidates from: {input_path}")
    
    # Read CSV file
    df = pd.read_csv(input_path, keep_default_na=False)
    
    if df.empty:
        logger.warning("Input CSV file is empty")
        return str(output_path)
    
    logger.info(f"Loaded {len(df)} API candidates")
    logger.info(f"Available columns: {list(df.columns)}")
    
    # Keep only required columns if they exist
    required_columns = ['module_name', 'class_name', 'func_name', 'full_signature']
    available_columns = [col for col in required_columns if col in df.columns]
    
    if not available_columns:
        logger.error(f"None of the required columns found: {required_columns}")
        logger.error(f"Available columns: {list(df.columns)}")
        raise ValueError("No required columns found in CSV file")
    
    # Filter to only required columns
    df_filtered = df[available_columns].copy()
    logger.info(f"Using columns: {available_columns}")
    
    # Remove duplicates based on available columns
    initial_count = len(df_filtered)
    df_filtered = df_filtered.drop_duplicates()
    after_dedup_count = len(df_filtered)
    logger.info(f"After deduplication: {after_dedup_count}/{initial_count} candidates")
    
    # Apply simple security filtering
    security_filter = SecurityFilter()
    
    # Convert to list of dictionaries for filtering
    candidates = df_filtered.to_dict('records')
    filtered_candidates = []
    for candidate in candidates:
        if security_filter.is_security_relevant(candidate):
            filtered_candidates.append(candidate)
    
    logger.info(f"After security filtering: {len(filtered_candidates)}/{len(candidates)} candidates")
    
    # Apply simple sampling to limit volume while maintaining diversity
    final_candidates = smart_candidate_selection(filtered_candidates, target_count=1500)
    
    logger.info(f"After intelligent sampling: {len(final_candidates)}/{len(filtered_candidates)} candidates")
    
    # Convert back to DataFrame and save
    if final_candidates:
        result_df = pd.DataFrame(final_candidates)
        result_df.to_csv(output_path, index=False, encoding='utf-8')
        logger.info(f"Saved filtered candidates to: {output_path}")
        
        # Also save as JSON
        with open(json_output_path, 'w', encoding='utf-8') as f:
            json.dump(final_candidates, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved filtered candidates to: {json_output_path}")
    else:
        # Create empty files with headers
        empty_df = pd.DataFrame(columns=available_columns)
        empty_df.to_csv(output_path, index=False, encoding='utf-8')
        
        with open(json_output_path, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=2)
        
        logger.warning(f"No security-relevant candidates found. Created empty files: {output_path}, {json_output_path}")
    
    return str(output_path)


def smart_candidate_selection(candidates: List[Dict[str, str]], target_count: int = 1500) -> List[Dict[str, str]]:
    """
    Simple intelligent sampling that prioritizes security-relevant APIs.
    
    Args:
        candidates: List of filtered candidate dictionaries
        target_count: Target number of candidates to select
        
    Returns:
        List of selected candidate dictionaries
    """
    if len(candidates) <= target_count:
        return candidates
    
    # Group candidates by function patterns for diversity
    groups = {
        'auth': [],
        'database': [],
        'http': [],
        'crypto': [],
        'file': [],
        'other': []
    }
    
    for candidate in candidates:
        func_name = candidate.get('func_name', '').lower()
        module_name = candidate.get('module_name', '').lower()
        signature = candidate.get('full_signature', '').lower()
        
        # Categorize candidate
        if any(pattern in func_name or pattern in module_name for pattern in ['auth', 'login', 'session', 'jwt', 'oauth']):
            groups['auth'].append(candidate)
        elif any(pattern in func_name or pattern in module_name for pattern in ['sql', 'query', 'database', 'db']):
            groups['database'].append(candidate)
        elif any(pattern in func_name or pattern in module_name for pattern in ['http', 'request', 'response', 'api']):
            groups['http'].append(candidate)
        elif any(pattern in func_name or pattern in module_name for pattern in ['crypto', 'hash', 'encrypt', 'secret']):
            groups['crypto'].append(candidate)
        elif any(pattern in func_name or pattern in module_name for pattern in ['file', 'path', 'upload', 'download']):
            groups['file'].append(candidate)
        else:
            groups['other'].append(candidate)
    
    # Select proportionally from each group
    selected = []
    group_targets = {
        'auth': int(target_count * 0.25),      # 25% for auth
        'database': int(target_count * 0.20),  # 20% for database
        'http': int(target_count * 0.20),      # 20% for HTTP
        'crypto': int(target_count * 0.15),    # 15% for crypto
        'file': int(target_count * 0.10),      # 10% for file
        'other': int(target_count * 0.10)      # 10% for other
    }
    
    # Sample from each group
    import random
    random.seed(42)  # For reproducible results
    
    for group_name, group_candidates in groups.items():
        target = group_targets[group_name]
        if group_candidates:
            if len(group_candidates) <= target:
                selected.extend(group_candidates)
            else:
                selected.extend(random.sample(group_candidates, target))
    
    # If we need more candidates, add from the largest group
    remaining_needed = target_count - len(selected)
    if remaining_needed > 0:
        all_remaining = [c for c in candidates if c not in selected]
        if all_remaining:
            additional = random.sample(all_remaining, min(remaining_needed, len(all_remaining)))
            selected.extend(additional)
    
    return selected[:target_count]


def main():
    """Main entry point for the filtering application."""
    parser = argparse.ArgumentParser(description='Filter API candidates for LLM labeling')
    parser.add_argument('input_csv', help='Path to input CSV file (fetch_apis_results.csv)')
    parser.add_argument('--output', help='Path to output CSV file (optional)')
    
    args = parser.parse_args()
    
    try:
        output_path = filter_api_candidates(args.input_csv, args.output)
        logger.info(f"✅ Filtering completed successfully!")
        logger.info(f"📄 Output file: {output_path}")
        print(output_path)  # Print path for next stage to use
        
    except Exception as e:
        logger.error(f"❌ Filtering failed: {e}")
        raise


if __name__ == "__main__":
    main()
