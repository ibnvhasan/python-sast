"""
CodeQL Query Execution Module

This module handles the automated execution of CodeQL queries against multiple project databases.

Overview:
    This script processes all CodeQL query files (.ql) located in the /src/codeql-queries directory
    and executes them against each project database found in the data/codeql-dbs directory.

Directory Structure:
    - Input queries: /src/codeql-queries/*.ql
    - Project databases: data/codeql-dbs/
    - Output results: /output/<project_name>/query_name/

Workflow:
    1. Discovers all .ql query files in /src/codeql-queries
    2. Iterates through each project database in data/codeql-dbs
    3. Executes each query against each project database
    4. Stores raw results as .bqrs files in /output/<project_name>/query_name/query_name_results.bqrs
    5. Automatically decodes .bqrs files to .csv format in the same output directory

Output Format:
    For each combination of project and query, generates:
    - Raw binary results: /output/<project_name>/query_name/query_name_results.bqrs
    - Decoded CSV results: /output/<project_name>/query_name/query_name_results.csv

Dependencies:
    - CodeQL CLI tool must be installed and accessible
    - Project databases must be properly built and stored in data/codeql-dbs
    - Write permissions required for /output directory
"""


import os
from pathlib import Path
import subprocess
import glob
import argparse

PYSAST_ROOT = Path(__file__).resolve().parent.parent
CODEQL_QUERIES_DIR = PYSAST_ROOT / "src" / "codeql-queries"
CODEQL_DBS_DIR = PYSAST_ROOT / "data" / "codeql-dbs"
OUTPUT_DIR = PYSAST_ROOT / "output"

# Check directories and create output directory if it doesn't exist
def check_directories():
    # if codeql dbs directory does not exist, raise an error, and ask user to run 02_build_codeql_dbs.py
    if not CODEQL_DBS_DIR.is_dir():
        raise FileNotFoundError(f"CodeQL databases directory not found: {CODEQL_DBS_DIR}. Please run 02_build_codeql_dbs.py first.")
    
    # Create output directory if it doesn't exist
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Output directory is ready: {OUTPUT_DIR}")
    
    
# Install /src/codeql-queries/qlpack.yml if it does not exist
def install_qlpack():
    qlpack_path = CODEQL_QUERIES_DIR / "qlpack.yml"
    if not qlpack_path.exists():
        print(f"qlpack.yml not found at {qlpack_path}")
        return False
    try:
        subprocess.run(["codeql", "pack", "install", str(CODEQL_QUERIES_DIR)], check=True)
        print("Successfully installed qlpack.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing qlpack: {e}")
        return False
    
# Discover all .ql query files in the queries directory
def discover_queries():
    query_files = list(CODEQL_QUERIES_DIR.glob("**/*.ql"))
    if not query_files:
        raise FileNotFoundError("No .ql query files found in the queries directory.")
    return query_files

# Discover all CodeQL databases in the databases directory
def discover_databases():
    db_dirs = [d for d in CODEQL_DBS_DIR.iterdir() if d.is_dir()]
    if not db_dirs:
        raise FileNotFoundError("No CodeQL databases found in the databases directory.")
    return db_dirs

# Execute a single query against a project database
def execute_query(query_file, project_db):
    project_name = project_db.name
    query_name = query_file.stem
    output_dir = OUTPUT_DIR / project_name / query_name
    
    # Create output directory for this query if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Define the output file paths
    bqrs_output_path = output_dir / f"{query_name}_results.bqrs"
    csv_output_path = output_dir / f"{query_name}_results.csv"
    
    # Run the CodeQL query
    try:
        subprocess.run([
            "codeql", "query", "run",
            "--database", str(project_db),
            "--output", str(bqrs_output_path),
            str(query_file)
        ], check=True)
        
        # Decode the results to CSV
        subprocess.run([
            "codeql", "bqrs", "decode",
            "--format=csv",
            "--output", str(csv_output_path),
            str(bqrs_output_path)
        ], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing query {query_name} for project {project_name}: {e}")
        return False

# Main execution function
def main():
    parser = argparse.ArgumentParser(description='Run CodeQL queries against project databases.')
    parser.add_argument('--project', type=str, default='all', help='Project name to run queries against (default: all).')
    parser.add_argument('--query', type=str, default='all', help='Query name to run (default: all).')
    args = parser.parse_args()
    
    try:
        from tqdm import tqdm
    except ImportError:
        print("tqdm is required for progress bars. Install it with 'pip install tqdm'.")
        tqdm = None
    
    try:
        check_directories()
        
        # Install qlpack if it exists
        install_qlpack()
        
        # Discover queries and databases
        query_files = discover_queries()
        all_databases = discover_databases()
        
        # Filter queries if specific query is requested
        if args.query != 'all':
            query_files = [q for q in query_files if q.stem == args.query]
            if not query_files:
                print(f"No query found matching: {args.query}")
                return
        
        # Filter databases if specific project is requested
        if args.project != 'all':
            all_databases = [db for db in all_databases if db.name == args.project]
            if not all_databases:
                print(f"No project database found matching: {args.project}")
                return
        
        total_operations = len(query_files) * len(all_databases)
        print(f"Running {len(query_files)} queries against {len(all_databases)} databases ({total_operations} total operations)")
        
        success_count = 0
        error_count = 0
        
        if tqdm:
            with tqdm(total=total_operations, desc="Running CodeQL queries", unit="query") as pbar:
                for query_file in query_files:
                    for project_db in all_databases:
                        pbar.set_description(f"Running {query_file.stem} on {project_db.name}")
                        if execute_query(query_file, project_db):
                            success_count += 1
                        else:
                            error_count += 1
                        pbar.update(1)
        else:
            for query_file in query_files:
                for project_db in all_databases:
                    print(f"Running {query_file.stem} on {project_db.name}")
                    if execute_query(query_file, project_db):
                        success_count += 1
                    else:
                        error_count += 1
        
        print(f"\nCompleted: {success_count} successful, {error_count} failed")
        print(f"Results stored in: {OUTPUT_DIR}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
