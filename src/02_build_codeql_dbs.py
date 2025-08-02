"""
CodeQL Database Builder

This module provides functionality to build CodeQL databases for each project
located in /data/project-sources. The generated databases are stored in the
data/codeql-dbs directory.

This script automates the process of creating CodeQL databases for multiple
projects, enabling code analysis and security scanning across a collection
of source code repositories.
"""

import os
from pathlib import Path
import subprocess
import argparse

PYSAST_ROOT = Path(__file__).resolve().parent.parent
PROJECT_SOURCES_DIR = PYSAST_ROOT / "data" / "project-sources"
CODEQL_DBS_DIR = PYSAST_ROOT / "data" / "codeql-dbs"


# Check if the necessary directories exist and create them if not
def check_directories() -> None:
    PROJECT_SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    CODEQL_DBS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Directories exist: \nProject Dir: {PROJECT_SOURCES_DIR}\nCodeQL DB Dir: {CODEQL_DBS_DIR}")

# Load the list of projects from the project sources directory
def load_projects() -> list:
    """Load the list of projects from the project sources directory."""
    projects = []
    for project in PROJECT_SOURCES_DIR.iterdir():
        if project.is_dir() and (project / ".git").exists():
            projects.append(project)
    return projects
    
# Build CodeQL databases for each project in the project sources directory
def build_codeql_dbs(project_dirs: list) -> None:
    try:
        from tqdm import tqdm
    except ImportError:
        print("tqdm is required for progress bars. Install it with 'pip install tqdm'.")
        tqdm = None

    total = len(project_dirs)
    bar = tqdm(project_dirs, desc="Building CodeQL DBs", unit="db") if tqdm else project_dirs
    errors = []
    for project_dir in bar:
        codeql_db_path = CODEQL_DBS_DIR / project_dir.name
        try:
            subprocess.run([
                "codeql", "database", "create",
                "--source-root", str(project_dir),
                "--language", "python",
                "--quiet",
                "--overwrite",
                str(codeql_db_path)
            ], check=True)
        except subprocess.CalledProcessError as e:
            errors.append(f"❌ Error building DB for {project_dir}: {e}")
    if errors:
        print("\nSome errors occurred:")
        for err in errors:
            print(err)
    
# Main function to execute the script
def main() -> None:
    parser = argparse.ArgumentParser(description='Build CodeQL databases for selected projects.')
    parser.add_argument('--project', type=str, default='all', help='Project name to build CodeQL DB for (default: all).')
    args = parser.parse_args()

    check_directories()
    all_projects = load_projects()
    if args.project == 'all':
        selected_projects = all_projects
    else:
        selected_projects = [p for p in all_projects if p.name == args.project]
        if not selected_projects:
            print(f"No project found matching: {args.project}")
            return
    build_codeql_dbs(selected_projects)
    
# Entry point for the script
if __name__ == "__main__":
    main()
    print("CodeQL databases built successfully.")
    print(f"Databases are stored in: {CODEQL_DBS_DIR}")
    print("You can now analyze the databases using CodeQL queries.")
    print("==============================================================")