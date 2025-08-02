"""
This file is to clone all projects that will be analyzed, the source is from ../data/dataset/pyvul.json.
After clone with the specific commit id, it will be checked out exactly one commit before it's fixed.

This module handles the cloning and checkout process for analyzing projects from a dataset.
It reads project information from a JSON dataset file and performs git operations to
prepare the repositories for analysis at the specific commit states needed.

The cloning process involves:
1. Reading project data from ../data/dataset/pyvul.json
2. Cloning repositories with specific commit IDs
3. Checking out to the commit immediately before the fix was applied
"""

import os
import json
import subprocess
import re
from pathlib import Path


PYSAST_ROOT = Path(__file__).resolve().parent.parent
PROJECT_SOURCES_DIR = PYSAST_ROOT / "data" / "project-sources"
DATASET_FILE = PYSAST_ROOT / "data" / "dataset" / "pyvul.json"

# 01 Check dataset file exists
def check_directories() -> None:
    """Ensure the dataset file and project sources directory exist."""
    if not DATASET_FILE.is_file():
        raise FileNotFoundError(f"Dataset file not found: {DATASET_FILE}")
    
    if not PROJECT_SOURCES_DIR.is_dir():
        os.makedirs(PROJECT_SOURCES_DIR, exist_ok=True)
        print(f"Created directory for project sources: {PROJECT_SOURCES_DIR}")
    else:
        print(f"Project sources directory already exists: {PROJECT_SOURCES_DIR}")



# 02 Load JSON dataset (find commit url and corresponding CWE id)
def load_dataset(DATASET_FILE) -> dict:
    """Load the dataset from the specified JSON file."""
    dataset = {}
    with open(DATASET_FILE, 'r') as f:
        try:
            dataset = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Error decoding JSON from {DATASET_FILE}: {e}")

    return dataset


# 03 Clone a repository from the specified commit URLs and checkout to the one commit before the fix
def clone_and_checkout(commit_url: str, cwe_id: str) -> None:
    """
    Clone a repository and checkout to the commit before the fix.
    
    Args:
        commit_url: URL to the GitHub commit
        cwe_id: The CWE ID associated with this vulnerability
    """
    # Extract repository URL and commit hash from commit URL
    # Format: https://github.com/owner/repo/commit/hash
    match = re.match(r'https://github.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)', commit_url)
    if not match:
        print(f"Invalid commit URL format: {commit_url}")
        return
    
    owner, repo, commit_hash = match.groups()
    repo_url = f"https://github.com/{owner}/{repo}.git"
    # Format: <project_owner>_<project_name>_cwe-<CWE_id>
    clean_cwe_id = cwe_id.replace("CWE-", "")
    project_dir = PROJECT_SOURCES_DIR / f"{owner}_{repo}_cwe-{clean_cwe_id}"
    
    if not project_dir.exists():
        print(f"Cloning {repo_url} into {project_dir}")
        subprocess.run(['git', 'clone', repo_url, str(project_dir)], check=True)
        
        # Checkout to the specified commit
        subprocess.run(['git', 'checkout', commit_hash], cwd=project_dir, check=True)
        
        # Then move one commit back to see the vulnerable code
        subprocess.run(['git', 'checkout', 'HEAD~1'], cwd=project_dir, check=True)
        print(f"Successfully checked out to commit before fix for {repo_url} (CWE-{cwe_id})")
    else:
        print(f"Repository already exists at {project_dir}")


# 04 Filter projects by CWE ID and limit the number to clone
def filter_projects(dataset: dict, cwe_ids: list, count_per_cwe: int) -> list:
    """
    Filter projects based on CWE IDs and limit the number per CWE.
    
    Args:
        dataset: The loaded dataset dictionary where keys are commit URLs and values are CWE IDs
        cwe_ids: List of CWE IDs to filter by (without "CWE-" prefix)
        count_per_cwe: Maximum number of projects to include per CWE ID
    
    Returns:
        List of tuples (commit_url, cwe_id) to process
    """
    filtered_projects = []
    
    # Group projects by CWE ID
    cwe_grouped_projects = {}
    for commit_url, cwe in dataset.items():
        # Remove "CWE-" prefix if present
        clean_cwe = cwe.replace("CWE-", "")
        if clean_cwe not in cwe_grouped_projects:
            cwe_grouped_projects[clean_cwe] = []
        cwe_grouped_projects[clean_cwe].append((commit_url, cwe))
    
    # Filter by requested CWE IDs and apply count limit
    for cwe_id in cwe_ids:
        clean_cwe_id = cwe_id.replace("CWE-", "")
        if clean_cwe_id in cwe_grouped_projects:
            selected_projects = cwe_grouped_projects[clean_cwe_id][:count_per_cwe]
            filtered_projects.extend(selected_projects)
            print(f"Selected {len(selected_projects)} projects for CWE-{clean_cwe_id}")
        else:
            print(f"No projects found for CWE-{clean_cwe_id}")
    
    return filtered_projects

import argparse

def main() -> None:
    """Main function to parse arguments and execute the cloning process."""
    parser = argparse.ArgumentParser(description='Clone GitHub projects for Python SAST analysis')
    parser.add_argument('--cwe', type=str, default=None, help='CWE IDs to filter projects (comma-separated, e.g., 78 or 79,94)')
    parser.add_argument('--count', type=int, default=None, help='Number of projects to clone per CWE ID, default is 1')
    args = parser.parse_args()

    # Default behavior: if no arguments, clone 1 project for each cwe 22,78,79,94
    if args.cwe is None and args.count is None:
        cwe_ids = ['22', '78', '79', '94']
        count = 1
    else:
        cwe_ids = [cwe.strip() for cwe in (args.cwe or '').split(',') if cwe.strip()] if args.cwe else ['22', '78', '79', '94']
        count = args.count if args.count is not None else 1
    
    try:
        from tqdm import tqdm
    except ImportError:
        print("tqdm is required for progress bars. Install it with 'pip install tqdm'.")
        return

    try:
        check_directories()
        dataset = load_dataset(DATASET_FILE)
        # Build a mapping of CWE to all candidate URLs
        cwe_grouped_projects = {}
        for commit_url, cwe_id in dataset.items():
            clean_cwe = cwe_id.replace("CWE-", "")
            cwe_grouped_projects.setdefault(clean_cwe, []).append(commit_url)

        total_repos_to_clone = len(cwe_ids) * count
        base_dir = str(PROJECT_SOURCES_DIR)

        with tqdm(total=total_repos_to_clone, desc="Overall Progress", unit="repo") as pbar:
            for cwe in cwe_ids:
                clean_cwe = cwe.replace("CWE-", "")
                urls = cwe_grouped_projects.get(clean_cwe, [])
                found = 0
                idx = 0
                pbar.write(f"Attempting to clone {count} repo(s) for CWE-{clean_cwe}...")
                while found < count and idx < len(urls):
                    url = urls[idx]
                    idx += 1
                    try:
                        parts = url.strip().split('/')
                        repo_owner = parts[3]
                        repo_name = parts[4]
                        commit_sha = parts[6]
                        repo_url = f"https://github.com/{repo_owner}/{repo_name}.git"

                        pbar.set_description(f"Cloning {repo_name}")

                        target_dir_base = os.path.join(base_dir, f"{repo_owner}_{repo_name}_cwe-{clean_cwe}")
                        target_dir = target_dir_base
                        counter = 1
                        while os.path.exists(target_dir):
                            # If exists, skip and try next matching repo
                            target_dir = f"{target_dir_base}_{counter}"
                            counter += 1
                        if os.path.exists(target_dir_base):
                            pbar.write(f"⚠️ Repo already exists: {target_dir_base}, skipping.")
                            continue

                        subprocess.run([
                            "git", "clone", "--quiet", repo_url, target_dir
                        ], check=True, capture_output=True, text=True)

                        # Checkout one before the fixed commit
                        subprocess.run([
                            "git", "checkout", f"{commit_sha}^"
                        ], cwd=target_dir, check=True, capture_output=True, text=True)

                        pbar.write(f"✅ Success! '{repo_name}' is ready in '{target_dir}'.")
                        found += 1
                    except subprocess.CalledProcessError as e:
                        pbar.write(f"❌ Error processing {url}: {e.stderr.strip() if e.stderr else e}")
                    except (IndexError, KeyError):
                        pbar.write(f"❌ Error: Could not parse the URL: {url}")
                    except Exception as e:
                        pbar.write(f"❌ An unexpected error occurred: {e}")
                    pbar.update(1)
                pbar.write("-" * 30)
        print(f"Successfully cloned {total_repos_to_clone} projects for analysis.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()