"""
API Candidate Filtering Module

This module provides functionality for filtering API candidates collected by CodeQL queries
from the previous stage of the analysis pipeline. The filtering process is crucial for
maintaining accuracy in LLM labeling of security-related components.

The filtering includes:
- Relevancy filtering for security-related APIs
- Deduplication of candidate APIs
- Quality assessment and ranking
- Preparation for LLM labeling of sources, sinks, and taint-propagators

This implementation follows the IRIS methodology for maintaining high precision in
static analysis results, ensuring that only the most relevant and unique API candidates
are passed to the subsequent LLM labeling stage for security classification.

The filtered candidates are essential for accurate identification of:
- Sources: Entry points where untrusted data enters the system
- Sinks: Exit points where data flows to sensitive operations
- Taint-propagators: Methods that pass data between sources and sinks
"""

import os
import json
import pandas as pd
import argparse
from pathlib import Path

PYSAST_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PYSAST_ROOT / "output"

# Python primitive/built-in types
PYTHON_PRIMITIVE_TYPES = {
    "int", "float", "str", "bool", "bytes", "list", "dict", "tuple", "set", "frozenset",
    "object", "type", "None", "NoneType"
}

# Security-relevant API patterns for Python projects
SECURITY_RELEVANT_MODULES = {
    # Web frameworks
    "flask", "django", "fastapi", "tornado", "cherrypy", "pyramid", "bottle",
    # HTTP clients
    "requests", "urllib", "httplib", "http.client", "httpx",
    # Database libraries  
    "sqlite3", "pymongo", "psycopg2", "mysql", "sqlalchemy",
    # File operations
    "os", "sys", "subprocess", "pathlib", "shutil",
    # Serialization
    "pickle", "json", "yaml", "xml", "lxml",
    # Templating
    "jinja2", "mako", "cheetah",
    # Authentication/crypto
    "hashlib", "hmac", "base64", "cryptography", "jwt",
    # Network/socket
    "socket", "ssl", "ftplib", "smtplib",
    # Validation/sanitization
    "re", "html", "escape",
    # Cloud/external services
    "boto3", "azure", "google.cloud"
}

# Security-relevant function patterns
SECURITY_RELEVANT_FUNCTIONS = {
    # Sources (input from external)
    "get", "post", "put", "delete", "request", "params", "form", "query", "header", "cookie", 
    "input", "raw_input", "read", "readline", "recv", "execute", "eval", "exec",
    "open", "file", "load", "loads", "decode", "parse", "connect",
    
    # Sinks (output to external/sensitive operations)
    "write", "send", "response", "render", "redirect", "forward", "include",
    "execute", "system", "popen", "call", "run", "save", "dump", "dumps", "encode",
    "log", "print", "output", "commit", "insert", "update", "delete",
    
    # Taint propagators (data transformation)
    "format", "join", "replace", "substitute", "interpolate", "concat", "append",
    "split", "strip", "lower", "upper", "translate", "escape", "unescape"
}

def check_directories():
    """Check if necessary directories exist."""
    if not OUTPUT_DIR.exists():
        raise FileNotFoundError(f"Output directory not found: {OUTPUT_DIR}. Please run 03_run_codeql_queries.py first.")
    print(f"Output directory found: {OUTPUT_DIR}")

def discover_projects():
    """Discover all project directories in the output folder."""
    projects = [d for d in OUTPUT_DIR.iterdir() if d.is_dir()]
    if not projects:
        raise FileNotFoundError("No project directories found in output folder.")
    return projects

def filter_invalid_entries(api_candidates):
    """
    Filter out invalid Python API entries.
    Ensures all required fields are present.
    """
    required_fields = ["method", "class", "package", "signature"]
    
    def is_valid(candidate):
        return all(candidate.get(field) for field in required_fields)
    
    return [api for api in api_candidates if is_valid(api)]

def api_is_candidate(candidate):
    """
    Python-focused API candidate filter - determine if API is security-relevant.
    
    Analysis approach:
    1. Exclude built-in/dunder methods that are never security-relevant
    2. Include security-critical contexts (web frameworks, database, OS operations)
    3. Include data flow operations (get, set, read, write, execute)
    4. Include APIs with complex parameters or security-relevant signatures
    """
    
    pkg = candidate.get("package", "").lower()
    method = candidate.get("method", "").lower()
    signature = candidate.get("signature", "").lower()
    
    # Step 1: HARD BLACKLIST - APIs that are never useful for security analysis
    hard_blacklist_methods = [
        "__init__", "__new__", "__del__", "__str__", "__repr__", "__hash__",
        "__len__", "__iter__", "__next__", "__contains__", "__getitem__", "__setitem__",
        "__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__",
        "__add__", "__sub__", "__mul__", "__div__", "__mod__", "__bool__",
        "__getattribute__", "__setattr__", "__getattr__", "__delattr__"
    ]
    
    if method in hard_blacklist_methods:
        return False
    
    # Step 2: HARD BLACKLIST - Package/class combinations that are never useful
    hard_blacklist_packages = [
        "__doc__", "__name__", "__module__", "__class__", "__dict__",
        "object", "type", "property", "staticmethod", "classmethod"
    ]
    
    if pkg in hard_blacklist_packages:
        return False
    
    # Step 3: SECURITY-RELEVANT CONTEXT - Always include these
    security_critical_contexts = {
        # Web frameworks - always security relevant
        'web': ['flask', 'django', 'fastapi', 'tornado', 'pyramid', 'bottle', 'cherrypy'],
        # HTTP/Network - always security relevant  
        'http': ['requests', 'urllib', 'httplib', 'http', 'httpx', 'aiohttp'],
        # Database - always security relevant
        'database': ['sqlite3', 'pymongo', 'psycopg2', 'mysql', 'sqlalchemy', 'redis'],
        # OS operations - always security relevant
        'os': ['os', 'sys', 'subprocess', 'pathlib', 'shutil', 'tempfile'],
        # Serialization - always security relevant
        'serialization': ['pickle', 'json', 'yaml', 'xml', 'lxml'],
        # Template engines - always security relevant
        'template': ['jinja2', 'mako', 'template'],
        # Crypto/Auth - always security relevant
        'crypto': ['hashlib', 'hmac', 'base64', 'cryptography', 'jwt', 'ssl', 'crypto'],
        # Logging (can be sinks)
        'logging': ['logging', 'logger']
    }
    
    for context_type, modules in security_critical_contexts.items():
        if any(module in pkg for module in modules):
            return True
    
    # Step 4: DATA FLOW OPERATIONS - Include operations that participate in data flow
    data_flow_methods = {
        # Data retrieval/access
        'get', 'put', 'set', 'add', 'remove', 'pop', 'append', 'insert', 'update', 'delete',
        # String operations (injection vectors)
        'format', 'replace', 'substitute', 'join', 'split', 'strip', 'encode', 'decode',
        # File operations
        'read', 'write', 'open', 'load', 'save', 'dump', 'close',
        # Network operations
        'send', 'recv', 'connect', 'listen', 'request', 'response',
        # Execution operations
        'execute', 'eval', 'exec', 'system', 'call', 'run', 'spawn',
        # Query operations
        'query', 'select', 'insert', 'update', 'delete'
    }
    
    if method in data_flow_methods:
        return True
    
    # Step 5: COMPLEX PARAMETER TYPES - Check for non-trivial parameters
    if python_api_has_non_trivial_parameter(candidate) or python_api_has_non_trivial_return(candidate):
        # But exclude very basic built-in types even if they have parameters
        basic_builtin_packages = ['str', 'int', 'float', 'list', 'dict', 'tuple', 'set', 'bool', 'bytes']
        if pkg not in basic_builtin_packages:
            return True
    
    # Step 6: SIGNATURE-BASED SECURITY PATTERNS
    security_signature_patterns = [
        'request', 'response', 'param', 'query', 'header', 'cookie', 'session',
        'auth', 'login', 'password', 'token', 'encrypt', 'decrypt', 'hash',
        'file', 'path', 'url', 'uri', 'sql', 'db', 'exec', 'eval', 'system',
        'render', 'template', 'escape', 'sanitize', 'validate'
    ]
    
    if any(pattern in signature for pattern in security_signature_patterns):
        return True
    
    # Default: exclude if none of the above criteria matched
    return False

def collect_invoked_external_apis(project_dir):
    """
    IRIS-style method: Load external APIs and apply api_is_candidate filter.
    
    Following IRIS methodology from collect_invoked_external_apis():
    1. Load all extracted external APIs from CodeQL results
    2. Apply api_is_candidate filter to each row
    3. Return surviving candidates
    """
    api_candidates = []
    
    # Look for fetch_external_apis query results (updated path structure)
    external_apis_patterns = [
        "01_fetch_external_apis",  # Your current structure
        "fetch_external_apis",    # Original expected structure
        "*external*",             # Fallback pattern
    ]
    
    for pattern in external_apis_patterns:
        external_apis_dirs = list(project_dir.glob(pattern))
        for external_apis_dir in external_apis_dirs:
            if external_apis_dir.is_dir():
                csv_files = list(external_apis_dir.glob("*.csv"))
                for csv_file in csv_files:
                    try:
                        df = pd.read_csv(csv_file, keep_default_na=False)
                        if not df.empty:
                            print(f"  ==> Found {len(df)} rows in {csv_file}")
                            print(f"  ==> Columns: {list(df.columns)}")
                            
                            # For Python results, process each row and apply api_is_candidate filter
                            if 'module_name' in df.columns and 'function_name' in df.columns:
                                print(f"  ==> Processing Python-style results with IRIS filtering...")
                                count = 0
                                filtered_count = 0
                                
                                for _, row in df.iterrows():
                                    count += 1
                                    
                                    # Create candidate in IRIS format
                                    candidate = {
                                        'package': str(row.get('module_name', '')),
                                        'class': str(row.get('module_name', '')),  # Use module as class for Python
                                        'method': str(row.get('function_name', '')),
                                        'signature': str(row.get('full_signature', '')),
                                        'is_static': 'false',  # Python doesn't have static methods in same way
                                        'file_path': str(row.get('file_path', '')),
                                        'line_number': str(row.get('line_number', ''))
                                    }
                                    
                                    # Apply IRIS api_is_candidate filter
                                    if api_is_candidate(candidate):
                                        api_candidates.append(candidate)
                                        filtered_count += 1
                                        
                                        # Show preview of first few accepted candidates
                                        if filtered_count <= 10:
                                            print(f"    ✅ Accepted {filtered_count}: {candidate['package']}.{candidate['method']}")
                                    else:
                                        # Show a few rejected examples for debugging
                                        if count <= 10:
                                            print(f"    ❌ Rejected {count}: {candidate['package']}.{candidate['method']}")
                                
                                print(f"  ==> IRIS filtering results:")
                                print(f"      📊 {filtered_count}/{count} candidates passed ({filtered_count/count*100:.1f}%)")
                                print(f"      🎯 Target reduction: 85-95% (IRIS achieved 89%)")
                                
                                if filtered_count/count > 0.15:  # More than 15% passing
                                    print(f"      ⚠️  Warning: Filter may be too permissive")
                                elif filtered_count/count < 0.01:  # Less than 1% passing  
                                    print(f"      ⚠️  Warning: Filter may be too restrictive")
                                else:
                                    print(f"      ✅ Filter selectivity looks good")
                            
                            else:
                                print(f"  ==> Unrecognized CSV format in {csv_file}")
                                print(f"      Expected columns: module_name, function_name, full_signature")
                                print(f"      Found columns: {list(df.columns)}")
                                    
                    except Exception as e:
                        print(f"Error reading {csv_file}: {e}")
    
    return api_candidates

def python_api_not_on_blacklist(candidate):
    """
    Python-specific blacklist filter: Exclude built-in types and non-security operations.
    """
    pkg = candidate.get("package", "")
    method = candidate.get("method", "")
    
    # Python built-in types and modules that are never security-relevant
    python_blacklist_packages = [
        "__doc__", "__name__", "__module__", "__class__", "__dict__",
        "str", "int", "float", "list", "dict", "tuple", "set", "bool", "bytes",
        "object", "type", "property", "staticmethod", "classmethod"
    ]
    
    if pkg in python_blacklist_packages:
        return False
    
    # Python dunder methods that are never security-relevant
    python_blacklist_methods = [
        "__getattribute__", "__setattr__", "__getattr__", "__delattr__",
        "__init__", "__new__", "__del__", "__str__", "__repr__", "__hash__",
        "__len__", "__iter__", "__next__", "__contains__", "__getitem__",
        "__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__",
        "__add__", "__sub__", "__mul__", "__div__", "__mod__", "__bool__"
    ]
    
    if method in python_blacklist_methods:
        return False
    
    # Filter very generic string/collection operations unless in security context
    generic_operations = [
        "find", "split", "join", "strip", "lower", "upper", "startswith", "endswith",
        "append", "extend", "remove", "pop", "clear", "copy", "keys", "values", "items"
    ]
    
    if method in generic_operations:
        # Only allow if in a potentially security-relevant context
        security_context_indicators = [
            "request", "response", "param", "query", "header", "cookie", "session",
            "auth", "login", "password", "token", "encrypt", "decrypt", "hash",
            "file", "path", "url", "uri", "sql", "db", "exec", "eval", "system"
        ]
        
        signature = candidate.get("signature", "").lower()
        if not any(indicator in signature or indicator in pkg.lower() 
                  for indicator in security_context_indicators):
            return False
    
    # Filter out test packages
    if "test" in pkg.lower():
        return False
        
    return True

def python_api_has_non_trivial_parameter(candidate):
    """
    Python-specific parameter check: Look for complex parameters or multiple parameters.
    """
    signature = candidate.get("signature", "")
    
    if "(" in signature and ")" in signature:
        # Extract parameter section
        param_start = signature.find("(")
        param_end = signature.rfind(")")
        params_section = signature[param_start+1:param_end].strip()
        
        if not params_section:
            return False  # No parameters
        
        # Look for indicators of complex/interesting parameters
        complex_param_indicators = [
            "request", "response", "session", "context", "data", "input", "output",
            "file", "path", "url", "connection", "cursor", "query", "command",
            "json", "xml", "html", "template", "config", "settings"
        ]
        
        params_lower = params_section.lower()
        if any(indicator in params_lower for indicator in complex_param_indicators):
            return True
        
        # Check for multiple parameters (often indicates complexity)
        param_count = len([p for p in params_section.split(",") if p.strip()])
        if param_count >= 2:
            return True
        
        # Check for meaningful parameter names (not just single letters)
        params = [p.strip() for p in params_section.split(",") if p.strip()]
        for param in params:
            if len(param) > 3 and not param.isdigit():  # Meaningful parameter names
                return True
    
    return False

def python_api_has_non_trivial_return(candidate):
    """
    Check if the Python API has non-trivial return type.
    For Python, this is less relevant than Java, but constructors are considered non-trivial.
    """
    signature = candidate.get("signature", "")
    method = candidate.get("method", "")
    
    # Constructors or class instantiation methods are considered non-trivial
    if method in ['__new__', '__init__'] or method.startswith('create') or method.startswith('build'):
        return True
    
    # For Python, we don't usually have explicit return types in signatures
    # So this check is less important than the parameter check
    return False

def filter_invalid_entries(api_candidates):
    """
    Filter out invalid API entries.
    Based on IRIS: ensures all required fields are present.
    """
    required_fields = ["method", "class", "package", "signature"]
    
    def is_valid(candidate):
        return all(candidate.get(field) for field in required_fields)
    
    return [api for api in api_candidates if is_valid(api)]

def smart_deduplicate_candidates(api_candidates):
    """
    Smart deduplication focused on unique API patterns for LLM labeling.
    
    Strategy: Keep semantically different APIs that represent different security patterns.
    Unlike simple deduplication, this focuses on what's useful for building CodeQL queries.
    
    Examples of what to keep as separate:
    - HashMap.get(Object) vs HashMap.get(String) - different parameter types
    - request.get() vs file.get() - different security contexts
    - String.format(String) vs String.format(String, Object[]) - different complexity
    """
    
    # First, do exact deduplication to remove true duplicates
    seen_exact = set()
    exact_deduplicated = []
    
    for candidate in api_candidates:
        # Create exact match key
        exact_key = (
            candidate.get("package", ""),
            candidate.get("class", ""), 
            candidate.get("method", ""),
            candidate.get("signature", "")
        )
        
        if exact_key not in seen_exact:
            seen_exact.add(exact_key)
            exact_deduplicated.append(candidate)
    
    print(f"    ==> Exact deduplication: {len(api_candidates)} → {len(exact_deduplicated)} candidates")
    
    # Then, group by semantic patterns for smart selection
    pattern_groups = {}
    
    for candidate in exact_deduplicated:
        pkg = candidate.get("package", "")
        cls = candidate.get("class", "")
        method = candidate.get("method", "")
        signature = candidate.get("signature", "")
        
        # Create a semantic grouping key
        # For Python: module.function 
        # For Java: package.class.method
        if pkg == cls:  # Python style: module used as both package and class
            base_pattern = f"{pkg}.{method}"
        else:  # Java style: separate package and class
            base_pattern = f"{pkg}.{cls}.{method}"
        
        # Analyze signature complexity for sub-grouping
        param_complexity = "simple"
        if "," in signature:  # Multiple parameters
            param_complexity = "multi"
        elif any(complex_type in signature.lower() for complex_type in 
                ['object', 'string', 'map', 'list', 'array', 'request', 'response', 'session']):
            param_complexity = "complex"
        
        # Create unique pattern key that preserves semantic differences
        pattern_key = f"{base_pattern}#{param_complexity}"
        
        if pattern_key not in pattern_groups:
            pattern_groups[pattern_key] = []
        pattern_groups[pattern_key].append(candidate)
    
    # Select best representative from each pattern group
    final_deduplicated = []
    
    for pattern_key, group in pattern_groups.items():
        if len(group) == 1:
            # Single candidate - always keep
            final_deduplicated.extend(group)
        else:
            # Multiple candidates - select the most representative ones
            # Sort by signature complexity and security relevance
            scored_candidates = []
            
            for candidate in group:
                score = 0
                pkg = candidate.get("package", "").lower()
                signature = candidate.get("signature", "").lower()
                
                # Higher score for security-relevant contexts
                if any(sec_ctx in pkg for sec_ctx in ['servlet', 'http', 'request', 'auth', 'sql', 'db']):
                    score += 10
                
                # Higher score for complex signatures
                param_count = signature.count(',') + 1 if '(' in signature else 0
                score += min(param_count, 5)  # Cap at 5 to avoid overweighting
                
                # Higher score for security-relevant signature patterns
                if any(pattern in signature for pattern in ['string', 'object', 'map', 'request', 'param']):
                    score += 5
                
                scored_candidates.append((score, candidate))
            
            # Sort by score and take top candidates (up to 2 per pattern to preserve some diversity)
            scored_candidates.sort(key=lambda x: x[0], reverse=True)
            
            # Take top 1-2 candidates depending on score distribution
            if len(scored_candidates) >= 2:
                top_score = scored_candidates[0][0]
                second_score = scored_candidates[1][0]
                
                if top_score - second_score <= 2:  # Close scores - keep both
                    final_deduplicated.extend([sc[1] for sc in scored_candidates[:2]])
                else:  # Clear winner - keep just the top one
                    final_deduplicated.append(scored_candidates[0][1])
            else:
                final_deduplicated.append(scored_candidates[0][1])
    
    print(f"    ==> Smart deduplication: {len(exact_deduplicated)} → {len(final_deduplicated)} candidates")
    
    return final_deduplicated

def process_api_candidates(project_name, api_candidates):
    """
    Process API candidates that have already been filtered by api_is_candidate.
    Following IRIS methodology: candidates are pre-filtered, so just apply final cleanup.
    """
    print(f"  ==> Processing {len(api_candidates)} pre-filtered API candidates for {project_name}")
    
    # Final smart deduplication step (IRIS also does this)
    final_candidates = smart_deduplicate_candidates(api_candidates)
    print(f"  ==> After deduplication: {len(final_candidates)} candidates")
    
    return final_candidates

def save_filtered_candidates(project_name, candidates):
    """
    Save filtered candidates to CSV and JSON files.
    Outputs to output/<project_name>/api_candidates/ directory.
    """
    project_output_dir = OUTPUT_DIR / project_name / "api_candidates"
    project_output_dir.mkdir(parents=True, exist_ok=True)
    
    # DEBUG: Check for duplicates before saving
    seen_signatures = set()
    duplicates_found = 0
    unique_candidates = []
    
    for candidate in candidates:
        signature_key = f"{candidate.get('package', '')}.{candidate.get('clazz', '')}.{candidate.get('func', '')}.{candidate.get('full_signature', '')}"
        if signature_key in seen_signatures:
            duplicates_found += 1
            print(f"    🔍 DEBUG: Found duplicate: {signature_key}")
        else:
            seen_signatures.add(signature_key)
            unique_candidates.append(candidate)
    
    if duplicates_found > 0:
        print(f"    ⚠️  WARNING: Found {duplicates_found} duplicates, saving {len(unique_candidates)} unique candidates")
        candidates_to_save = unique_candidates
    else:
        print(f"    ✅ No duplicates found, saving {len(candidates)} candidates")
        candidates_to_save = candidates
    
    # Save as CSV
    csv_path = project_output_dir / "filtered_api_candidates.csv"
    df = pd.DataFrame(candidates_to_save)
    df.to_csv(csv_path, index=False, encoding='utf-8')
    
    # Save as JSON
    json_path = project_output_dir / "filtered_api_candidates.json" 
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(candidates_to_save, f, indent=2, ensure_ascii=False)
    
    print(f"  ==> Saved {len(candidates_to_save)} filtered candidates to {csv_path} and {json_path}")
    
    return csv_path, json_path

def prepare_llm_prompts(candidates, cwe_type=None):
    """
    Prepare candidates for LLM labeling following IRIS format.
    IRIS format: package,clazz,func,full_signature (NO CWE context at this stage)
    """
    # Format candidates for LLM processing - IRIS style
    formatted_candidates = []
    
    for candidate in candidates:
        # Use IRIS column naming: package,clazz,func,full_signature
        formatted = {
            "package": candidate.get("package", ""),
            "clazz": candidate.get("class", ""),  # IRIS uses 'clazz' not 'class'
            "func": candidate.get("method", ""),   # IRIS uses 'func' not 'method'
            "full_signature": candidate.get("signature", "")  # IRIS uses 'full_signature'
        }
        formatted_candidates.append(formatted)
    
    return formatted_candidates

def main():
    """Main function to execute API candidate filtering."""
    parser = argparse.ArgumentParser(description='Filter API candidates for LLM labeling.')
    parser.add_argument('--project', type=str, default='all', 
                        help='Project name to filter candidates for (default: all)')
    parser.add_argument('--cwe', type=str, default=None,
                        help='CWE type context for filtering (optional)')
    
    args = parser.parse_args()
    
    try:
        from tqdm import tqdm
    except ImportError:
        print("tqdm is required for progress bars. Install it with 'pip install tqdm'.")
        tqdm = None
    
    try:
        print(f"PYSAST_ROOT: {PYSAST_ROOT}")
        print(f"OUTPUT_DIR: {OUTPUT_DIR}")
        
        check_directories()
        all_projects = discover_projects()
        
        print(f"Discovered projects: {[p.name for p in all_projects]}")
        
        # Filter projects if specific project is requested
        if args.project != 'all':
            all_projects = [p for p in all_projects if p.name == args.project]
            if not all_projects:
                print(f"No project found matching: {args.project}")
                print(f"Available projects: {[p.name for p in discover_projects()]}")
                return
        
        print(f"Processing {len(all_projects)} projects for API candidate filtering")
        
        total_filtered = 0
        
        projects_iter = tqdm(all_projects, desc="Filtering API candidates", unit="project") if tqdm else all_projects
        
        for project_dir in projects_iter:
            project_name = project_dir.name
            if tqdm:
                projects_iter.set_description(f"Processing {project_name}")
            else:
                print(f"Processing project: {project_name}")
            
            # Load API candidates from query results using IRIS methodology
            api_candidates = collect_invoked_external_apis(project_dir)
            
            if not api_candidates:
                print(f"  ==> No API candidates found for {project_name}")
                continue
            
            # Process the pre-filtered API candidates
            filtered_candidates = process_api_candidates(project_name, api_candidates)
            
            if filtered_candidates:
                # Prepare for LLM labeling
                llm_ready_candidates = prepare_llm_prompts(filtered_candidates, args.cwe)
                
                # Save filtered candidates
                csv_path, json_path = save_filtered_candidates(project_name, llm_ready_candidates)
                total_filtered += len(filtered_candidates)
            else:
                print(f"  ==> No candidates remaining after filtering for {project_name}")
        
        print(f"\nFiltering completed!")
        print(f"Total filtered candidates across all projects: {total_filtered}")
        print(f"Results saved in: {OUTPUT_DIR}/<project_name>/api_candidates/")
        print("Ready for LLM labeling stage.")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()