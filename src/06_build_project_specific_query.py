"""
This script aggregates raw responses from large language model (LLM) runs and
converts them into Python CodeQL configuration files.  For each project in the
specified root directory it searches for `api_labelling` folders.  Under
`api_labelling` it expects one or more model/run directories such as
`gpt-4_run_0` or `qwen2.5-coder-1.5b_run_0`.  Each run directory contains either:
- `labeled_apis.json` file (new structure from 05_api_labelling.py)
- `results` folder with `batch_*_raw_response.txt` files (legacy structure)

The script performs three main tasks for each run:

1. **Collect LLM output** – it reads either the `labeled_apis.json` file directly
   or aggregates and parses `*_raw_response.txt` files from the `results` directory,
   extracts any JSON objects or arrays, and combines them into a single list.
   The aggregated list is deduplicated on the tuple of package, class,
   method, signature and type.  The combined list is then written to
   `labeled_apis.json` under the run directory (if not already present).

2. **Separate by label** – from the aggregated list it builds three
   sub‑lists based on the ``type`` field of each entry: `source`,
   `sink` and `taint-propagator`.

3. **Generate Python CodeQL library files** – for each run it creates a new
   subfolder named ``custom_codeql_library`` (if it does not already
   exist) inside the run directory.  In this folder it writes six files:
   ``MySources.qll``, ``MySinks.qll``, ``MySummaries.qll``,
   ``MyTaintedPathQuery.qll``, ``cwe-022wLLM.ql``, and ``specs.model.yml``.
   These files define Python CodeQL configuration classes and queries
   which extend the standard `TaintTracking::Configuration`. The main
   query file ``cwe-022wLLM.ql`` can be run directly against a CodeQL
   database to detect path injection vulnerabilities using the LLM-generated
   sources and sinks. The templates aim to mirror the behaviour of the
   IRIS pipeline while remaining self‑contained and Python-specific.

IRIS Integration:
This module can be called automatically after API labeling completes in 
05_api_labelling.py, or manually for specific projects. It follows the 
IRIS pattern of converting LLM-labeled APIs into executable CodeQL queries.

Usage:

```
# Process all projects in output directory
python 06_build_project_specific_query.py --root output

# Process specific project only
python 06_build_project_specific_query.py --project apache_airflow_cwe-22

# List available runs without processing
python 06_build_project_specific_query.py --list-runs
```

When run without the ``--root`` argument the script defaults to the
current working directory.  This is intentional so that the script can
be dropped into the same folder as the top‑level project directories
and run without additional arguments.

Integration with API Labeling:
The 05_api_labelling.py script automatically calls build_project_specific_queries()
after completing API labeling, unless the --no-codeql flag is used.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from typing import List, Dict, Any, Tuple


def parse_raw_llm_output(raw_content: str) -> List[Dict[str, Any]]:
    """Extract JSON objects or arrays from a raw LLM response.

    The raw response files emitted by the IRIS pipeline often include
    markdown code fences, escaped newlines and comments.  This function
    removes common wrappers and attempts to locate a JSON array.  If an
    array is found it is parsed directly.  Otherwise each top level
    object delimited by braces is extracted.  Returns a list of
    dictionaries; invalid or unparsable content yields an empty list.

    Parameters
    ----------
    raw_content: str
        The contents of a ``*_raw_response.txt`` file.

    Returns
    -------
    List[Dict[str, Any]]
        A list of JSON objects extracted from the response.
    """
    # Remove leading/trailing whitespace and backtick fences
    data = raw_content
    # Strip code fences such as ```json ... ``` or ```
    data = re.sub(r"```json\s*", "", data, flags=re.IGNORECASE)
    data = re.sub(r"```", "", data)
    # Unescape single quotes and remove escaped newlines
    data = data.replace("\\'", "'")
    data = data.replace("\\n", "")
    data = data.replace("\\\n", "")
    # Remove line comments (// ...) which are invalid in JSON
    data = re.sub(r"//.*", "", data)
    # Collapse double quotes to avoid invalid escape sequences
    data = data.replace('""', '"')
    # First try to find a JSON array in the text
    array_matches = re.findall(r"\[[\s\S]*?\]", data)
    if array_matches:
        for match in array_matches:
            try:
                result = json.loads(match)
                if isinstance(result, list):
                    return result
            except Exception:
                continue
    # If no array was found, fall back to extracting individual objects
    object_matches = re.findall(r"\{[^\{\}]*\}", data)
    results: List[Dict[str, Any]] = []
    for obj_str in object_matches:
        try:
            obj = json.loads(obj_str)
            if isinstance(obj, dict):
                results.append(obj)
        except Exception:
            # Skip unparsable fragments
            continue
    return results


def aggregate_run_results(results_dir: str) -> List[Dict[str, Any]]:
    """Aggregate all JSON entries from LLM raw response files in a directory.

    Given a path to a ``results`` directory the function reads every
    ``*_raw_response.txt`` file, parses its contents via
    ``parse_raw_llm_output`` and concatenates the resulting lists.  It
    deduplicates entries based on the tuple (package, class, method,
    signature, type).

    Parameters
    ----------
    results_dir: str
        Path to the directory containing raw response files.

    Returns
    -------
    List[Dict[str, Any]]
        A deduplicated list of API labelling results.
    """
    aggregated: List[Dict[str, Any]] = []
    if not os.path.isdir(results_dir):
        return aggregated
    for filename in os.listdir(results_dir):
        if not filename.endswith("_raw_response.txt"):
            continue
        filepath = os.path.join(results_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
            entries = parse_raw_llm_output(raw)
            aggregated.extend(entries)
        except Exception:
            # If the file cannot be read or parsed, skip it silently
            continue
    # Deduplicate entries by package, class, method, signature and type
    seen: set[Tuple[str, str, str, str, str]] = set()
    deduped: List[Dict[str, Any]] = []
    for entry in aggregated:
        # Debug: check entry type
        if not isinstance(entry, dict):
            print(f"  ⚠️  Warning: Found non-dict entry: {type(entry)} = {entry}")
            continue
        # Ensure the entry has all required keys
        pkg = entry.get("package")
        cls = entry.get("class")
        method = entry.get("method")
        signature = entry.get("signature")
        typ = entry.get("type")
        key = (pkg, cls, method, signature, typ)
        if all(key) and key not in seen:
            seen.add(key)
            deduped.append(entry)
    return deduped


def build_sources_qll(entries: List[Dict[str, Any]]) -> str:
    """Create the contents of ``MySources.qll`` from a list of source entries.

    The generated QLL file defines a predicate isLLMDetectedSource that identifies
    API calls classified as sources by the LLM. Uses the new approach with 
    exists clauses for each labeled API.

    Parameters
    ----------
    entries: list of dict
        A list of API descriptions classified as sources by the LLM.
        Expected format: {"module": "module.name", "function": "func_name", ...}

    Returns
    -------
    str
        The complete contents of a QLL file.
    """
    conditions: List[str] = []
    
    for i, api in enumerate(entries):
        if not isinstance(api, dict):
            print(f"  ⚠️  Warning: Non-dict entry at index {i}: {type(api)} = {api}")
            continue
            
        module_name = api.get("module", "")
        func_name = api.get("function", "")
        
        if not func_name:
            continue
            
        # Parse module and function for CodeQL matching
        if module_name and module_name != "":
            if "." in module_name:
                # Handle nested modules like airflow.utils.session
                module_parts = module_name.split(".")
                if len(module_parts) == 2:
                    # Simple case: module.submodule
                    cond = (f"exists(Call call | "
                           f"call.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = \"{module_parts[0]}\" and "
                           f"call.getFunc().(Attribute).getObject().(Attribute).getAttr() = \"{module_parts[1]}\" and "
                           f"call.getFunc().(Attribute).getAttr() = \"{func_name}\" and "
                           f"src.asCfgNode() = call)")
                else:
                    # Multiple levels: airflow.utils.session -> use the last two parts
                    base_module = ".".join(module_parts[:-1])
                    final_module = module_parts[-1]
                    cond = (f"exists(Call call | "
                           f"call.getFunc().(Attribute).getObject().(Attribute).getAttr() = \"{final_module}\" and "
                           f"call.getFunc().(Attribute).getAttr() = \"{func_name}\" and "
                           f"src.asCfgNode() = call)")
            else:
                # Single module name
                cond = (f"exists(Call call | "
                       f"call.getFunc().(Attribute).getObject().(Name).getId() = \"{module_name}\" and "
                       f"call.getFunc().(Attribute).getAttr() = \"{func_name}\" and "
                       f"src.asCfgNode() = call)")
        else:
            # Built-in function without module
            cond = (f"exists(Call call | "
                   f"call.getFunc().(Name).getId() = \"{func_name}\" and "
                   f"src.asCfgNode() = call)")
                   
        conditions.append(cond)
    
    body = "false" if not conditions else " or\n    ".join(conditions)
    
    qll = f"""import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ast.Call
import semmle.python.ast.Name
import semmle.python.ast.Attribute

predicate isLLMDetectedSource(DataFlow::Node src) {{
    {body}
}}
"""
    return qll


def build_sinks_qll(entries: List[Dict[str, Any]]) -> str:
    """Create the contents of ``MySinks.qll`` from a list of sink entries.

    The generated QLL file defines a predicate isLLMDetectedSink that identifies
    API calls classified as sinks by the LLM. Uses the new approach with 
    exists clauses for each labeled API and handles sink_args.

    Parameters
    ----------
    entries: list of dict
        A list of API descriptions classified as sinks by the LLM.
        Expected format: {"module": "module.name", "function": "func_name", "sink_args": [...]}

    Returns
    -------
    str
        The complete contents of a QLL file.
    """
    conditions: List[str] = []
    
    for i, api in enumerate(entries):
        if not isinstance(api, dict):
            print(f"  ⚠️  Warning: Non-dict entry in sinks at index {i}: {type(api)} = {api}")
            continue
            
        module_name = api.get("module", "")
        func_name = api.get("function", "")
        sink_args = api.get("sink_args", [])
        
        if not func_name:
            continue
            
        # Normalize sink_args to a list
        if isinstance(sink_args, str):
            sink_args = [sink_args]
        if not isinstance(sink_args, list):
            sink_args = []
            
        # Build call pattern
        if module_name and module_name != "":
            if "." in module_name:
                module_parts = module_name.split(".")
                if len(module_parts) == 2:
                    call_pattern = (f"call.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = \"{module_parts[0]}\" and "
                                   f"call.getFunc().(Attribute).getObject().(Attribute).getAttr() = \"{module_parts[1]}\" and "
                                   f"call.getFunc().(Attribute).getAttr() = \"{func_name}\"")
                else:
                    final_module = module_parts[-1]
                    call_pattern = (f"call.getFunc().(Attribute).getObject().(Attribute).getAttr() = \"{final_module}\" and "
                                   f"call.getFunc().(Attribute).getAttr() = \"{func_name}\"")
            else:
                call_pattern = (f"call.getFunc().(Attribute).getObject().(Name).getId() = \"{module_name}\" and "
                               f"call.getFunc().(Attribute).getAttr() = \"{func_name}\"")
        else:
            call_pattern = f"call.getFunc().(Name).getId() = \"{func_name}\""
            
        # Build argument conditions
        arg_conditions: List[str] = []
        for arg in sink_args:
            if isinstance(arg, str):
                arg = arg.strip()
                if arg.isdigit():
                    idx = int(arg)
                    arg_conditions.append(f"snk.asCfgNode() = call.getArg({idx})")
                elif arg.lower() in ['0', 'first', 'arg0']:
                    arg_conditions.append("snk.asCfgNode() = call.getArg(0)")
                elif arg.lower() in ['1', 'second', 'arg1']:
                    arg_conditions.append("snk.asCfgNode() = call.getArg(1)")
                elif arg.lower() in ['2', 'third', 'arg2']:
                    arg_conditions.append("snk.asCfgNode() = call.getArg(2)")
                    
        # Default to first argument if no sink_args specified
        if not arg_conditions:
            arg_conditions.append("snk.asCfgNode() = call.getArg(0)")
            
        arg_body = " or ".join(arg_conditions)
        cond = (f"exists(Call call | "
               f"{call_pattern} and "
               f"({arg_body}))")
               
        conditions.append(cond)
    
    body = "false" if not conditions else " or\n    ".join(conditions)
    
    qll = f"""import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ast.Call
import semmle.python.ast.Name
import semmle.python.ast.Attribute

predicate isLLMDetectedSink(DataFlow::Node snk) {{
    {body}
}}
"""
    return qll


def build_summaries_qll(entries: List[Dict[str, Any]]) -> str:
    """Create the contents of ``MySummaries.qll`` from taint‑propagator entries.

    The generated QLL file defines a predicate isLLMDetectedStep that identifies
    API calls classified as propagators by the LLM. Uses the new approach with 
    exists clauses for each labeled API.

    Parameters
    ----------
    entries: list of dict
        A list of API descriptions classified as taint‑propagators by the LLM.
        Expected format: {"module": "module.name", "function": "func_name", ...}

    Returns
    -------
    str
        The complete contents of a QLL file.
    """
    conditions: List[str] = []
    
    for i, api in enumerate(entries):
        if not isinstance(api, dict):
            print(f"  ⚠️  Warning: Non-dict entry in taint-propagators at index {i}: {type(api)} = {api}")
            continue
            
        module_name = api.get("module", "")
        func_name = api.get("function", "")
        
        if not func_name:
            continue
            
        # Build call pattern
        if module_name and module_name != "":
            if "." in module_name:
                module_parts = module_name.split(".")
                if len(module_parts) == 2:
                    call_pattern = (f"call.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = \"{module_parts[0]}\" and "
                                   f"call.getFunc().(Attribute).getObject().(Attribute).getAttr() = \"{module_parts[1]}\" and "
                                   f"call.getFunc().(Attribute).getAttr() = \"{func_name}\"")
                else:
                    final_module = module_parts[-1]
                    call_pattern = (f"call.getFunc().(Attribute).getObject().(Attribute).getAttr() = \"{final_module}\" and "
                                   f"call.getFunc().(Attribute).getAttr() = \"{func_name}\"")
            else:
                call_pattern = (f"call.getFunc().(Attribute).getObject().(Name).getId() = \"{module_name}\" and "
                               f"call.getFunc().(Attribute).getAttr() = \"{func_name}\"")
        else:
            call_pattern = f"call.getFunc().(Name).getId() = \"{func_name}\""
            
        cond = (f"exists(Call call | "
               f"(call.getArg(_) = prev.asCfgNode() or call.getFunc().(Attribute).getObject() = prev.asCfgNode()) and "
               f"{call_pattern} and "
               f"call = next.asCfgNode())")
               
        conditions.append(cond)
    
    body = "false" if not conditions else " or\n    ".join(conditions)
    
    qll = f"""import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ast.Call
import semmle.python.ast.Name
import semmle.python.ast.Attribute

predicate isLLMDetectedStep(DataFlow::Node prev, DataFlow::Node next) {{
    {body}
}}
"""
    return qll


def build_tainted_path_query_qll() -> str:
    """Create the contents of ``MyTaintedPathQuery.qll`` for Python path injection detection.

    This creates a comprehensive taint-tracking configuration that combines
    the generated sources, sinks, and taint propagators into multiple
    configurations for detecting path injection vulnerabilities.

    Returns
    -------
    str
        The complete contents of MyTaintedPathQuery.qll file.
    """
    qll = """/** Provides dataflow configurations for tainted path queries. */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.PathInjectionQuery
import semmle.python.Expr
import semmle.python.ast.Call
import semmle.python.ast.Name
import semmle.python.ast.Attribute
import MySources
import MySinks
import MySummaries

/**
 * A taint-tracking configuration for tracking flow from LLM-detected sources to LLM-detected sinks.
 */
module MyTaintedPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isLLMDetectedSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isLLMDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    // Add common sanitizers for path injection
    exists(Call call |
      call.getFunc().(Name).getId() in ["basename", "dirname", "normpath", "abspath"] and
      sanitizer.asCfgNode() = call
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isLLMDetectedStep(n1, n2)
  }
}

/** Tracks flow from LLM-detected sources to LLM-detected sinks. */
module MyTaintedPathFlow = TaintTracking::Global<MyTaintedPathConfig>;


/**
 * A taint-tracking configuration using only LLM-detected sinks with standard sources.
 */
module MyTaintedPathSinksOnlyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Use standard Python sources (user input, HTTP requests, etc.)
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    isLLMDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    exists(Call call |
      call.getFunc().(Name).getId() in ["basename", "dirname", "normpath", "abspath"] and
      sanitizer.asCfgNode() = call
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    // Use standard taint steps
    TaintTracking::defaultAdditionalTaintStep(n1, n2)
  }
}

/** Tracks flow from standard sources to LLM-detected sinks. */
module MyTaintedPathFlowSinksOnly = TaintTracking::Global<MyTaintedPathSinksOnlyConfig>;


/**
 * A taint-tracking configuration using only LLM-detected sources with standard sinks.
 */
module MyTaintedPathSourcesOnlyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isLLMDetectedSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    // Use standard Python path injection sinks
    exists(Call call |
      call.getFunc().(Name).getId() in ["open", "read", "write"] and
      sink.asCfgNode() = call.getArg(0)
    ) or
    exists(Call call |
      call.getFunc().(Attribute).getAttr() in ["open", "read", "write"] and
      sink.asCfgNode() = call.getArg(0)
    )
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    exists(Call call |
      call.getFunc().(Name).getId() in ["basename", "dirname", "normpath", "abspath"] and
      sanitizer.asCfgNode() = call
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    TaintTracking::defaultAdditionalTaintStep(n1, n2)
  }
}

/** Tracks flow from LLM-detected sources to standard sinks. */
module MyTaintedPathFlowSourcesOnly = TaintTracking::Global<MyTaintedPathSourcesOnlyConfig>;
"""
    return qll


def build_cwe_022_query() -> str:
    """Create the contents of ``cwe-022wLLM.ql`` for Python path injection detection.

    This creates the main query file that will be run against the CodeQL database
    to detect path injection vulnerabilities using the LLM-generated sources and sinks.

    Returns
    -------
    str
        The complete contents of cwe-022wLLM.ql file.
    """
    qll = """/**
 * @name Uncontrolled data used in path expression
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id python/my-path-injection
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.Expr
import semmle.python.ast.Call
import semmle.python.ast.Name
import semmle.python.ast.Attribute
import MyTaintedPathQuery
import MyTaintedPathFlow::PathGraph

/**
 * Gets the data-flow node at which to report a path ending at `sink`.
 *
 * For Python, we report directly at the sink since there's no equivalent
 * to Java's PathCreation concept.
 */
DataFlow::Node getReportingNode(DataFlow::Node sink) {
  MyTaintedPathFlow::flowTo(sink) and
  result = sink
}

bindingset[src]
string sourceType(DataFlow::Node src) {
  if exists(Parameter p | src.asParameter() = p)
  then result = "user-provided value as function parameter"
  else result = "user-provided value from LLM-detected source"
}

from
  MyTaintedPathFlow::PathNode source, MyTaintedPathFlow::PathNode sink
where
  MyTaintedPathFlow::flowPath(source, sink)
select
  getReportingNode(sink.getNode()),
  source,
  sink,
  "This path depends on a $@.",
  source.getNode(),
  sourceType(source.getNode())
"""
    return qll


def build_specs_model_yml(sources: List[Dict[str, Any]], sinks: List[Dict[str, Any]], project_name: str = "unknown-project") -> str:
    """Create the contents of ``specs.model.yml`` for Python CodeQL model extensions.

    This creates a YAML file that defines CodeQL model extensions for Python,
    adding the LLM-detected sources and sinks as external models that can be
    recognized by CodeQL's dataflow analysis.

    Parameters
    ----------
    sources: list of dict
        A list of API descriptions classified as sources by the LLM.
    sinks: list of dict
        A list of API descriptions classified as sinks by the LLM.

    Returns
    -------
    str
        The complete contents of specs.model.yml file.
    """
    # Build sink model entries in the correct format: [package, class, subtypes, method, signature, ext, input, kind, provenance]
    sink_data = []
    for api in sinks:
        if not isinstance(api, dict):
            continue
        package = api.get("package", "")
        clazz = api.get("class", "")
        method = api.get("method", "")
        if not method:
            continue
        
        # Get sink arguments, default to first argument
        sink_args = api.get("sink_args", ["0"])
        if isinstance(sink_args, str):
            sink_args = [sink_args]
        if not isinstance(sink_args, list):
            sink_args = ["0"]
        
        # Convert argument specifications to CodeQL format
        for arg in sink_args:
            if isinstance(arg, str):
                arg = arg.strip()
                if arg.lower() == "this":
                    arg_spec = "Argument[self]"
                elif arg.isdigit():
                    arg_spec = f"Argument[{arg}]"
                elif arg.startswith('arg') and arg[3:].isdigit():
                    idx = int(arg[3:])
                    arg_spec = f"Argument[{idx}]"
                elif arg.startswith('p') and arg[1:].isdigit():
                    idx = int(arg[1:])
                    arg_spec = f"Argument[{idx}]"
                else:
                    arg_spec = "Argument[0]"  # Default fallback
            else:
                arg_spec = "Argument[0]"
            
            # Format: [package, class, subtypes, method, signature, ext, input, kind, provenance]
            sink_data.append([
                package if package else "",
                clazz if clazz else "",
                True,
                method,
                "",
                "",
                arg_spec,
                project_name,
                "manual"
            ])
    
    # Build source model entries in the correct format: [package, class, subtypes, method, signature, ext, output, kind, provenance]
    source_data = []
    for api in sources:
        if not isinstance(api, dict):
            continue
        package = api.get("package", "")
        clazz = api.get("class", "")
        method = api.get("method", "")
        if not method:
            continue
        
        # Format: [package, class, subtypes, method, signature, ext, output, kind, provenance]
        source_data.append([
            package if package else "",
            clazz if clazz else "",
            True,
            method,
            "",
            "",
            "ReturnValue",
            project_name,
            "manual"
        ])
    
    # Build YAML content manually to match the exact format from the example
    yaml_lines = ["extensions:"]
    
    # Add sink models if we have any
    if sink_data:
        yaml_lines.extend([
            "  - addsTo:",
            "      pack: codeql/python-all",
            "      extensible: sinkModel",
            "    data:"
        ])
        for entry in sink_data:
            yaml_lines.append(f"      - {entry}")
    
    # Add source models if we have any
    if source_data:
        yaml_lines.extend([
            "  - addsTo:",
            "      pack: codeql/python-all",
            "      extensible: sourceModel",
            "    data:"
        ])
        for entry in source_data:
            yaml_lines.append(f"      - {entry}")
    
    return "\n".join(yaml_lines) + "\n"


def process_run(run_path: str) -> None:
    """Process a single LLM run directory.

    This function reads either the labeled_apis.json file (new structure) or
    aggregates raw response files (legacy structure) and generates the CodeQL library files.

    Parameters
    ----------
    run_path: str
        The filesystem path to a run directory (e.g. ``.../api_labelling/gpt-4_run_0``).
    """
    labeled_apis_path = os.path.join(run_path, "labeled_apis.json")
    results_dir = os.path.join(run_path, "results")
    
    # Try new structure first (labeled_apis.json)
    if os.path.exists(labeled_apis_path):
        try:
            with open(labeled_apis_path, "r", encoding="utf-8") as f:
                aggregated = json.load(f)
            print(f"  📄 Loaded {len(aggregated)} labeled APIs from labeled_apis.json")
        except Exception as e:
            print(f"  ❌ Failed to read labeled_apis.json: {e}")
            return
    # Fall back to legacy structure (raw response files)
    elif os.path.isdir(results_dir):
        print(f"  📁 Processing legacy structure - aggregating raw response files from results/")
        aggregated = aggregate_run_results(results_dir)
        if not aggregated:
            print(f"  ⚠️  No valid responses found in results directory")
            return
        print(f"  📄 Aggregated {len(aggregated)} entries from raw response files")
        
        # Save aggregated results for future runs
        try:
            with open(labeled_apis_path, "w", encoding="utf-8") as f:
                json.dump(aggregated, f, indent=2, ensure_ascii=False)
            print(f"  � Saved aggregated results to labeled_apis.json")
        except Exception as e:
            print(f"  ⚠️  Failed to save aggregated results: {e}")
    else:
        print(f"  ❌ No labeled_apis.json or results directory found in {run_path}")
        return
    
    # Split entries by type
    sources = [e for e in aggregated if e.get("type") == "source"]
    sinks = [e for e in aggregated if e.get("type") == "sink"]
    propagators = [e for e in aggregated if e.get("type") in ["propagator", "taint-propagator"]]
    
    print(f"  📊 Found: {len(sources)} sources, {len(sinks)} sinks, {len(propagators)} propagators")
    
    # Create output directory
    out_dir = os.path.join(run_path, "custom_codeql_library")
    os.makedirs(out_dir, exist_ok=True)
    
    # Extract project name from the run path
    # Handle both legacy and new directory structures:
    # Legacy: .../output/project_name/api_labelling/model_run/
    # New: .../output/project_name/model_run/
    if "/api_labelling/" in run_path:
        # Legacy structure
        project_name = os.path.basename(os.path.dirname(os.path.dirname(run_path)))
    else:
        # New structure
        project_name = os.path.basename(os.path.dirname(run_path))
    
    # Build and write QLL files
    try:
        src_qll = build_sources_qll(sources)
        sink_qll = build_sinks_qll(sinks)
        summaries_qll = build_summaries_qll(propagators)
        tainted_path_qll = build_tainted_path_query_qll()
        cwe_022_qll = build_cwe_022_query()
        specs_model_yml = build_specs_model_yml(sources, sinks, project_name)
        
        with open(os.path.join(out_dir, "MySources.qll"), "w", encoding="utf-8") as f:
            f.write(src_qll)
        with open(os.path.join(out_dir, "MySinks.qll"), "w", encoding="utf-8") as f:
            f.write(sink_qll)
        with open(os.path.join(out_dir, "MySummaries.qll"), "w", encoding="utf-8") as f:
            f.write(summaries_qll)
        with open(os.path.join(out_dir, "MyTaintedPathQuery.qll"), "w", encoding="utf-8") as f:
            f.write(tainted_path_qll)
        with open(os.path.join(out_dir, "cwe-022wLLM.ql"), "w", encoding="utf-8") as f:
            f.write(cwe_022_qll)
        with open(os.path.join(out_dir, "specs.model.yml"), "w", encoding="utf-8") as f:
            f.write(specs_model_yml)
        
        # Generate qlpack.yml file
        qlpack_yml = f"""name: {project_name}-llm-queries
version: 1.0.0
description: LLM-generated Python queries for {project_name} SAST analysis
dependencies:
  codeql/python-all: "*"
"""
        with open(os.path.join(out_dir, "qlpack.yml"), "w", encoding="utf-8") as f:
            f.write(qlpack_yml)
        
        # Run codeql pack install
        try:
            import subprocess
            result = subprocess.run(
                ["codeql", "pack", "install"],
                cwd=out_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                print(f"      - qlpack.yml (CodeQL pack configuration)")
                print(f"      - ✅ codeql pack install completed successfully")
            else:
                print(f"      - qlpack.yml (CodeQL pack configuration)")
                print(f"      - ⚠️  codeql pack install failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(f"      - qlpack.yml (CodeQL pack configuration)")
            print(f"      - ⚠️  codeql pack install timed out")
        except FileNotFoundError:
            print(f"      - qlpack.yml (CodeQL pack configuration)")
            print(f"      - ⚠️  codeql command not found - install CodeQL CLI")
        except Exception as e:
            print(f"      - qlpack.yml (CodeQL pack configuration)")
            print(f"      - ⚠️  codeql pack install error: {e}")
        
        print(f"  ✅ Generated Python CodeQL libraries and query files in custom_codeql_library/")
        print(f"      - MySources.qll ({len(sources)} sources)")
        print(f"      - MySinks.qll ({len(sinks)} sinks)")
        print(f"      - MySummaries.qll ({len(propagators)} propagators)")
        print(f"      - MyTaintedPathQuery.qll (taint-tracking configurations)")
        print(f"      - cwe-022wLLM.ql (main query for path injection detection)")
        print(f"      - specs.model.yml (CodeQL model extensions)")
    except Exception as e:
        print(f"  ❌ Failed to generate CodeQL libraries: {e}")
        import traceback
        traceback.print_exc()


def find_run_directories(root: str) -> List[str]:
    """Locate all LLM run directories under a given root.

    A run directory is defined as any subdirectory of the form
    ``*/api_labelling/<run>`` where ``<run>`` contains a ``results``
    subdirectory.  This helper walks the directory tree beneath
    ``root`` and collects such paths.

    Parameters
    ----------
    root: str
        The path from which to start searching.

    Returns
    -------
    List[str]
        A list of paths to run directories.
    """
    run_paths: List[str] = []
    if not os.path.isdir(root):
        return run_paths
    
    for project_name in os.listdir(root):
        project_path = os.path.join(root, project_name)
        if not os.path.isdir(project_path):
            continue
        
        # Check if this project has api_labelling directory (legacy structure)
        api_labelling_path = os.path.join(project_path, "api_labelling")
        if os.path.isdir(api_labelling_path):
            # Look for run directories inside api_labelling
            for run_name in os.listdir(api_labelling_path):
                run_path = os.path.join(api_labelling_path, run_name)
                if not os.path.isdir(run_path):
                    continue
                
                # Check if it has labeled_apis.json file
                labeled_apis_path = os.path.join(run_path, "labeled_apis.json")
                if os.path.exists(labeled_apis_path):
                    run_paths.append(run_path)
        
        # Also check for run directories directly under project (new structure)
        for item_name in os.listdir(project_path):
            item_path = os.path.join(project_path, item_name)
            if not os.path.isdir(item_path):
                continue
            
            # Skip known non-run directories
            if item_name in ['api_candidates', 'api_labelling', 'fetch_apis', 'project-sources']:
                continue
                
            # Check if this looks like a run directory (has labeled_apis.json)
            labeled_apis_path = os.path.join(item_path, "labeled_apis.json")
            if os.path.exists(labeled_apis_path):
                run_paths.append(item_path)
    return run_paths


def build_project_specific_queries(project_name: str, root: str = "output") -> bool:
    """Build project-specific CodeQL queries from API labelling results.
    
    This function locates API labelling results for a specific project and generates
    the corresponding CodeQL query files (sources.qll, sinks.qll, etc.) following
    the IRIS pattern.
    
    Args:
        project_name: Name of the project to build queries for
        root: Root directory containing project folders (default: "output")
        
    Returns:
        bool: True if queries were successfully built, False otherwise
    """
    print(f"🔍 Building CodeQL queries for project: {project_name}")
    
    # Find project directory
    project_path = os.path.join(root, project_name)
    if not os.path.isdir(project_path):
        print(f"❌ Project directory not found: {project_path}")
        return False
    
    # Find API labelling directory (legacy structure)
    api_labelling_path = os.path.join(project_path, "api_labelling")
    
    # Find run directories with labeled results
    run_dirs = []
    
    # First, check legacy structure: project/api_labelling/run_dirs/
    if os.path.isdir(api_labelling_path):
        for run_name in os.listdir(api_labelling_path):
            run_path = os.path.join(api_labelling_path, run_name)
            if not os.path.isdir(run_path):
                continue
            
            # Check for labeled_apis.json (new structure) or results directory (old structure)
            labeled_apis_path = os.path.join(run_path, "labeled_apis.json")
            results_dir = os.path.join(run_path, "results")
            
            if os.path.exists(labeled_apis_path) or os.path.isdir(results_dir):
                run_dirs.append(run_path)
    
    # Second, check new structure: project/run_dirs/ (directly under project)
    for item_name in os.listdir(project_path):
        item_path = os.path.join(project_path, item_name)
        if not os.path.isdir(item_path):
            continue
        
        # Skip known non-run directories
        if item_name in ['api_candidates', 'api_labelling', 'fetch_apis', 'project-sources']:
            continue
            
        # Check if this looks like a run directory (has labeled_apis.json)
        labeled_apis_path = os.path.join(item_path, "labeled_apis.json")
        if os.path.exists(labeled_apis_path):
            run_dirs.append(item_path)
    
    if not run_dirs:
        print(f"❌ No LLM run directories found in {project_path}")
        print(f"💡 Expected structure: {project_name}/<model_run>/labeled_apis.json or {project_name}/api_labelling/<model_run>/labeled_apis.json")
        return False
    
    print(f"✅ Found {len(run_dirs)} LLM run directories for {project_name}:")
    for run_dir in run_dirs:
        run_name = os.path.basename(run_dir)
        print(f"   📁 {run_name}")
    
    print(f"\n🚀 Processing LLM runs for {project_name}...")
    processed_count = 0
    
    for run_path in run_dirs:
        try:
            process_run(run_path)
            processed_count += 1
            run_name = os.path.basename(run_path)
            print(f"✅ Processed {project_name}/{run_name}")
        except Exception as e:
            run_name = os.path.basename(run_path)
            print(f"❌ Failed to process {project_name}/{run_name}: {e}")
            import traceback
            traceback.print_exc()
    
    success = processed_count > 0
    if success:
        print(f"\n🎉 Completed! Processed {processed_count}/{len(run_dirs)} run directories for {project_name}.")
        print(f"📁 Generated Python CodeQL libraries in: {project_name}/api_labelling/*/custom_codeql_library/")
        print(f"📄 Files created: MySources.qll, MySinks.qll, MySummaries.qll, MyTaintedPathQuery.qll, cwe-022wLLM.ql, specs.model.yml, qlpack.yml")
    else:
        print(f"\n❌ Failed to process any runs for {project_name}")
    
    return success


def main(root: str) -> None:
    """Main function to process all LLM run directories."""
    print(f"🔍 Searching for LLM run directories in: {root}")
    
    run_dirs = find_run_directories(root)
    if not run_dirs:
        print(f"❌ No LLM run directories found under {root}")
        print(f"💡 Expected structure: <project>/api_labelling/<model_run>/results/")
        print(f"💡 Looking for directories with *_raw_response.txt files")
        return
    
    print(f"✅ Found {len(run_dirs)} LLM run directories:")
    for run_dir in run_dirs:
        project_name = os.path.basename(os.path.dirname(os.path.dirname(run_dir)))
        run_name = os.path.basename(run_dir)
        print(f"   📁 {project_name}/{run_name}")
    
    print(f"\n🚀 Processing LLM runs...")
    processed_count = 0
    
    for run_path in run_dirs:
        try:
            process_run(run_path)
            processed_count += 1
            project_name = os.path.basename(os.path.dirname(os.path.dirname(run_path)))
            run_name = os.path.basename(run_path)
            print(f"✅ Processed {project_name}/{run_name}")
        except Exception as e:
            project_name = os.path.basename(os.path.dirname(os.path.dirname(run_path)))
            run_name = os.path.basename(run_path)
            print(f"❌ Failed to process {project_name}/{run_name}: {e}")
    
    print(f"\n🎉 Completed! Processed {processed_count}/{len(run_dirs)} run directories.")
    if processed_count > 0:
        print(f"📁 Generated Python CodeQL libraries in: */api_labelling/*/custom_codeql_library/")
        print(f"📄 Files created: MySources.qll, MySinks.qll, MySummaries.qll, MyTaintedPathQuery.qll, cwe-022wLLM.ql, specs.model.yml, qlpack.yml")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aggregate LLM outputs and generate Python CodeQL libraries.")
    parser.add_argument(
        "--root",
        type=str,
        default="output",
        help="Root directory containing the project folders. Defaults to 'output'.",
    )
    parser.add_argument(
        "--project",
        type=str,
        help="Specific project name to build queries for. If provided, only this project will be processed.",
    )
    parser.add_argument(
        "--list-runs",
        action="store_true",
        help="List available LLM runs without processing them."
    )
    args = parser.parse_args()
    
    if args.list_runs:
        print(f"🔍 Searching for LLM run directories in: {args.root}")
        run_dirs = find_run_directories(args.root)
        if not run_dirs:
            print(f"❌ No LLM run directories found under {args.root}")
        else:
            print(f"✅ Found {len(run_dirs)} LLM run directories:")
            for run_dir in run_dirs:
                project_name = os.path.basename(os.path.dirname(os.path.dirname(run_dir)))
                run_name = os.path.basename(run_dir)
                print(f"   📁 {project_name}/{run_name}")
    elif args.project:
        # Process specific project
        success = build_project_specific_queries(args.project, args.root)
        if not success:
            exit(1)
    else:
        # Process all projects
        main(args.root)