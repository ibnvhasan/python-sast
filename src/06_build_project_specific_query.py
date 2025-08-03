#!/usr/bin/env python3
"""
IRIS-Compatible CodeQL Query Generator

A production-grade tool for generating project-specific CodeQL queries from LLM labeling results.
Implements the IRIS methodology for automated security vulnerability detection in Python projects.

Author: Python SAST Team
License: MIT
Version: 2.0.0

Features:
- IRIS methodology compliance
- CodeQL .qll file generation (MySources.qll, MySinks.qll, MySummaries.qll)
- CodeQL model specification files (specs.model.yml)
- Run-specific directory support (gpt-4_0, gpt-4_1, etc.)
- Comprehensive validation and error handling
- Production logging and metrics

Usage:
    python 06_building_project_specific_query.py
    python 06_building_project_specific_query.py --list-projects
    python 06_building_project_specific_query.py --verbose
"""

import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


# Configure production logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Project configuration
PYSAST_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PYSAST_ROOT / "output"


@dataclass
class LLMRun:
    """Represents a single LLM run with extracted metadata."""
    project_name: str
    llm_name: str
    run_id: str
    run_dir: Path
    
    @property
    def output_dir(self) -> Path:
        """Get the output directory for this LLM run."""
        return self.run_dir / "project_queries"


@dataclass
class ProjectStats:
    """Statistics for generated CodeQL queries."""
    sources: int = 0
    sinks: int = 0
    taint_propagators: int = 0
    total_apis: int = 0
    
    @property
    def summary(self) -> str:
        return f"Sources: {self.sources}, Sinks: {self.sinks}, Propagators: {self.taint_propagators}, Total: {self.total_apis}"


@dataclass
class CodeQLContent:
    """Container for generated CodeQL content."""
    sources: str
    sinks: str
    summaries: str
    model_spec: str


class CodeQLTemplates:
    """CodeQL template definitions following IRIS patterns."""
    
    SOURCE_TEMPLATE = '''import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isGPTDetectedSource(DataFlow::Node src) {{
    exists(Call call |
        src.asExpr() = call and
        (
            {conditions}
        )
    )
}}'''

    SINK_TEMPLATE = '''import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isGPTDetectedSink(DataFlow::Node snk) {{
    exists(Call call |
        (
            {conditions}
        ) and
        snk.asExpr() = call
    )
}}'''

    SUMMARY_TEMPLATE = '''import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isGPTDetectedStep(DataFlow::Node pred, DataFlow::Node succ) {{
    exists(Call call |
        pred.asExpr() = call.getArg(0) and
        succ.asExpr() = call and
        (
            {conditions}
        )
    )
}}'''

    @staticmethod
    def build_condition(api: Dict[str, Any]) -> Optional[str]:
        """Build a single CodeQL condition from API data."""
        method = api.get('method', '').strip()
        clazz = api.get('class', '').strip()
        
        if not method:
            return None
            
        if clazz and clazz != method:  # Avoid redundant class.method patterns
            return f'(call.getFunc().(Attribute).getName() = "{method}" and call.getFunc().(Attribute).getObject().pointsTo().getClass().getName() = "{clazz}")'
        else:
            return f'call.getFunc().(Name).getId() = "{method}"'


class IRISQueryGenerator:
    """
    IRIS-compatible CodeQL query generator.
    
    Implements the complete IRIS methodology for generating project-specific
    CodeQL queries from LLM-labeled API data for a single LLM run.
    """
    
    def __init__(self, llm_run: LLMRun):
        """
        Initialize the query generator for a specific LLM run.
        
        Args:
            llm_run: LLMRun object containing project and run metadata
        """
        self.llm_run = llm_run
        self.run_dir = llm_run.run_dir
        self.queries_dir = llm_run.output_dir
        
        # Ensure output directory exists
        self.queries_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized IRIS generator for {llm_run.project_name} [{llm_run.llm_name}_{llm_run.run_id}]")
        logger.info(f"Input directory: {self.run_dir}")
        logger.info(f"Output directory: {self.queries_dir}")
    
    def load_llm_results(self) -> List[Dict[str, Any]]:
        """Load and parse LLM labeling results."""
        results_file = self.run_dir / "final_results.json"
        
        if not results_file.exists():
            raise FileNotFoundError(f"Results file not found: {results_file}")
        
        logger.info(f"Loading LLM results from: {results_file}")
        
        try:
            with open(results_file, 'r') as f:
                data = json.load(f)
            
            results = []
            for batch in data.get('results', []):
                results.extend(batch.get('parsed_results', []))
            
            logger.info(f"Loaded {len(results)} API labels from {self.llm_run.llm_name}_{self.llm_run.run_id}")
            return results
            
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid results file format: {e}")
    
    def categorize_apis(self, apis: List[Dict[str, Any]]) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """Categorize APIs into sources, sinks, and taint propagators."""
        sources, sinks, propagators = [], [], []
        
        for api in apis:
            api_type = api.get('type', '').lower()
            
            if api_type == 'source':
                sources.append(api)
            elif api_type == 'sink':
                sinks.append(api)
            elif api_type in ['taint-propagator', 'taint_propagator', 'propagator']:
                propagators.append(api)
            else:
                logger.warning(f"Unknown API type '{api_type}' for {api.get('signature', 'unknown')}")
        
        logger.info(f"Categorized APIs: {len(sources)} sources, {len(sinks)} sinks, {len(propagators)} propagators")
        return sources, sinks, propagators
    
    def _build_conditions(self, apis: List[Dict[str, Any]]) -> str:
        """Build CodeQL conditions from API list."""
        if not apis:
            return "none()"
        
        conditions = []
        for api in apis:
            condition = CodeQLTemplates.build_condition(api)
            if condition:
                conditions.append(condition)
        
        return " or\n            ".join(conditions) if conditions else "none()"
    
    def generate_codeql_content(self, sources: List[Dict], sinks: List[Dict], propagators: List[Dict]) -> CodeQLContent:
        """Generate all CodeQL content."""
        logger.info("Generating CodeQL content...")
        
        source_conditions = self._build_conditions(sources)
        sink_conditions = self._build_conditions(sinks)
        summary_conditions = self._build_conditions(propagators)
        
        sources_content = CodeQLTemplates.SOURCE_TEMPLATE.format(conditions=source_conditions)
        sinks_content = CodeQLTemplates.SINK_TEMPLATE.format(conditions=sink_conditions)
        summaries_content = CodeQLTemplates.SUMMARY_TEMPLATE.format(conditions=summary_conditions)
        
        # Generate model specification
        model_spec = self._generate_model_spec(sources, sinks, propagators)
        
        return CodeQLContent(
            sources=sources_content,
            sinks=sinks_content,
            summaries=summaries_content,
            model_spec=model_spec
        )
    
    def _generate_model_spec(self, sources: List[Dict], sinks: List[Dict], propagators: List[Dict]) -> str:
        """Generate IRIS-compatible model specification YAML."""
        logger.info("Generating model specification...")
        
        def format_model_entry(api: Dict[str, Any], entry_type: str) -> str:
            """Format a single model entry."""
            package = api.get('package', 'python.builtin')
            clazz = api.get('class', api.get('method', 'Unknown'))
            method = api.get('method', '')
            signature = api.get('signature', f"{package}.{method}")
            
            if entry_type == 'source':
                return f'      - ["{package}", "{clazz}", True, "{method}", "", "", "ReturnValue", "{self.llm_run.project_name}", "manual"]'
            else:  # sink
                return f'      - ["{package}", "{clazz}", True, "{method}", "", "", "Argument[0..10]", "{self.llm_run.project_name}", "manual"]'
        
        # Build model entries
        source_entries = [format_model_entry(api, 'source') for api in sources[:10]]  # Limit for readability
        sink_entries = [format_model_entry(api, 'sink') for api in sinks[:10]]
        
        timestamp = datetime.now().isoformat()
        
        return f'''# CodeQL Model Specification
# Generated for: {self.llm_run.project_name}
# LLM: {self.llm_run.llm_name}
# Run ID: {self.llm_run.run_id}
# Generated: {timestamp}
# 
# This file defines source and sink models for CodeQL analysis
# following the IRIS methodology for automated vulnerability detection.

extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: sinkModel
    data:
{chr(10).join(sink_entries)}
  - addsTo:
      pack: codeql/python-all
      extensible: sourceModel
    data:
{chr(10).join(source_entries)}

# Statistics:
# - Sources: {len(sources)}
# - Sinks: {len(sinks)}
# - Taint Propagators: {len(propagators)}
# - Total APIs: {len(sources) + len(sinks) + len(propagators)}
'''
    
    def save_files(self, content: CodeQLContent, stats: ProjectStats) -> None:
        """Save all generated files."""
        logger.info("Saving generated files...")
        
        files = [
            ("MySources.qll", content.sources),
            ("MySinks.qll", content.sinks),
            ("MySummaries.qll", content.summaries),
            ("specs.model.yml", content.model_spec)
        ]
        
        for filename, file_content in files:
            filepath = self.queries_dir / filename
            with open(filepath, 'w') as f:
                f.write(file_content)
            logger.info(f"Saved: {filepath}")
        
        # Save generation metadata
        metadata = {
            "project": self.llm_run.project_name,
            "llm_name": self.llm_run.llm_name,
            "run_id": self.llm_run.run_id,
            "generated_at": datetime.now().isoformat(),
            "statistics": {
                "sources": stats.sources,
                "sinks": stats.sinks,
                "taint_propagators": stats.taint_propagators,
                "total_apis": stats.total_apis
            },
            "files_generated": [f[0] for f in files]
        }
        
        metadata_file = self.queries_dir / "generation_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"Saved metadata: {metadata_file}")
    
    def generate(self) -> bool:
        """Main generation workflow."""
        try:
            logger.info(f"Starting CodeQL query generation for {self.llm_run.project_name} [{self.llm_run.llm_name}_{self.llm_run.run_id}]")
            
            # Load and process data
            apis = self.load_llm_results()
            if not apis:
                logger.error("No API data found")
                return False
            
            sources, sinks, propagators = self.categorize_apis(apis)
            stats = ProjectStats(
                sources=len(sources),
                sinks=len(sinks),
                taint_propagators=len(propagators),
                total_apis=len(apis)
            )
            
            # Generate content
            content = self.generate_codeql_content(sources, sinks, propagators)
            
            # Save files
            self.save_files(content, stats)
            
            logger.info(f"✅ Generation completed successfully!")
            logger.info(f"📊 {stats.summary}")
            logger.info(f"📁 Output: {self.queries_dir}")
            
            return True
            
        except Exception as e:
            logger.error(f"Generation failed: {e}")
            return False


def discover_llm_runs() -> List[LLMRun]:
    """
    Discover all available LLM runs across all projects.
    
    Returns:
        List of LLMRun objects for all valid runs found
    """
    llm_runs = []
    
    if not OUTPUT_DIR.exists():
        logger.warning(f"Output directory not found: {OUTPUT_DIR}")
        return llm_runs
    
    for project_dir in OUTPUT_DIR.iterdir():
        if not project_dir.is_dir():
            continue
            
        project_name = project_dir.name
        labelling_dir = project_dir / "api_labelling"
        
        if not labelling_dir.exists():
            logger.debug(f"No api_labelling directory for project: {project_name}")
            continue
        
        # Find LLM run directories
        for run_dir in labelling_dir.iterdir():
            if not run_dir.is_dir():
                continue
                
            # Parse LLM name and run ID from directory name (e.g., "gpt-4_0")
            dir_name = run_dir.name
            if '_' not in dir_name:
                logger.debug(f"Invalid run directory format: {dir_name}")
                continue
                
            try:
                llm_name, run_id = dir_name.rsplit('_', 1)
                
                # Validate that final_results.json exists
                results_file = run_dir / "final_results.json"
                if not results_file.exists():
                    logger.debug(f"No final_results.json in {dir_name}")
                    continue
                
                llm_run = LLMRun(
                    project_name=project_name,
                    llm_name=llm_name,
                    run_id=run_id,
                    run_dir=run_dir
                )
                llm_runs.append(llm_run)
                
            except (ValueError, IndexError) as e:
                logger.debug(f"Failed to parse run directory {dir_name}: {e}")
                continue
    
    logger.info(f"Discovered {len(llm_runs)} LLM runs across {len(set(run.project_name for run in llm_runs))} projects")
    return llm_runs


def generate_all_queries() -> bool:
    """
    Generate CodeQL queries for all discovered LLM runs.
    
    Returns:
        True if all generations succeeded, False otherwise
    """
    llm_runs = discover_llm_runs()
    
    if not llm_runs:
        logger.error("No LLM runs found. Make sure projects have been labeled with LLMs.")
        return False
    
    logger.info(f"🚀 Starting batch generation for {len(llm_runs)} LLM runs")
    
    success_count = 0
    total_stats = ProjectStats()
    
    for llm_run in llm_runs:
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing: {llm_run.project_name} [{llm_run.llm_name}_{llm_run.run_id}]")
        logger.info(f"{'='*60}")
        
        try:
            generator = IRISQueryGenerator(llm_run)
            if generator.generate():
                success_count += 1
                # TODO: Accumulate stats if needed
            else:
                logger.error(f"Failed to generate queries for {llm_run.project_name} [{llm_run.llm_name}_{llm_run.run_id}]")
                
        except Exception as e:
            logger.error(f"Error processing {llm_run.project_name} [{llm_run.llm_name}_{llm_run.run_id}]: {e}")
    
    logger.info(f"\n🎯 Batch generation completed!")
    logger.info(f"✅ Successful: {success_count}/{len(llm_runs)} runs")
    
    if success_count < len(llm_runs):
        logger.warning(f"❌ Failed: {len(llm_runs) - success_count} runs")
        return False
    
    return True


def list_available_runs() -> None:
    """List all projects and their available LLM runs."""
    print("📋 Available LLM runs with labeling results:\n")
    
    llm_runs = discover_llm_runs()
    
    if not llm_runs:
        print("❌ No LLM runs found")
        return
    
    # Group by project
    projects = {}
    for run in llm_runs:
        if run.project_name not in projects:
            projects[run.project_name] = []
        projects[run.project_name].append(run)
    
    for project_name, runs in sorted(projects.items()):
        print(f"   📁 {project_name}")
        for run in sorted(runs, key=lambda x: (x.llm_name, x.run_id)):
            results_file = run.run_dir / "final_results.json"
            try:
                with open(results_file, 'r') as f:
                    data = json.load(f)
                api_count = sum(len(batch.get('parsed_results', [])) for batch in data.get('results', []))
                print(f"      ✅ {run.llm_name}_{run.run_id} ({api_count} APIs)")
            except:
                print(f"      ❌ {run.llm_name}_{run.run_id} (invalid results)")
        print()


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate CodeQL queries from LLM labeling results (IRIS methodology)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Generate queries for all LLM runs
  %(prog)s --list-runs        # List available LLM runs
  %(prog)s --verbose          # Enable verbose logging
        """
    )
    
    parser.add_argument('--list-runs', action='store_true',
                       help='List available LLM runs with results')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.list_runs:
        list_available_runs()
        return
    
    # Generate queries for all runs
    success = generate_all_queries()
    
    if success:
        print(f"\n🎯 Next steps:")
        print(f"   1. Review generated files in project_queries/ directories")
        print(f"   2. Validate CodeQL syntax with: codeql query format")
        print(f"   3. Test queries against the projects' CodeQL databases")
        print(f"   4. Integrate specs.model.yml files into your CodeQL analysis workflow")
    else:
        print(f"\n❌ Some generations failed. Check logs for details.")
        exit(1)


if __name__ == "__main__":
    main()