"""
API Candidate Labeling Module using Large Language Models

This module provides functionality to prompt LLMs (either online or offline from HuggingFace) 
to label collected candidate APIs from the previous stage. The candidate APIs are expected 
to be located in <project_root>/output/project_name/api_candidates/.

IRIS Methodology Implementation:
This implementation follows the IRIS framework which includes TWO stages of labeling:

Stage 1 (Implemented): API Candidate Labeling
- Labels API methods as source, sink, or taint-propagator
- Processes APIs in batches with CWE-specific context
- Uses vulnerability-specific prompts and examples

Stage 2 (Future): Function Parameters Labeling  
- Labels individual parameters within function calls
- Requires CodeQL queries to collect function parameters (NOT YET IMPLEMENTED)
- Would process parameter-level taint analysis

Note: Currently only Stage 1 is implemented. Stage 2 requires additional CodeQL queries
to collect function parameters from the codebase.

Key Features:
- Supports configurable number of API candidates to process (default: 300 APIs per project)
- Supports multiple LLM models:
  * GPT models: gpt-4.1, gpt-4, gpt-3.5 (requires OPENAI_API_KEY)
  * DeepSeek models: deepseek-r1-7b, deepseekcoder-33b, deepseekcoder-7b, deepseekcoder-v2-15b
  * Qwen models: qwen2.5-coder-1.5b, qwen2.5-coder-7b, qwen2.5-14b, qwen2.5-32b, qwen2.5-72b
  * CodeLlama models: codellama-7b-instruct, codellama-13b-instruct, codellama-34b-instruct, codellama-70b-instruct
- Processes APIs in configurable batches (default: 30 APIs per batch)
- User-configurable run IDs with auto-increment (default: "0")
- Stores prompts and results in organized directory structure
- Converts results to JSON format with statistics

Configuration:
- Prompt configurations: /src/prompts.py
- LLM model configurations: /src/models/

Output Structure:
- Prompts: output/project_name/api_labelling/model_name_run_id/prompts/
- Raw results: output/project_name/api_labelling/model_name_run_id/results/
- JSON results: output/project_name/api_labelling/model_name_run_id/final_results.json

Inspired by: IRIS framework

Arguments:
- Number of candidates to process per project (default: 300)
- LLM model selection (default: gpt-4.1)
  * GPT: gpt-4.1, gpt-4, gpt-3.5
  * DeepSeek: deepseek-r1-7b, deepseekcoder-33b, deepseekcoder-7b, deepseekcoder-v2-15b  
  * Qwen: qwen2.5-coder-1.5b, qwen2.5-coder-7b, qwen2.5-14b, qwen2.5-32b, qwen2.5-72b
  * CodeLlama: codellama-7b-instruct, codellama-13b-instruct, codellama-34b-instruct, codellama-70b-instruct
- Batch size for API processing (default: 30 APIs per batch)
- Run ID for organizing multiple runs (default: "0", auto-increments if exists)
"""


import argparse
import json
import os
import time
from pathlib import Path
from typing import List, Dict, Any

from prompts import API_LABELLING_SYSTEM_PROMPT, API_LABELLING_USER_PROMPT


class APILabeller:
    """Main class for API candidate labelling using LLMs."""
    
    def __init__(self, model_name: str = "gpt-4.1", max_candidates: int = 300, batch_size: int = 30, run_id: str = "0"):
        self.model_name = model_name
        self.max_candidates = max_candidates
        self.batch_size = batch_size
        self.run_id = run_id
        self.root_dir = Path(__file__).parent.parent
        self.output_dir = self.root_dir / "output"
    
    def get_final_run_id(self, project_name: str) -> str:
        """Get final run_id with auto-increment if needed."""
        base_dir = self.output_dir / project_name / "api_labelling"
        
        if not base_dir.exists():
            return self.run_id
        
        # Check if run_id already exists
        target_dir = base_dir / f"{self.model_name}_{self.run_id}"
        if not target_dir.exists():
            return self.run_id
        
        # Auto-increment if exists
        if self.run_id.isdigit():
            # If numeric, increment
            i = int(self.run_id)
            while (base_dir / f"{self.model_name}_{i}").exists():
                i += 1
            return str(i)
        else:
            # If string, append number
            i = 1
            while (base_dir / f"{self.model_name}_{self.run_id}_{i}").exists():
                i += 1
            return f"{self.run_id}_{i}"
        
    def list_available_projects(self) -> List[str]:
        """List projects that have api_candidates."""
        projects = []
        if not self.output_dir.exists():
            print(f"❌ Output directory not found: {self.output_dir}")
            return projects
            
        for project_dir in self.output_dir.iterdir():
            if project_dir.is_dir() and (project_dir / "api_candidates").exists():
                projects.append(project_dir.name)
        return projects
    
    def load_candidates(self, project_name: str) -> List[Dict[str, Any]]:
        """Load API candidates from JSON file."""
        candidates_file = self.output_dir / project_name / "api_candidates" / "filtered_api_candidates.json"
        
        if not candidates_file.exists():
            raise FileNotFoundError(
                f"❌ No candidates found for {project_name}. "
                f"Please run 04_filter_api_candidates.py first."
            )
        
        with open(candidates_file, 'r') as f:
            candidates = json.load(f)
        
        # Limit candidates if specified
        if len(candidates) > self.max_candidates:
            candidates = candidates[:self.max_candidates]
            print(f"📊 Limited to {self.max_candidates} candidates (from {len(candidates)} total)")
        
        print(f"📋 Loaded {len(candidates)} API candidates")
        return candidates
    
    def create_batches(self, candidates: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Split candidates into batches."""
        batches = []
        for i in range(0, len(candidates), self.batch_size):
            batches.append(candidates[i:i + self.batch_size])
        print(f"📦 Created {len(batches)} batches (size: {self.batch_size})")
        return batches
    
    def detect_cwe_from_project(self, project_name: str) -> str:
        """Detect CWE type from project name."""
        project_lower = project_name.lower()
        if "cwe-22" in project_lower or "path" in project_lower:
            return "cwe-022"
        elif "cwe-78" in project_lower or "command" in project_lower:
            return "cwe-078"
        elif "cwe-79" in project_lower or "xss" in project_lower:
            return "cwe-079"
        elif "cwe-94" in project_lower or "injection" in project_lower:
            return "cwe-094"
        else:
            return "cwe-078"  # Default
    
    def get_cwe_config(self, cwe_query: str) -> Dict[str, Any]:
        """Get CWE configuration with examples - IRIS style."""
        cwe_configs = {
            "cwe-078": {
                "cwe_id": "078",
                "desc": "OS Command Injection",
                "long_desc": "OS command injection allows an attacker to execute operating system commands on the server that is running an application, and typically fully compromise the application and its data. This occurs when applications execute system commands using user-controlled input without proper validation or sanitization.",
                "examples": [
                    {"package": "subprocess", "class": "Popen", "method": "__init__", "signature": "Popen(args, shell=False)", "sink_args": ["args"], "type": "sink"},
                    {"package": "os", "class": "system", "method": "system", "signature": "system(command)", "sink_args": ["command"], "type": "sink"},
                    {"package": "subprocess", "class": "run", "method": "run", "signature": "run(args, shell=False)", "sink_args": ["args"], "type": "sink"},
                    {"package": "flask", "class": "request", "method": "args.get", "signature": "args.get(key)", "sink_args": [], "type": "source"}
                ]
            },
            "cwe-022": {
                "cwe_id": "022", 
                "desc": "Path Traversal or Zip Slip",
                "long_desc": "A path traversal vulnerability allows an attacker to access files on your web server to which they should not have access. They do this by tricking either the web server or the web application running on it into returning files that exist outside of the web root folder. Another attack pattern is that users can pass in malicious Zip file which may contain directories like \"../\".",
                "examples": [
                    {"package": "builtins", "class": "open", "method": "open", "signature": "open(file, mode='r')", "sink_args": ["file"], "type": "sink"},
                    {"package": "pathlib", "class": "Path", "method": "__init__", "signature": "Path(path)", "sink_args": [], "type": "taint-propagator"},
                    {"package": "zipfile", "class": "ZipFile", "method": "extractall", "signature": "extractall(path=None)", "sink_args": ["path"], "type": "sink"}
                ]
            },
            "cwe-079": {
                "cwe_id": "079",
                "desc": "Cross-Site Scripting",
                "long_desc": "Cross-site scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. This occurs when applications include untrusted data in web pages without proper validation or escaping.",
                "examples": [
                    {"package": "flask", "class": "request", "method": "args.get", "signature": "args.get(key)", "sink_args": [], "type": "source"},
                    {"package": "django.http", "class": "HttpResponse", "method": "__init__", "signature": "HttpResponse(content)", "sink_args": ["content"], "type": "sink"}
                ]
            },
            "cwe-094": {
                "cwe_id": "094",
                "desc": "Code Injection", 
                "long_desc": "Code injection allows attackers to inject and execute arbitrary code in the application context. This typically occurs when applications dynamically execute code using user-controlled input.",
                "examples": [
                    {"package": "builtins", "class": "eval", "method": "eval", "signature": "eval(expression)", "sink_args": ["expression"], "type": "sink"},
                    {"package": "builtins", "class": "exec", "method": "exec", "signature": "exec(object)", "sink_args": ["object"], "type": "sink"}
                ]
            }
        }
        return cwe_configs.get(cwe_query, cwe_configs["cwe-078"])

    def create_prompt(self, batch: List[Dict[str, Any]], project_name: str) -> tuple[str, str]:
        """Create IRIS-style system and user prompts for a batch."""
        # Detect CWE from project name
        cwe_query = self.detect_cwe_from_project(project_name)
        cwe_config = self.get_cwe_config(cwe_query)
        
        # System prompt (IRIS style with clearer JSON array format)
        system_prompt = """You are a security expert. \
You are given a list of APIs to be labeled as potential taint sources, sinks, or APIs that propagate taints. \
Taint sources are values that an attacker can use for unauthorized and malicious operations when interacting with the system. \
Taint source APIs usually return strings or custom object types. Setter methods are typically NOT taint sources. \
Taint sinks are program points that can use tainted data in an unsafe way, which directly exposes vulnerability under attack. \
Taint propagators carry tainted information from input to the output without sanitization, and typically have non-primitive input and outputs. \

IMPORTANT: You must analyze ALL APIs provided and return the result as a JSON array (list) with each object in the format:

[
  { "package": <package name>,
    "class": <class name>,
    "method": <method name>,
    "signature": <signature of the method>,
    "sink_args": <list of arguments or `this`; empty if the API is not sink>,
    "type": <"source", "sink", or "taint-propagator"> },
  { "package": <package name>,
    "class": <class name>,
    "method": <method name>,
    "signature": <signature of the method>,
    "sink_args": <list of arguments or `this`; empty if the API is not sink>,
    "type": <"source", "sink", or "taint-propagator"> }
]

You must return a JSON array containing ALL the APIs provided. DO NOT OUTPUT ANYTHING OTHER THAN THE JSON ARRAY."""
        
        # Format examples (IRIS style)
        examples_text = ""
        for example in cwe_config["examples"]:
            examples_text += f"{example['package']},{example.get('class', '')},{example['method']},{example['signature']}\n"
        
        # Format candidates (using actual JSON structure)
        methods_text = ""
        for candidate in batch:
            package = candidate.get('package', '')
            clazz = candidate.get('clazz', '')  
            func = candidate.get('func', '')
            signature = candidate.get('full_signature', func)
            methods_text += f"{package},{clazz},{func},{signature}\n"
        
        # User prompt (IRIS style with emphasis on ALL APIs)
        user_prompt = f"""{cwe_config['long_desc']}

Some example source/sink/taint-propagator methods are:
{examples_text}

Among the following methods, \
assuming that the arguments passed to the given function is malicious, \
what are the functions that are potential source, sink, or taint-propagators to {cwe_config['desc']} attack (CWE-{cwe_config['cwe_id']})?

IMPORTANT: Analyze ALL the APIs listed below and return a JSON array with one object for each API.

Package,Class,Method,Signature
{methods_text}

Return a JSON array with analysis for ALL {len(batch)} APIs listed above."""
        
        return system_prompt, user_prompt
    
    def initialize_model(self):
        """Initialize the selected LLM model."""
        # Set HF_HOME for offline models
        os.environ.setdefault('HF_HOME', str(self.root_dir / '.cache' / 'huggingface'))
        
        # Create logger for models
        try:
            from utils.mylogger import MyLogger
            logger = MyLogger("api_labeling_logs")
        except ImportError:
            import logging
            logger = logging.getLogger(__name__)
        
        # Dynamically import model based on name
        try:
            if self.model_name.startswith('gpt'):
                from models.gpt import GPTModel
                return GPTModel(self.model_name, logger)
            elif 'deepseek' in self.model_name.lower():
                from models.deepseek import DeepSeekModel
                return DeepSeekModel(self.model_name, logger)
            elif 'qwen' in self.model_name.lower():
                from models.qwen import QwenModel
                return QwenModel(self.model_name, logger)
            elif 'codellama' in self.model_name.lower():
                from models.codellama import CodeLlamaModel
                return CodeLlamaModel(self.model_name, logger)
            # Add more models as needed
            else:
                raise ValueError(f"❌ Unsupported model: {self.model_name}")
        except Exception as e:
            print(f"❌ Failed to initialize model '{self.model_name}': {e}")
            print(f"💡 Available DeepSeek models: deepseek-r1-7b, deepseekcoder-33b, deepseekcoder-7b, deepseekcoder-v2-15b")
            print(f"💡 Available Qwen models: qwen2.5-coder-1.5b, qwen2.5-coder-7b, qwen2.5-14b, qwen2.5-32b, qwen2.5-72b")
            print(f"💡 Available CodeLlama models: codellama-7b-instruct, codellama-13b-instruct, codellama-34b-instruct, codellama-70b-instruct")
            print(f"💡 Available GPT models: gpt-4.1, gpt-4, gpt-3.5")
            print(f"💡 Make sure you have the required dependencies installed:")
            print(f"   - For DeepSeek/Qwen/CodeLlama: pip install transformers torch accelerate")
            print(f"   - For GPT: Set OPENAI_API_KEY environment variable")
            raise
    
    def parse_json_response(self, response: str, expected_count: int = 0) -> List[Dict[str, Any]]:
        """Parse JSON response from LLM (robust parsing like IRIS)."""
        if not response:
            print(f"⚠️  Empty response received")
            return []
            
        print(f"📤 Response length: {len(response)} characters")
        if expected_count > 0:
            print(f"🎯 Expected {expected_count} API results")
            
        try:
            # Try direct JSON parsing first
            if response.strip().startswith('['):
                results = json.loads(response.strip())
                print(f"✅ Parsed {len(results)} results from JSON array")
                return results
            
            # Extract JSON from response
            import re
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                results = json.loads(json_str)
                print(f"✅ Extracted and parsed {len(results)} results from JSON array")
                return results
            
            # Try to find individual JSON objects and create array
            json_objects = re.findall(r'\{[^}]*\}', response)
            if json_objects:
                results = []
                for obj_str in json_objects:
                    try:
                        results.append(json.loads(obj_str))
                    except Exception as e:
                        print(f"⚠️  Failed to parse JSON object: {obj_str[:100]}... Error: {e}")
                        continue
                print(f"✅ Parsed {len(results)} individual JSON objects")
                return results
            
            # Check if it's a single JSON object (should be an array)
            if response.strip().startswith('{'):
                try:
                    single_result = json.loads(response.strip())
                    print(f"⚠️  Got single JSON object instead of array - wrapping in array")
                    return [single_result]
                except:
                    pass
                
        except Exception as e:
            print(f"❌ JSON parsing failed: {e}")
            print(f"🔍 Response preview: {response[:200]}...")
            
        print(f"❌ Could not parse any JSON from response")
        return []
    
    def process_project(self, project_name: str) -> Dict[str, Any]:
        """Process a single project through the labelling pipeline."""
        print(f"\n🚀 Processing project: {project_name}")
        
        # NOTE: IRIS methodology includes two stages of labeling:
        # 1. API candidate labeling (this stage) - Label API methods as source/sink/taint-propagator
        # 2. Function parameters labeling (future stage) - Label individual parameters within functions
        # 
        # The second stage requires CodeQL queries to collect function parameters,
        # which are not yet implemented. This stage focuses on API candidate labeling only.
        
        final_run_id = self.get_final_run_id(project_name)
        start_time = time.time()
        
        # Create output directories
        base_dir = self.output_dir / project_name / "api_labelling" / f"{self.model_name}_run_{final_run_id}"
        prompts_dir = base_dir / "prompts"
        results_dir = base_dir / "results"
        prompts_dir.mkdir(parents=True, exist_ok=True)
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Load candidates and create batches
        candidates = self.load_candidates(project_name)
        batches = self.create_batches(candidates)
        
        # Initialize model
        print(f"🤖 Initializing model: {self.model_name}")
        model = self.initialize_model()
        
        results = []
        stats = {"total_apis": len(candidates), "successful_batches": 0, "failed_batches": 0}
        
        # Process each batch
        for batch_id, batch in enumerate(batches):
            print(f"⚡ Processing batch {batch_id + 1}/{len(batches)}")
            
            try:
                # Create and save prompts (IRIS style with CWE context)
                system_prompt, user_prompt = self.create_prompt(batch, project_name)
                prompt_file = prompts_dir / f"batch_{batch_id}.txt"
                with open(prompt_file, 'w') as f:
                    f.write(f"SYSTEM:\n{system_prompt}\n\nUSER:\n{user_prompt}")
                
                # Get LLM response (don't use expect_json=True as it forces single object format)
                response = model.predict([
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ])
                
                # Save raw response
                response_file = results_dir / f"batch_{batch_id}_raw_response.txt"
                with open(response_file, 'w') as f:
                    f.write(response if isinstance(response, str) else str(response))
                
                # Parse JSON response (IRIS style)
                if response:
                    parsed_results = self.parse_json_response(response, len(batch))
                    results.append({"batch_id": batch_id, "response": response, "parsed_results": parsed_results, "apis": batch})
                    stats["successful_batches"] += 1
                    print(f"✅ Batch {batch_id}: {len(parsed_results)}/{len(batch)} APIs labeled")
                else:
                    results.append({"batch_id": batch_id, "response": "ERROR: No response", "parsed_results": [], "apis": batch})
                    stats["failed_batches"] += 1
                
            except Exception as e:
                print(f"❌ Batch {batch_id} failed: {e}")
                results.append({"batch_id": batch_id, "response": f"ERROR: {e}", "parsed_results": [], "apis": batch})
                stats["failed_batches"] += 1
        
        # Save final JSON results with statistics
        final_results = {
            "project": project_name,
            "model": self.model_name,
            "run_id": final_run_id,
            "timestamp": time.time(),
            "processing_time": time.time() - start_time,
            "statistics": stats,
            "results": results
        }
        
        json_file = base_dir / "final_results.json"
        with open(json_file, 'w') as f:
            json.dump(final_results, f, indent=2)
        
        print(f"✅ Completed {project_name}: {stats['successful_batches']}/{len(batches)} batches successful")
        return final_results


def main():
    parser = argparse.ArgumentParser(description="API Candidate Labelling with LLMs")
    parser.add_argument("--project", help="Project name to process")
    parser.add_argument("--model", default="gpt-4.1", help="LLM model to use")
    parser.add_argument("--max-candidates", type=int, default=300, help="Max candidates per project")
    parser.add_argument("--batch-size", type=int, default=30, help="Batch size for processing")
    parser.add_argument("--run-id", default="0", help="Run ID (default: 0, auto-increments if exists)")
    parser.add_argument("--list-projects", action="store_true", help="List available projects")
    
    args = parser.parse_args()
    
    labeller = APILabeller(args.model, args.max_candidates, args.batch_size, args.run_id)
    
    if args.list_projects:
        projects = labeller.list_available_projects()
        print(f"\n📁 Available projects ({len(projects)}):")
        for project in projects:
            print(f"  - {project}")
        return
    
    if not args.project:
        projects = labeller.list_available_projects()
        if not projects:
            print("❌ No projects with api_candidates found!")
            return
        print(f"\n📁 Available projects: {', '.join(projects)}")
        print("Use --project <name> to process a specific project")
        return
    
    try:
        result = labeller.process_project(args.project)
        print(f"\n🎉 Results saved in: {result.get('project')}/api_labelling/")
    except Exception as e:
        print(f"❌ Processing failed: {e}")


if __name__ == "__main__":
    main()