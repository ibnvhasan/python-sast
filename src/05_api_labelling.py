"""
Enhanced API Candidate Labeling Module using Large Language Models

This module provides advanced functionality to prompt LLMs (online and offline) to label 
collected candidate APIs from the previous stage. Implements the IRIS methodology with 
enhanced error handling, retry logic, and comprehensive statistics.

IRIS Methodology Implementation:
This implementation follows the IRIS framework which includes TWO stages of labeling:

Stage 1 (Implemented): API Candidate Labeling
- Labels API methods as source, sink, or taint-propagator
- Processes APIs in batches with CWE-specific context
- Uses vulnerability-specific prompts and examples
- Enhanced retry logic and error handling

Stage 2 (Future): Function Parameters Labeling  
- Labels individual parameters within function calls
- Requires CodeQL queries to collect function parameters (NOT YET IMPLEMENTED)
- Would process parameter-level taint analysis

Enhanced Features:
- Robust error handling with exponential backoff retry
- Comprehensive statistics tracking and reporting
- Support for multiple LLM providers:
  * GPT models: gpt-4, gpt-4-turbo, gpt-3.5-turbo (OpenAI)
  * Claude models: claude-3-opus, claude-3-sonnet (Anthropic)
  * Gemini models: gemini-pro, gemini-1.5-pro (Google)
  * Ollama models: llama3.1:8b, codellama:7b, etc. (Local)
  * HuggingFace models: Any transformer model (Local)
- Enhanced prompt management and response parsing
- Rate limiting and token usage optimization
- Detailed logging and progress tracking

Configuration:
- Environment variables for API keys
- Configurable batch sizes and retry policies
- CWE-specific prompt templates

Output Structure:
- Enhanced directory structure with run IDs
- Comprehensive statistics and metrics
- Raw responses and parsed results
- Error logs and retry information
"""

import argparse
import json
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import re
try:
    import torch  # used if transformers backend is selected
except Exception:
    torch = None

# Enhanced imports for better model support
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from iris_prompts import build_api_labeling_prompts

# Import for CodeQL query generation
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_queries", 
                                                   os.path.join(os.path.dirname(__file__), "06_build_project_specific_query.py"))
    build_queries_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build_queries_module)
    build_project_specific_queries = build_queries_module.build_project_specific_queries
except Exception:
    print("⚠️  Warning: Could not import build_project_specific_queries - CodeQL query generation will be skipped")
    build_project_specific_queries = None


@dataclass
class LabelingStats:
    """Enhanced statistics tracking for labeling results"""
    total_candidates: int = 0
    processed_batches: int = 0
    successful_batches: int = 0
    failed_batches: int = 0
    successful_labels: int = 0
    failed_labels: int = 0
    sources: int = 0
    sinks: int = 0
    propagators: int = 0
    sanitizers: int = 0
    neutral: int = 0
    total_retries: int = 0
    processing_time: float = 0.0
    
    def update_label_counts(self, results: List[Dict[str, Any]]):
        """Update label distribution counts"""
        for result in results:
            label_type = result.get('type', 'neutral').lower()
            if label_type == 'source':
                self.sources += 1
            elif label_type == 'sink':
                self.sinks += 1
            elif label_type in ['taint-propagator', 'propagator']:
                self.propagators += 1
            elif label_type == 'sanitizer':
                self.sanitizers += 1
            else:
                self.neutral += 1
    
    def get_success_rate(self) -> float:
        """Calculate overall success rate"""
        return self.successful_labels / self.total_candidates if self.total_candidates > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary for serialization"""
        return {
            "total_candidates": self.total_candidates,
            "processed_batches": self.processed_batches,
            "successful_batches": self.successful_batches,
            "failed_batches": self.failed_batches,
            "successful_labels": self.successful_labels,
            "failed_labels": self.failed_labels,
            "total_retries": self.total_retries,
            "processing_time": self.processing_time,
            "success_rate": self.get_success_rate(),
            "label_distribution": {
                "sources": self.sources,
                "sinks": self.sinks,
                "taint_propagators": self.propagators,
                "sanitizers": self.sanitizers,
                "neutral": self.neutral
            }
        }


class EnhancedAPILabeller:
    """Enhanced API candidate labelling with multiple LLM support and robust error handling."""
    
    def __init__(self, model_name: str = "gpt-4", max_candidates: int = 300, 
                 batch_size: int = 30, run_id: str = "0", max_retries: int = 3,
                 allow_remote: bool = False,
                 hf_4bit: bool = False,
                 max_new_tokens: int = 256,
                 temperature: float = 0.0,
                 max_input_tokens: int = 8192,
                 no_codeql: bool = False):
        self.model_name = model_name
        self.max_candidates = max_candidates
        self.batch_size = batch_size
        self.run_id = run_id
        self.max_retries = max_retries
        # By default, enforce offline/local HF models only unless explicitly allowed
        self.allow_remote = allow_remote
        self.hf_4bit = hf_4bit
        self.no_codeql = no_codeql
        self.root_dir = Path(__file__).parent.parent
        self.output_dir = self.root_dir / "output"
        self.stats = LabelingStats()

        # Generation configuration
        self.generation_hparams = {
            "max_new_tokens": max_new_tokens,
            "temperature": temperature,
            "max_input_tokens": max_input_tokens,
        }
        
        # Model setup
        self.model = None
        self.model_type = self._detect_model_type()
    
    def _detect_model_type(self) -> str:
        """Detect the type of model being used"""
        model_lower = self.model_name.lower()
        if model_lower.startswith('gpt'):
            return 'openai'
        elif model_lower.startswith('claude'):
            return 'anthropic'
        elif model_lower.startswith('gemini'):
            return 'google'
        elif 'ollama:' in model_lower or self._is_ollama_model():
            return 'ollama'
        elif any(x in model_lower for x in ['deepseek', 'qwen', 'codellama']):
            return 'huggingface'
        else:
            return 'huggingface'  # Default to local model
    
    def _is_ollama_model(self) -> bool:
        """Check if model name matches common Ollama patterns"""
        ollama_patterns = [
            "llama3.1:8b", "llama3.1:70b", "llama3:8b", "llama3:70b",
            "codellama:7b", "codellama:13b", "codellama:34b",
            "mistral:7b", "mixtral:8x7b", "phi3:mini", "phi3:medium"
        ]
        return self.model_name in ollama_patterns
    
    def _setup_openai_model(self):
        """Setup OpenAI GPT models"""
        try:
            import openai
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OPENAI_API_KEY environment variable is required")
            return openai.OpenAI(api_key=api_key)
        except Exception as e:
            raise RuntimeError(f"Failed to setup OpenAI: {e}")
    
    def _setup_anthropic_model(self):
        """Setup Anthropic Claude models"""
        try:
            import anthropic
            api_key = os.getenv('ANTHROPIC_API_KEY')
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY environment variable is required")
            return anthropic.Anthropic(api_key=api_key)
        except Exception as e:
            raise RuntimeError(f"Failed to setup Anthropic: {e}")
    
    def _setup_google_model(self):
        """Setup Google Gemini models"""
        try:
            import google.generativeai as genai
            api_key = os.getenv('GOOGLE_API_KEY')
            if not api_key:
                raise ValueError("GOOGLE_API_KEY environment variable is required")
            genai.configure(api_key=api_key)
            return genai.GenerativeModel(self.model_name)
        except Exception as e:
            raise RuntimeError(f"Failed to setup Gemini: {e}")
    
    def _setup_ollama_model(self):
        """Setup Ollama for local models"""
        try:
            import ollama
            return ollama.Client()
        except Exception as e:
            raise RuntimeError(f"Failed to setup Ollama: {e}")
    
    def _setup_huggingface_model(self):
        """Setup HuggingFace transformers model with fallback to existing model classes"""
        # First try existing model classes
        try:
            if 'deepseek' in self.model_name.lower():
                from models.deepseek import DeepSeekModel
                from utils.mylogger import MyLogger
                logger = MyLogger("api_labeling_logs")
                return DeepSeekModel(self.model_name, logger)
            elif 'qwen' in self.model_name.lower():
                from models.qwen import QwenModel
                from utils.mylogger import MyLogger
                logger = MyLogger("api_labeling_logs")
                return QwenModel(self.model_name, logger)
            elif 'codellama' in self.model_name.lower():
                from models.codellama import CodeLlamaModel
                from utils.mylogger import MyLogger
                logger = MyLogger("api_labeling_logs")
                return CodeLlamaModel(self.model_name, logger)
        except Exception as e:
            print(f"⚠️  Failed to load existing model class: {e}")
        
        # Fallback to direct transformers usage
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch
            
            # Honor HF_HOME cache directory if provided
            hf_cache = os.environ.get("HF_HOME")
            if hf_cache:
                print(f"� Using HF cache dir: {hf_cache}")
            
            print(f"�🔄 Loading HuggingFace model: {self.model_name}")
            tokenizer = AutoTokenizer.from_pretrained(self.model_name, cache_dir=hf_cache)
            
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            
            model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None,
                trust_remote_code=True,
                low_cpu_mem_usage=True,
                cache_dir=hf_cache
            )
            
            print(f"✅ Model loaded. Using device: {'CUDA' if torch.cuda.is_available() else 'CPU'}")
            return {"tokenizer": tokenizer, "model": model, "type": "transformers"}
        except Exception as e:
            raise RuntimeError(f"Failed to setup HuggingFace model '{self.model_name}': {e}")
    
    def initialize_model(self):
        """Initialize the selected LLM model with enhanced error handling"""
        print(f"🤖 Initializing {self.model_type} model: {self.model_name}")
        
        try:
            if not self.allow_remote and self.model_type in {"openai", "anthropic", "google"}:
                raise RuntimeError(
                    "Remote API models are disabled. Use a local HuggingFace model (e.g., deepseek-r1-7b, qwen2.5-coder-7b), "
                    "or rerun with --allow-remote to enable cloud APIs."
                )
            # Configure 4-bit quantization preference for HF
            if self.model_type == 'huggingface':
                os.environ["HF_LOAD_4BIT"] = "1" if self.hf_4bit else "0"
            if self.model_type == 'openai':
                self.model = self._setup_openai_model()
            elif self.model_type == 'anthropic':
                self.model = self._setup_anthropic_model()
            elif self.model_type == 'google':
                self.model = self._setup_google_model()
            elif self.model_type == 'ollama':
                self.model = self._setup_ollama_model()
            else:  # huggingface
                self.model = self._setup_huggingface_model()
            
            # Apply generation hyperparameters if supported by the model wrapper
            try:
                if hasattr(self.model, 'model_hyperparams'):
                    self.model.model_hyperparams.update({
                        'max_new_tokens': self.generation_hparams['max_new_tokens'],
                        'temperature': self.generation_hparams['temperature'],
                        'max_input_tokens': self.generation_hparams['max_input_tokens'],
                        'top_p': 1.0,
                        'do_sample': False,
                    })
            except Exception:
                pass

            print(f"✅ Model initialized successfully")
            return self.model
            
        except Exception as e:
            print(f"❌ Failed to initialize model '{self.model_name}': {e}")
            self._print_model_help()
            raise
    
    def _print_model_help(self):
        """Print helpful information about available models"""
        print(f"\n💡 Available model options:")
        print(f"   OpenAI: gpt-4, gpt-4-turbo, gpt-3.5-turbo (requires OPENAI_API_KEY)")
        print(f"   Anthropic: claude-3-opus, claude-3-sonnet (requires ANTHROPIC_API_KEY)")
        print(f"   Google: gemini-pro, gemini-1.5-pro (requires GOOGLE_API_KEY)")
        print(f"   Ollama: llama3.1:8b, codellama:7b, mistral:7b (requires Ollama)")
        print(f"   HuggingFace: deepseek-r1-7b, qwen2.5-32b, codellama-7b-instruct")
    
    def query_model_with_retry(self, system_prompt: str, user_prompt: str, 
                              batch_id: int) -> Optional[str]:
        """Query model with exponential backoff retry logic"""
        for attempt in range(self.max_retries):
            try:
                response = self._query_model_once(system_prompt, user_prompt)
                if response and response.strip():
                    if attempt > 0:
                        print(f"✅ Batch {batch_id}: Success on attempt {attempt + 1}")
                    return response
                else:
                    print(f"⚠️  Batch {batch_id}: Empty response on attempt {attempt + 1}")
            
            except Exception as e:
                print(f"❌ Batch {batch_id}: Error on attempt {attempt + 1}: {e}")
                self.stats.total_retries += 1
                
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    print(f"⏳ Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
        
        print(f"💥 Batch {batch_id}: Failed after {self.max_retries} attempts")
        return None
    
    def _query_model_once(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Single model query without retry logic"""
        if self.model_type == 'openai':
            response = self.model.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=4000
            )
            return response.choices[0].message.content
        
        elif self.model_type == 'anthropic':
            response = self.model.messages.create(
                model=self.model_name,
                max_tokens=4000,
                temperature=0.1,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}]
            )
            return response.content[0].text
        
        elif self.model_type == 'google':
            response = self.model.generate_content(
                f"{system_prompt}\n\n{user_prompt}",
                generation_config={"temperature": 0.1, "max_output_tokens": 4000}
            )
            return response.text
        
        elif self.model_type == 'ollama':
            response = self.model.chat(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )
            return response['message']['content']
        
        else:  # huggingface
            if isinstance(self.model, dict) and self.model.get("type") == "transformers":
                # Direct transformers usage
                tokenizer = self.model["tokenizer"]
                model = self.model["model"]
                
                full_prompt = f"{system_prompt}\n\n{user_prompt}"
                inputs = tokenizer(full_prompt, return_tensors="pt", truncation=True, max_length=self.generation_hparams.get('max_input_tokens', 2048))
                
                if torch is None:
                    raise RuntimeError("torch not available for local transformers generation")
                with torch.no_grad():
                    outputs = model.generate(
                        **inputs,
                        max_new_tokens=self.generation_hparams.get('max_new_tokens', 256),
                        temperature=self.generation_hparams.get('temperature', 0.0),
                        do_sample=False,
                        pad_token_id=tokenizer.eos_token_id,
                        eos_token_id=tokenizer.eos_token_id
                    )
                
                response = tokenizer.decode(outputs[0], skip_special_tokens=True)
                return response[len(full_prompt):].strip()
            else:
                # Use existing model class that implements predict(chat_messages)
                chat_messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
                try:
                    # For GPT remote models, request strict JSON when supported
                    return self.model.predict(chat_messages, expect_json=True)
                except TypeError:
                    return self.model.predict(chat_messages)
    
    def parse_json_response(self, response: str, expected_count: int = 0) -> List[Dict[str, Any]]:
        """Enhanced JSON response parsing with better error handling"""
        if not response:
            return []
        
        # Clean response by removing common prefixes/suffixes
        response = response.strip()
        
        # Remove markdown code blocks if present
        if '```json' in response:
            response = re.sub(r'```json\s*', '', response)
            response = re.sub(r'```\s*$', '', response)
        elif '```' in response:
            response = re.sub(r'```\s*', '', response)
        
        # Remove any text before the first [ and after the last ]
        start_idx = response.find('[')
        end_idx = response.rfind(']')
        
        if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
            response = response[start_idx:end_idx + 1]
        
        try:
            parsed = json.loads(response)
            
            # Ensure it's a list
            if not isinstance(parsed, list):
                return []
            
            # Validate expected count
            if expected_count > 0 and len(parsed) != expected_count:
                print(f"⚠️  Expected {expected_count} results, got {len(parsed)}")
            
            return parsed
            
        except json.JSONDecodeError as e:
            print(f"❌ JSON parsing failed: {e}")
            print(f"📄 Raw response preview: {response[:200]}...")
            return []
    
    def get_final_run_id(self, project_name: str) -> str:
        """Get final run_id with auto-increment if needed."""
        base_path = self.output_dir / project_name / "api_labelling"
        if not base_path.exists():
            return self.run_id
        
        existing_runs = []
        pattern = f"{self.model_name}_run_"
        
        for path in base_path.iterdir():
            if path.is_dir() and path.name.startswith(pattern):
                try:
                    run_num = int(path.name[len(pattern):])
                    existing_runs.append(run_num)
                except ValueError:
                    continue
        
        if self.run_id == "0" and existing_runs:
            return str(max(existing_runs) + 1)
        
        return self.run_id
    
    def list_available_projects(self) -> List[str]:
        """List projects that have api_candidates."""
        projects = []
        for project_dir in self.output_dir.iterdir():
            if project_dir.is_dir():
                candidates_file = project_dir / "api_candidates/filtered_api_candidates.json"
                if candidates_file.exists():
                    projects.append(project_dir.name)
        return sorted(projects)
    
    def load_candidates(self, project_name: str) -> List[Dict[str, Any]]:
        """Load API candidates from JSON file."""
        candidates_file = self.output_dir / project_name / "api_candidates/filtered_api_candidates.json"
        
        if not candidates_file.exists():
            raise FileNotFoundError(f"No candidates file found at {candidates_file}")
        
        with open(candidates_file, 'r') as f:
            candidates = json.load(f)
        
        # Limit candidates if specified
        if self.max_candidates and len(candidates) > self.max_candidates:
            candidates = candidates[:self.max_candidates]
            print(f"📊 Limited to {self.max_candidates} candidates (from {len(candidates)})")
        
        print(f"📊 Loaded {len(candidates)} API candidates")
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
        """Create IRIS-style system and user prompts using the dedicated builder."""
        cwe_query = self.detect_cwe_from_project(project_name)
        cwe_config = self.get_cwe_config(cwe_query)
        return build_api_labeling_prompts(cwe_config, batch)
    
    def process_project(self, project_name: str) -> Dict[str, Any]:
        """Enhanced project processing with comprehensive error handling and statistics"""
        print(f"\n🚀 Processing project: {project_name}")
        print(f"🤖 Model: {self.model_name} ({self.model_type})")
        print(f"⚙️  Config: max_candidates={self.max_candidates}, batch_size={self.batch_size}, retries={self.max_retries}")
        
        start_time = time.time()
        final_run_id = self.get_final_run_id(project_name)
        
        # Create enhanced output directories
        base_dir = self.output_dir / project_name / "api_labelling" / f"{self.model_name}_run_{final_run_id}"
        prompts_dir = base_dir / "prompts"
        results_dir = base_dir / "results"
        stats_dir = base_dir / "statistics"
        
        for dir_path in [prompts_dir, results_dir, stats_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Load candidates and create batches
        candidates = self.load_candidates(project_name)
        batches = self.create_batches(candidates)
        
        self.stats.total_candidates = len(candidates)
        
        # Initialize model
        model = self.initialize_model()
        
        # Enhanced batch processing with progress tracking
        all_results = []
        batch_stats = []
        
        print(f"\n📋 Starting batch processing...")
        
        for batch_id, batch in enumerate(batches):
            batch_start_time = time.time()
            print(f"\n⚡ Processing batch {batch_id + 1}/{len(batches)} ({len(batch)} APIs)")
            
            try:
                # Dynamically size generation tokens to avoid truncated JSON
                # Rough estimate: ~70 tokens per item; cap at 2048 for safety
                dyn_max_new = min(2048, max(256, 70 * len(batch)))
                # Apply to direct transformers path
                self.generation_hparams['max_new_tokens'] = dyn_max_new
                # Apply to wrapper models if available
                try:
                    if hasattr(self.model, 'model_hyperparams'):
                        self.model.model_hyperparams['max_new_tokens'] = dyn_max_new
                except Exception:
                    pass

                # Create and save prompts (IRIS style with CWE context)
                system_prompt, user_prompt = self.create_prompt(batch, project_name)
                
                # Check prompt length for token limit warnings
                total_prompt_length = len(system_prompt) + len(user_prompt)
                print(f"📏 Prompt length: {total_prompt_length} characters; max_new_tokens={dyn_max_new}")
                if total_prompt_length > 15000:
                    print(f"⚠️  Warning: Very long prompt, may exceed token limits")
                
                # Save prompt
                prompt_file = prompts_dir / f"batch_{batch_id}.txt"
                with open(prompt_file, 'w') as f:
                    f.write(f"SYSTEM:\n{system_prompt}\n\nUSER:\n{user_prompt}")
                
                # Query model with retry logic
                response = self.query_model_with_retry(system_prompt, user_prompt, batch_id)
                
                # Save raw response
                response_file = results_dir / f"batch_{batch_id}_raw_response.txt"
                with open(response_file, 'w') as f:
                    f.write(response if response else "ERROR: No response after retries")
                
                # Parse response and update statistics
                validated_results: List[Dict[str, Any]] = []
                if response and response.strip():
                    parsed_results = self.parse_json_response(response, len(batch))
                    
                    # If parsing failed, try one strict re-prompt
                    if not parsed_results:
                        strict_user_prompt = (
                            user_prompt
                            + f"\n\nSTRICT MODE: Return ONLY a valid JSON array with exactly {len(batch)} objects. "
                              "No prose, no markdown, no code fences."
                        )
                        response2 = self.query_model_with_retry(system_prompt, strict_user_prompt, batch_id)
                        if response2 and response2.strip():
                            parsed_results = self.parse_json_response(response2, len(batch))
                            # Save second raw response too
                            response_file2 = results_dir / f"batch_{batch_id}_raw_response_retry.txt"
                            with open(response_file2, 'w') as f:
                                f.write(response2)
                    
                    # Validate and enhance results (may still be empty)
                    validated_results = self._validate_and_enhance_results(parsed_results, batch)
                    
                    if validated_results:
                        all_results.extend(validated_results)
                        self.stats.update_label_counts(validated_results)
                        self.stats.successful_labels += len(validated_results)
                        self.stats.successful_batches += 1
                        print(f"✅ Batch {batch_id}: {len(validated_results)}/{len(batch)} APIs labeled successfully")
                    else:
                        print(f"❌ Batch {batch_id}: Failed to parse JSON after retry")
                        self.stats.failed_labels += len(batch)
                        self.stats.failed_batches += 1
                else:
                    print(f"❌ Batch {batch_id}: Failed to get valid response")
                    self.stats.failed_labels += len(batch)
                    self.stats.failed_batches += 1
                
                # Track batch statistics
                batch_time = time.time() - batch_start_time
                batch_stats.append({
                    "batch_id": batch_id,
                    "batch_size": len(batch),
                    "processing_time": batch_time,
                    "success": response is not None,
                    "parsed_count": len(validated_results) if response else 0
                })
                
                # Rate limiting - small delay between batches
                if batch_id < len(batches) - 1:
                    print(f"⏳ Waiting 2s before next batch...")
                    time.sleep(2)
                
            except Exception as e:
                print(f"❌ Batch {batch_id} failed with exception: {e}")
                self.stats.failed_labels += len(batch)
                self.stats.failed_batches += 1
                
                batch_stats.append({
                    "batch_id": batch_id,
                    "batch_size": len(batch),
                    "processing_time": time.time() - batch_start_time,
                    "success": False,
                    "error": str(e)
                })
        
        # Calculate final statistics
        self.stats.processing_time = time.time() - start_time
        self.stats.processed_batches = len(batches)
        
        # Save comprehensive results
        final_results = {
            "project": project_name,
            "model": self.model_name,
            "model_type": self.model_type,
            "run_id": final_run_id,
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "max_candidates": self.max_candidates,
                "batch_size": self.batch_size,
                "max_retries": self.max_retries
            },
            "statistics": self.stats.to_dict(),
            "batch_details": batch_stats,
            "labeled_apis": all_results
        }
        
        # Save final JSON results
        results_file = base_dir / "final_results.json"
        with open(results_file, 'w') as f:
            json.dump(final_results, f, indent=2)
        
        # Save statistics separately for easy analysis
        stats_file = stats_dir / "labeling_statistics.json"
        with open(stats_file, 'w') as f:
            json.dump(self.stats.to_dict(), f, indent=2)
        
        # Save labeled APIs in IRIS-compatible format
        apis_file = base_dir / "labeled_apis.json"
        with open(apis_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        # Print comprehensive summary
        self._print_final_summary(final_results)
        
        # Build project-specific CodeQL queries (IRIS pattern)
        if not self.no_codeql and build_project_specific_queries and all_results:
            print(f"\n🔧 Building project-specific CodeQL queries...")
            try:
                success = build_project_specific_queries(project_name, str(self.output_dir))
                if success:
                    print(f"✅ Successfully generated CodeQL query files for {project_name}")
                    print(f"📁 Query files location: {project_name}/api_labelling/*/custom_codeql_library/")
                else:
                    print(f"⚠️  Failed to generate CodeQL queries for {project_name}")
            except Exception as e:
                print(f"❌ Error generating CodeQL queries: {e}")
                print(f"💡 You can manually run: python src/06_build_project_specific_query.py --project {project_name}")
        elif self.no_codeql:
            print(f"\n🔧 CodeQL query generation skipped (--no-codeql flag)")
        elif not build_project_specific_queries:
            print(f"\n💡 To generate CodeQL queries, run: python src/06_build_project_specific_query.py --project {project_name}")
        elif not all_results:
            print(f"\n⚠️  No labeled APIs found - skipping CodeQL query generation")
        
        return final_results
    
    def _validate_and_enhance_results(self, parsed_results: List[Dict[str, Any]], 
                                    original_batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate and enhance parsed results with original API data"""
        validated = []
        
        for result in parsed_results:
            # Ensure required fields exist
            if 'type' not in result:
                result['type'] = 'neutral'
            
            # Normalize type field
            result['type'] = result['type'].lower().replace('taint-propagator', 'propagator')
            
            # Add metadata
            result['labeling_timestamp'] = datetime.now().isoformat()
            result['model_used'] = self.model_name
            
            # Try to match with original API data for additional context
            if 'method' in result:
                for orig_api in original_batch:
                    if (orig_api.get('func', '') == result.get('method', '') or
                        orig_api.get('full_signature', '') == result.get('signature', '')):
                        result['original_api_data'] = orig_api
                        break
            
            validated.append(result)
        
        return validated
    
    def _print_final_summary(self, results: Dict[str, Any]):
        """Print comprehensive final summary"""
        stats = results['statistics']
        
        print(f"\n" + "="*60)
        print(f"🎉 LABELING COMPLETED")
        print(f"="*60)
        print(f"📊 Project: {results['project']}")
        print(f"🤖 Model: {results['model']} ({results['model_type']})")
        print(f"🆔 Run ID: {results['run_id']}")
        print(f"⏱️  Processing Time: {stats['processing_time']:.2f} seconds")
        print(f"\n📈 RESULTS SUMMARY:")
        print(f"   Total Candidates: {stats['total_candidates']}")
        print(f"   Successfully Labeled: {stats['successful_labels']}")
        print(f"   Failed Labels: {stats['failed_labels']}")
        print(f"   Success Rate: {stats['success_rate']:.1%}")
        print(f"\n🎯 LABEL DISTRIBUTION:")
        dist = stats['label_distribution']
        print(f"   Sources: {dist['sources']}")
        print(f"   Sinks: {dist['sinks']}")
        print(f"   Taint Propagators: {dist['taint_propagators']}")
        print(f"   Sanitizers: {dist['sanitizers']}")
        print(f"   Neutral: {dist['neutral']}")
        print(f"\n📦 BATCH STATISTICS:")
        print(f"   Total Batches: {stats['processed_batches']}")
        print(f"   Successful Batches: {stats['successful_batches']}")
        print(f"   Failed Batches: {stats['failed_batches']}")
        print(f"   Total Retries: {stats['total_retries']}")
        print(f"\n📁 Output saved to: {results['project']}/api_labelling/")
        print(f"="*60)


def main():
    parser = argparse.ArgumentParser(description="Enhanced API Candidate Labelling with Multiple LLM Support")
    parser.add_argument("--project", help="Project name to process")
    parser.add_argument("--model", default="gpt-4", 
                       help="LLM model to use. Options: gpt-4, gpt-4-turbo, gpt-3.5-turbo (OpenAI), "
                            "claude-3-opus, claude-3-sonnet (Anthropic), "
                            "gemini-pro (Google), "
                            "llama3.1:8b, codellama:7b (Ollama), "
                            "deepseek-r1-7b, qwen2.5-32b (HuggingFace)")
    parser.add_argument("--max-candidates", type=int, default=300, help="Max candidates per project")
    parser.add_argument("--batch-size", type=int, default=30, help="Batch size for processing")
    parser.add_argument("--run-id", default="0", help="Run ID (default: 0, auto-increments if exists)")
    parser.add_argument("--max-retries", type=int, default=3, help="Maximum retry attempts per batch")
    parser.add_argument("--list-projects", action="store_true", help="List available projects")
    parser.add_argument("--allow-remote", action="store_true", help="Allow remote/cloud LLM APIs (OpenAI/Anthropic/Google)")
    parser.add_argument("--hf-4bit", action="store_true", default=False, help="Use 4-bit quantization for local HF models (default: off)")
    parser.add_argument("--no-hf-4bit", dest="hf_4bit", action="store_false", help="Disable 4-bit quantization for local HF models")
    parser.add_argument("--max-new-tokens", type=int, default=256, help="Max new tokens to generate per response (speed control)")
    parser.add_argument("--temperature", type=float, default=0.0, help="Sampling temperature (0.0 = greedy)")
    parser.add_argument("--max-input-tokens", type=int, default=8192, help="Max input tokens (truncation limit)")
    parser.add_argument("--no-codeql", action="store_true", help="Skip automatic CodeQL query generation after API labeling")
    
    args = parser.parse_args()
    
    labeller = EnhancedAPILabeller(
        model_name=args.model, 
        max_candidates=args.max_candidates, 
        batch_size=args.batch_size, 
        run_id=args.run_id,
        max_retries=args.max_retries,
        allow_remote=args.allow_remote,
        hf_4bit=args.hf_4bit,
        max_new_tokens=args.max_new_tokens,
        temperature=args.temperature,
        max_input_tokens=args.max_input_tokens,
        no_codeql=args.no_codeql
    )
    
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
            print("💡 Run 04_filter_api_candidates.py first to generate candidates")
            return
        print(f"\n📁 Available projects: {', '.join(projects)}")
        print("Use --project <n> to process a specific project")
        return
    
    try:
        print(f"\n🚀 Starting enhanced API labeling...")
        print(f"🎯 Target: {args.project}")
        print(f"🤖 Model: {args.model}")
        print(f"⚙️  Config: {args.max_candidates} candidates, batch size {args.batch_size}, {args.max_retries} retries")
        
        result = labeller.process_project(args.project)
        
        print(f"\n🎉 Processing completed successfully!")
        print(f"📁 Results saved in: output/{args.project}/api_labelling/")
        
        # Show quick stats
        stats = result.get('statistics', {})
        if stats:
            print(f"📊 Quick Stats: {stats.get('successful_labels', 0)}/{stats.get('total_candidates', 0)} "
                  f"APIs labeled ({stats.get('success_rate', 0):.1%} success rate)")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Process interrupted by user")
    except Exception as e:
        print(f"\n❌ Processing failed: {e}")
        print(f"💡 Try with a different model or check your API keys")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
