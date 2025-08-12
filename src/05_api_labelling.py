"""
API Labelling Module

This module performs LLM-based labelling of security-relevant APIs to classify them
as sources, sinks, or propagators for specific CWE vulnerabilities.

Supports multiple LLM providers with model-specific configurations.
Output structure follows: output/<project>/<model_name>_run<id>/{prompts,responses,statistics}/

Classifications: source, sink, propagator (3 types only)
"""

import argparse
import json
import logging
import os
import subprocess
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import importlib

# Import CWE examples and model configurations
from cwe_examples import get_cwe_examples, get_cwe_description

# Setup logging
def setup_logging(project_name: str) -> logging.Logger:
    """Setup logging with timestamp and project-specific log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_dir = Path("_logs")  # Root level _logs directory
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / f"api_labelling_{timestamp}.txt"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Starting API labelling for project: {project_name}")
    logger.info(f"Log file: {log_file}")
    return logger


def extract_cwe_from_project(project_name: str) -> str:
    """Extract CWE number from project name.
    
    Args:
        project_name: Project name like 'apache_airflow_cwe-22'
        
    Returns:
        CWE number as string (e.g., '22')
    """
    match = re.search(r'cwe-?(\d+)', project_name.lower())
    if match:
        return match.group(1)
    return "22"  # Default to CWE-22 if not found


def load_model_config(model_name: str) -> Dict[str, Any]:
    """Load model configuration from src/models/ directory.
    
    Args:
        model_name: Full model name
        
    Returns:
        Model configuration dictionary
    """
    # Default configuration
    default_config = {
        "temperature": 0,
        "max_tokens": 4096,
        "model_type": "huggingface"
    }
    
    # Try to determine model type and load config
    model_lower = model_name.lower()
    
    if any(name in model_lower for name in ['gpt', 'openai']):
        try:
            from models.gpt import _OPENAI_DEFAULT_PARAMS, _model_name_map
            default_config.update(_OPENAI_DEFAULT_PARAMS)
            default_config["model_type"] = "openai"
            default_config["actual_model_name"] = _model_name_map.get(model_name, model_name)
        except ImportError:
            pass
    elif any(name in model_lower for name in ['qwen']):
        try:
            from models.qwen import _model_name_map
            default_config["model_type"] = "huggingface"
            default_config["actual_model_name"] = _model_name_map.get(model_name, model_name)
        except ImportError:
            pass
    elif any(name in model_lower for name in ['deepseek']):
        try:
            from models.deepseek import _model_name_map
            default_config["model_type"] = "huggingface" 
            default_config["actual_model_name"] = _model_name_map.get(model_name, model_name)
        except ImportError:
            pass
    
    return default_config
    
    logger = logging.getLogger(__name__)
    logger.info(f"Starting API labelling for project: {project_name}")
    logger.info(f"Log file: {log_file}")
    return logger


class LLMProvider:
    """Base class for LLM providers."""
    
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.total_tokens = 0
        self.total_requests = 0
    
    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> Dict[str, Any]:
        """Generate response from LLM."""
        raise NotImplementedError
    
    def cleanup(self):
        """Cleanup resources."""
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""
    
    def __init__(self, model_name: str):
        super().__init__(model_name)
        try:
            import openai
            self.client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        except ImportError:
            raise ImportError("openai package required for GPT models. Install with: pip install openai")
        
        if not os.getenv('OPENAI_API_KEY'):
            raise ValueError("OPENAI_API_KEY environment variable required for GPT models")
    
    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> Dict[str, Any]:
        """Generate response using OpenAI API."""
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=temperature,
                max_tokens=4000
            )
            
            self.total_requests += 1
            self.total_tokens += response.usage.total_tokens
            
            return {
                "response": response.choices[0].message.content,
                "tokens": response.usage.total_tokens,
                "success": True
            }
        except Exception as e:
            return {
                "response": "",
                "tokens": 0,
                "success": False,
                "error": str(e)
            }


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""
    
    def __init__(self, model_name: str):
        super().__init__(model_name)
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
        except ImportError:
            raise ImportError("anthropic package required for Claude models. Install with: pip install anthropic")
        
        if not os.getenv('ANTHROPIC_API_KEY'):
            raise ValueError("ANTHROPIC_API_KEY environment variable required for Claude models")
    
    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> Dict[str, Any]:
        """Generate response using Anthropic API."""
        try:
            response = self.client.messages.create(
                model=self.model_name,
                max_tokens=4000,
                temperature=temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}]
            )
            
            self.total_requests += 1
            # Anthropic doesn't provide token count in response, estimate
            estimated_tokens = len(system_prompt + user_prompt + response.content[0].text) // 4
            self.total_tokens += estimated_tokens
            
            return {
                "response": response.content[0].text,
                "tokens": estimated_tokens,
                "success": True
            }
        except Exception as e:
            return {
                "response": "",
                "tokens": 0,
                "success": False,
                "error": str(e)
            }


class GoogleProvider(LLMProvider):
    """Google Gemini provider."""
    
    def __init__(self, model_name: str):
        super().__init__(model_name)
        try:
            import google.generativeai as genai
            genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
            self.model = genai.GenerativeModel(model_name)
        except ImportError:
            raise ImportError("google-generativeai package required for Gemini models. Install with: pip install google-generativeai")
        
        if not os.getenv('GOOGLE_API_KEY'):
            raise ValueError("GOOGLE_API_KEY environment variable required for Gemini models")
    
    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> Dict[str, Any]:
        """Generate response using Google API."""
        try:
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            response = self.model.generate_content(
                full_prompt,
                generation_config={"temperature": temperature, "max_output_tokens": 4000}
            )
            
            self.total_requests += 1
            # Estimate tokens for Google
            estimated_tokens = len(full_prompt + response.text) // 4
            self.total_tokens += estimated_tokens
            
            return {
                "response": response.text,
                "tokens": estimated_tokens,
                "success": True
            }
        except Exception as e:
            return {
                "response": "",
                "tokens": 0,
                "success": False,
                "error": str(e)
            }


class HuggingFaceProvider(LLMProvider):
    """Local HuggingFace model provider with CUDA support."""
    
    def __init__(self, model_name: str, actual_model_name: str = None):
        super().__init__(model_name)
        self.actual_model_name = actual_model_name or model_name
        self.tokenizer = None
        self.model = None
        self.device = None
        self._load_model()
    
    def _load_model(self):
        """Load model from HuggingFace with CUDA support."""
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForCausalLM
            
            # Check for CUDA
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            print(f"Loading {self.actual_model_name} on {self.device}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.actual_model_name,
                trust_remote_code=True,
                padding_side="left"
            )
            
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # Load model with appropriate settings
            model_kwargs = {
                "trust_remote_code": True,
                "torch_dtype": torch.float16 if self.device == "cuda" else torch.float32,
            }
            
            if self.device == "cuda":
                model_kwargs["device_map"] = "auto"
            
            self.model = AutoModelForCausalLM.from_pretrained(
                self.actual_model_name,
                **model_kwargs
            )
            
            if self.device == "cpu":
                self.model = self.model.to(self.device)
            
            print(f"Model {self.actual_model_name} loaded successfully on {self.device}")
            
        except ImportError:
            raise ImportError("torch and transformers required for local models. Install with: pip install torch transformers accelerate")
        except Exception as e:
            raise RuntimeError(f"Failed to load model {self.actual_model_name}: {e}")
    
    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> Dict[str, Any]:
        """Generate response using local HuggingFace model."""
        try:
            import torch
            
            # Format prompt (adjust based on model requirements)
            if "qwen" in self.actual_model_name.lower():
                formatted_prompt = f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{user_prompt}<|im_end|>\n<|im_start|>assistant\n"
            elif "llama" in self.actual_model_name.lower():
                formatted_prompt = f"<s>[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n\n{user_prompt} [/INST]"
            else:
                # Generic format
                formatted_prompt = f"System: {system_prompt}\n\nUser: {user_prompt}\n\nAssistant:"
            
            # Tokenize
            inputs = self.tokenizer(
                formatted_prompt,
                return_tensors="pt",
                truncation=True,
                max_length=2048
            ).to(self.device)
            
            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=1024,
                    temperature=temperature if temperature > 0 else 0.1,
                    do_sample=temperature > 0,
                    pad_token_id=self.tokenizer.eos_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                )
            
            # Decode response (remove input prompt)
            input_length = inputs['input_ids'].shape[1]
            response_tokens = outputs[0][input_length:]
            response = self.tokenizer.decode(response_tokens, skip_special_tokens=True)
            
            self.total_requests += 1
            total_tokens = outputs[0].shape[1]
            self.total_tokens += total_tokens
            
            return {
                "response": response.strip(),
                "tokens": total_tokens,
                "success": True
            }
            
        except Exception as e:
            return {
                "response": "",
                "tokens": 0,
                "success": False,
                "error": str(e)
            }
    
    def cleanup(self):
        """Cleanup CUDA memory."""
        if self.model is not None:
            del self.model
        if self.tokenizer is not None:
            del self.tokenizer
        
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except ImportError:
            pass


def create_llm_provider(model_name: str, model_config: Dict[str, Any] = None) -> LLMProvider:
    """Factory function to create appropriate LLM provider."""
    if model_config is None:
        model_config = load_model_config(model_name)
    
    model_lower = model_name.lower()
    actual_model_name = model_config.get("actual_model_name", model_name)
    
    if any(provider in model_lower for provider in ['gpt', 'openai']):
        return OpenAIProvider(actual_model_name)
    elif any(provider in model_lower for provider in ['claude', 'anthropic']):
        return AnthropicProvider(actual_model_name)
    elif any(provider in model_lower for provider in ['gemini', 'google']):
        return GoogleProvider(actual_model_name)
    else:
        # Use HuggingFace model with proper name mapping
        return HuggingFaceProvider(model_name, actual_model_name)


def load_api_candidates(json_path: Path) -> List[Dict[str, Any]]:
    """Load API candidates from JSON file."""
    with open(json_path, 'r', encoding='utf-8') as f:
        candidates = json.load(f)
    
    # Ensure required fields
    for candidate in candidates:
        for field in ['module_name', 'func_name', 'full_signature']:
            if field not in candidate:
                candidate[field] = ""
    
    return candidates


def create_batches(candidates: List[Dict[str, Any]], batch_size: int, max_candidates: int) -> List[List[Dict[str, Any]]]:
    """Create batches of API candidates for processing."""
    # Limit to max_candidates
    limited_candidates = candidates[:max_candidates]
    
    # Create batches
    batches = []
    for i in range(0, len(limited_candidates), batch_size):
        batch = limited_candidates[i:i + batch_size]
        batches.append(batch)
    
    return batches


def build_prompts(batch: List[Dict[str, Any]], cwe_id: str) -> Tuple[str, str]:
    """Build system and user prompts for a batch of API candidates.
    
    Args:
        batch: List of API candidate dictionaries
        cwe_id: CWE identifier for specific examples
        
    Returns:
        Tuple of (system_prompt, user_prompt)
    """
    cwe_info = get_cwe_description(cwe_id)
    cwe_examples = get_cwe_examples(cwe_id)
    
    # Build system prompt with 3-class classification
    system_prompt = f"""You are a Python security expert analyzing APIs for {cwe_info['name']} vulnerabilities (CWE-{cwe_id}).

Your task is to classify each API call as exactly one of three types:
- "source": APIs that return user-controlled or external data (e.g., request parameters, file reads, network inputs)
- "sink": APIs that perform dangerous operations with untrusted data (e.g., code execution, file writes, database queries)
- "propagator": APIs that transform/pass data without sanitization (e.g., string operations, parsing)

Context: {cwe_info['description']}
Focus: {cwe_info['context']}

For sinks, specify which arguments are dangerous using their parameter names or positions.

Return ONLY a JSON list with this exact format:
[
  {{
    "module": "<module_name>",
    "function": "<function_name>", 
    "signature": "<full_signature>",
    "type": "<source|sink|propagator>",
    "sink_args": ["<arg1>", "<arg2>"]
  }}
]

DO NOT OUTPUT ANYTHING OTHER THAN THE JSON LIST."""

    # Build user prompt with few-shot examples and batch
    user_prompt = f"VULNERABILITY: {cwe_info['name']} (CWE-{cwe_id})\n\n"
    
    # Add few-shot examples
    if cwe_examples:
        user_prompt += "EXAMPLES:\n"
        for i, example in enumerate(cwe_examples, 1):
            user_prompt += f"{i}. Module: {example['module']}\n"
            user_prompt += f"   Function: {example['function']}\n"
            user_prompt += f"   Signature: {example['signature']}\n"
            user_prompt += f"   Type: {example['type']}\n"
            if example.get('sink_args'):
                user_prompt += f"   Sink args: {example['sink_args']}\n"
            user_prompt += f"   Reason: {example['description']}\n\n"
    
    user_prompt += "ANALYZE THE FOLLOWING APIS:\n\n"
    
    # Add batch APIs to analyze
    for i, candidate in enumerate(batch, 1):
        module = candidate.get('module_name', '')
        func = candidate.get('func_name', '')
        signature = candidate.get('full_signature', '')
        
        user_prompt += f"{i}. Module: {module}\n"
        user_prompt += f"   Function: {func}\n"
        user_prompt += f"   Signature: {signature}\n\n"
    
    user_prompt += f"Return the JSON classification for all {len(batch)} APIs listed above."
    
    return system_prompt, user_prompt


def save_batch_files(batch_id: int, system_prompt: str, user_prompt: str, response: Dict[str, Any], 
                    prompts_dir: Path, responses_dir: Path):
    """Save batch prompt and response files in organized directory structure."""
    
    # Save prompt file
    prompt_file = prompts_dir / f"batch_{batch_id:03d}_prompt.txt"
    with open(prompt_file, 'w', encoding='utf-8') as f:
        f.write("=== SYSTEM PROMPT ===\n")
        f.write(system_prompt)
        f.write("\n\n=== USER PROMPT ===\n")
        f.write(user_prompt)
    
    # Save response file
    response_file = responses_dir / f"batch_{batch_id:03d}_response.json"
    with open(response_file, 'w', encoding='utf-8') as f:
        json.dump(response, f, indent=2, ensure_ascii=False)


def parse_llm_response(response_text: str) -> List[Dict[str, Any]]:
    """Parse LLM response to extract API classifications."""
    try:
        # Try to find JSON in response
        response_text = response_text.strip()
        
        # Look for JSON array
        start_idx = response_text.find('[')
        end_idx = response_text.rfind(']') + 1
        
        if start_idx >= 0 and end_idx > start_idx:
            json_text = response_text[start_idx:end_idx]
            parsed = json.loads(json_text)
            
            if isinstance(parsed, list):
                return parsed
        
        # If no valid JSON found, return empty list
        return []
        
    except json.JSONDecodeError:
        return []
    except Exception:
        return []


def generate_statistics(all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate statistical analysis of LLM labelling results."""
    if not all_results:
        return {"error": "No results to analyze"}
    
    # Count classifications (3 types now)
    type_counts = {"source": 0, "sink": 0, "propagator": 0, "unknown": 0}
    total_apis = len(all_results)
    
    for result in all_results:
        api_type = result.get('type', 'unknown')
        if api_type in type_counts:
            type_counts[api_type] += 1
        else:
            type_counts['unknown'] += 1
    
    # Calculate percentages
    type_percentages = {
        api_type: (count / total_apis) * 100 
        for api_type, count in type_counts.items()
    }
    
    # Count sink arguments
    sink_arg_counts = {}
    sinks_with_args = 0
    
    for result in all_results:
        if result.get('type') == 'sink':
            sink_args = result.get('sink_args', [])
            if sink_args:
                sinks_with_args += 1
                for arg in sink_args:
                    sink_arg_counts[arg] = sink_arg_counts.get(arg, 0) + 1
    
    # Module analysis
    module_stats = {}
    for result in all_results:
        module = result.get('module', 'unknown')
        if module not in module_stats:
            module_stats[module] = {"source": 0, "sink": 0, "propagator": 0}
        api_type = result.get('type', 'unknown')
        if api_type in module_stats[module]:
            module_stats[module][api_type] += 1
    
    return {
        "total_apis_analyzed": total_apis,
        "classification_distribution": {
            "counts": type_counts,
            "percentages": type_percentages
        },
        "sink_analysis": {
            "total_sinks": type_counts.get('sink', 0),
            "sinks_with_dangerous_args": sinks_with_args,
            "common_dangerous_args": dict(sorted(sink_arg_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        },
        "data_flow_summary": {
            "sources": type_counts.get('source', 0),
            "sinks": type_counts.get('sink', 0),
            "propagators": type_counts.get('propagator', 0),
            "source_to_sink_ratio": round(type_counts.get('source', 0) / max(type_counts.get('sink', 1), 1), 2)
        },
        "module_breakdown": dict(sorted(module_stats.items(), key=lambda x: sum(x[1].values()), reverse=True)[:20])
    }


def main():
    """Main entry point for API labelling."""
    parser = argparse.ArgumentParser(description='LLM-based API security labelling')
    parser.add_argument('--project', required=True, help='Project name to process')
    parser.add_argument('--model', required=True, help='LLM model to use')
    parser.add_argument('--batch-size', type=int, default=20, help='Number of APIs per batch')
    parser.add_argument('--max-candidates', type=int, default=1000, help='Maximum number of API candidates to process')
    parser.add_argument('--run-id', default='01', help='Run identifier for output files')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.project)
    
    try:
        # Extract CWE from project name
        cwe_id = extract_cwe_from_project(args.project)
        logger.info(f"Detected CWE-{cwe_id} from project name: {args.project}")
        
        # Load model configuration
        model_config = load_model_config(args.model)
        logger.info(f"Model config: {model_config}")
        
        # Setup paths with new directory structure
        input_path = Path(f"output/{args.project}/api_candidates/filtered_api_candidates.json")
        
        # Create output directory: output/<project>/<model_name>_run<id>/
        model_run_dir = Path(f"output/{args.project}/{args.model}_run{args.run_id}")
        prompts_dir = model_run_dir / "prompts"
        responses_dir = model_run_dir / "responses" 
        statistics_dir = model_run_dir / "statistics"
        
        # Create all directories
        for directory in [prompts_dir, responses_dir, statistics_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        if not input_path.exists():
            raise FileNotFoundError(f"API candidates file not found: {input_path}")
        
        logger.info(f"Loading API candidates from: {input_path}")
        candidates = load_api_candidates(input_path)
        logger.info(f"Loaded {len(candidates)} API candidates")
        
        # Create batches
        batches = create_batches(candidates, args.batch_size, args.max_candidates)
        logger.info(f"Created {len(batches)} batches (batch_size={args.batch_size}, max_candidates={args.max_candidates})")
        
        # Initialize LLM provider
        logger.info(f"Initializing LLM provider: {args.model}")
        provider = create_llm_provider(args.model, model_config)
        
        # Process batches
        all_results = []
        failed_batches = []
        
        for batch_id, batch in enumerate(batches, 1):
            logger.info(f"Processing batch {batch_id}/{len(batches)} ({len(batch)} APIs)")
            
            # Build prompts with CWE-specific examples
            system_prompt, user_prompt = build_prompts(batch, cwe_id)
            
            # Generate response with temperature=0 from config
            start_time = time.time()
            response = provider.generate(system_prompt, user_prompt, model_config.get("temperature", 0))
            end_time = time.time()
            
            # Save batch files in organized structure
            save_batch_files(batch_id, system_prompt, user_prompt, response, prompts_dir, responses_dir)
            
            if response['success']:
                # Parse results
                batch_results = parse_llm_response(response['response'])
                all_results.extend(batch_results)
                
                logger.info(f"Batch {batch_id} completed successfully: {len(batch_results)} APIs classified "
                           f"({response['tokens']} tokens, {end_time - start_time:.1f}s)")
            else:
                failed_batches.append(batch_id)
                logger.error(f"Batch {batch_id} failed: {response.get('error', 'Unknown error')}")
            
            # Small delay between requests
            time.sleep(1)
        
        # Generate final outputs
        logger.info("Generating aggregated results and statistics...")
        
        # Save aggregated results as labeled_apis.json (for next stage)
        labeled_apis_file = model_run_dir / "labeled_apis.json"
        with open(labeled_apis_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        
        # Also save to statistics directory with run ID
        results_file = statistics_dir / f"api_labelling_results_{args.run_id}.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        
        # Generate and save statistics
        stats = generate_statistics(all_results)
        stats_file = statistics_dir / f"api_labelling_statistics_{args.run_id}.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        # Summary
        logger.info(f"✅ API labelling completed!")
        logger.info(f"📊 Total APIs processed: {len(all_results)}")
        logger.info(f"📁 Main results: {labeled_apis_file}")
        logger.info(f"📁 Detailed results: {results_file}")
        logger.info(f"📈 Statistics saved to: {stats_file}")
        logger.info(f"📝 Total LLM requests: {provider.total_requests}")
        logger.info(f"🔢 Total tokens used: {provider.total_tokens}")
        logger.info(f"📂 Output directory: {model_run_dir}")
        
        if failed_batches:
            logger.warning(f"⚠️  Failed batches: {failed_batches}")
        
        # Cleanup
        provider.cleanup()
        
        # Print labeled_apis.json path for next stage integration (the main file that next stage expects)
        print(str(labeled_apis_file))
        
        # Automatically trigger next stage 
        logger.info(f"🔗 Automatically calling build_project_specific_query.py...")
        
        # Import and call the next stage
        try:
            result = subprocess.run([
                'python', 'src/06_build_project_specific_query.py',
                '--project', args.project
            ], capture_output=True, text=True, cwd=os.getcwd())
            
            if result.returncode == 0:
                logger.info(f"✅ Successfully built project-specific queries!")
                logger.info(f"📁 CodeQL query generation completed")
            else:
                logger.warning(f"⚠️  Query building had issues: {result.stderr}")
                logger.info(f"📋 You can manually run: python src/06_build_project_specific_query.py --project {args.project}")
                
        except Exception as e:
            logger.warning(f"⚠️  Could not automatically call next stage: {e}")
            logger.info(f"📋 Manual next step: python src/06_build_project_specific_query.py --project {args.project}")
        
        return str(labeled_apis_file)
        
    except Exception as e:
        logger.error(f"❌ API labelling failed: {e}")
        raise


if __name__ == "__main__":
    main()
