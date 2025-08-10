"""
Prompts for LLM-based API security classification
Following IRIS approach for Python security analysis
"""

def get_system_prompt() -> str:
    """
    System prompt for API security classification
    Based on IRIS methodology for taint analysis
    """
    return """You are a Python security expert analyzing APIs for potential security vulnerabilities.

Your task is to classify each API call as one of five types:
- "source": APIs that return user-controlled or external data (e.g., request parameters, file reads, network inputs)
- "sink": APIs that perform dangerous operations with untrusted data (e.g., code execution, file writes, database queries)
- "taint-propagator": APIs that transform/pass data without sanitization (e.g., string operations, parsing)
- "sanitizer": APIs that clean/validate data to remove security risks (e.g., escaping, validation)
- "neutral": APIs that are not security-relevant (e.g., math operations, date/time)

For sinks, specify which arguments are dangerous using their parameter names or positions.

Return ONLY a JSON list with this exact format:
[
  {
    "module": "<module_name>",
    "function": "<function_name>", 
    "signature": "<full_signature>",
    "type": "<source|sink|taint-propagator|sanitizer|neutral>",
    "sink_args": ["<arg1>", "<arg2>"]
  }
]

DO NOT OUTPUT ANYTHING OTHER THAN THE JSON LIST."""


def get_few_shot_examples():
    """
    Few-shot examples for Python security analysis
    Based on IRIS training data and common vulnerability patterns
    """
    return [
        # Source examples - APIs that introduce external/user data
        {
            "module": "flask",
            "function": "request.args.get",
            "signature": "flask.request.args.get",
            "type": "source",
            "sink_args": [],
            "description": "HTTP request parameter - user controlled input"
        },
        {
            "module": "sys", 
            "function": "argv",
            "signature": "sys.argv",
            "type": "source",
            "sink_args": [],
            "description": "Command line arguments - external input"
        },
        {
            "module": "os.environ",
            "function": "get",
            "signature": "os.environ.get",
            "type": "source", 
            "sink_args": [],
            "description": "Environment variables - external configuration"
        },
        
        # Sink examples - APIs that perform dangerous operations
        {
            "module": "subprocess",
            "function": "run",
            "signature": "subprocess.run",
            "type": "sink",
            "sink_args": ["args", "shell"],
            "description": "Command execution - dangerous with untrusted input"
        },
        {
            "module": "os",
            "function": "system",
            "signature": "os.system",
            "type": "sink",
            "sink_args": ["command"],
            "description": "Shell command execution - code injection risk"
        },
        {
            "module": "eval",
            "function": "__builtin__.eval",
            "signature": "eval",
            "type": "sink",
            "sink_args": ["source"],
            "description": "Dynamic code evaluation - code injection"
        },
        
        # Taint propagator examples - APIs that pass data through
        {
            "module": "json",
            "function": "loads",
            "signature": "json.loads",
            "type": "taint-propagator",
            "sink_args": [],
            "description": "JSON parsing - preserves taint from input to output"
        },
        {
            "module": "urllib.parse",
            "function": "unquote",
            "signature": "urllib.parse.unquote",
            "type": "taint-propagator", 
            "sink_args": [],
            "description": "URL decoding - transforms but preserves taint"
        },
        {
            "module": "str",
            "function": "format",
            "signature": "str.format",
            "type": "taint-propagator",
            "sink_args": [],
            "description": "String formatting - combines tainted and clean data"
        },
        
        # Sanitizer examples - APIs that clean/validate data
        {
            "module": "html",
            "function": "escape",
            "signature": "html.escape",
            "type": "sanitizer",
            "sink_args": [],
            "description": "HTML escaping - removes XSS injection risk"
        },
        {
            "module": "re",
            "function": "escape",
            "signature": "re.escape",
            "type": "sanitizer",
            "sink_args": [],
            "description": "Regex escaping - removes regex injection"
        },
        {
            "module": "urllib.parse",
            "function": "quote",
            "signature": "urllib.parse.quote", 
            "type": "sanitizer",
            "sink_args": [],
            "description": "URL encoding - sanitizes for URL context"
        },
        
        # Neutral examples - APIs with no security implications
        {
            "module": "math",
            "function": "sqrt",
            "signature": "math.sqrt",
            "type": "neutral",
            "sink_args": [],
            "description": "Mathematical operation - no security relevance"
        },
        {
            "module": "datetime",
            "function": "now",
            "signature": "datetime.now", 
            "type": "neutral",
            "sink_args": [],
            "description": "Date/time function - no security relevance"
        },
        {
            "module": "random",
            "function": "random",
            "signature": "random.random",
            "type": "neutral",
            "sink_args": [],
            "description": "Random number generation - no security impact"
        }
    ]


def create_user_prompt(candidates, include_descriptions=False):
    """
    Create user prompt with few-shot examples and candidates to classify
    
    Args:
        candidates: List of API candidates to classify
        include_descriptions: Whether to include example descriptions (for debugging)
    """
    examples = get_few_shot_examples()
    
    # Format few-shot examples
    examples_text = "Here are examples of different API types:\n\n"
    for ex in examples:
        examples_text += f"Module: {ex['module']}, Function: {ex['function']}, Type: {ex['type']}"
        if include_descriptions:
            examples_text += f" ({ex['description']})"
        examples_text += "\n"
    
    # Format candidates to classify
    candidates_text = "\n\nAnalyze these API candidates:\n\n"
    for candidate in candidates:
        candidates_text += f"Module: {candidate['module']}, Function: {candidate['function']}, Signature: {candidate['signature']}\n"
    
    instruction = "\n\nClassify each API according to the security types defined above. Focus on the potential security impact of each API in a taint analysis context."
    
    return examples_text + candidates_text + instruction


# IRIS-style prompt configuration
PROMPT_CONFIG = {
    "model_instructions": {
        "temperature": 0.1,
        "max_tokens": 2048, 
        "top_p": 0.9,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0
    },
    "classification_types": {
        "source": "APIs that introduce external or user-controlled data into the program",
        "sink": "APIs that perform operations that could be dangerous with untrusted data", 
        "taint-propagator": "APIs that transform or pass data without removing potential taint",
        "sanitizer": "APIs that clean, validate, or escape data to remove security risks",
        "neutral": "APIs that have no security relevance in taint analysis"
    },
    "output_format": {
        "type": "json_list",
        "required_fields": ["module", "function", "signature", "type", "sink_args"],
        "strict_mode": True
    }
}