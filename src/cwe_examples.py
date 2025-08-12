"""
CWE-specific few-shot examples for API security classification

This module provides security examples tailored to specific CWE categories:
- CWE-22: Path Traversal
- CWE-78: OS Command Injection  
- CWE-79: Cross-Site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-94: Code Injection

Each CWE includes 6 examples: 2 sources, 2 sinks, 2 propagators
"""

from typing import Dict, List, Any

# CWE-22: Path Traversal Examples
CWE_22_EXAMPLES = [
    # Sources - APIs that return user-controlled file paths
    {
        "module": "flask.request",
        "function": "args.get",
        "signature": "flask.request.args.get('filename')",
        "type": "source",
        "sink_args": [],
        "description": "HTTP parameter containing filename - user controlled path input"
    },
    {
        "module": "os.environ", 
        "function": "get",
        "signature": "os.environ.get('UPLOAD_PATH')",
        "type": "source",
        "sink_args": [],
        "description": "Environment variable path - external configuration"
    },
    # Sinks - APIs that perform file operations with paths
    {
        "module": "builtins",
        "function": "open",
        "signature": "open(filename, mode='r')",
        "type": "sink",
        "sink_args": ["filename"],
        "description": "File open operation - dangerous with untrusted paths"
    },
    {
        "module": "shutil",
        "function": "copyfile", 
        "signature": "shutil.copyfile(src, dst)",
        "type": "sink",
        "sink_args": ["src", "dst"],
        "description": "File copy operation - path traversal risk"
    },
    # Propagators - APIs that manipulate paths without validation
    {
        "module": "os.path",
        "function": "join",
        "signature": "os.path.join(base_path, user_input)",
        "type": "propagator",
        "sink_args": [],
        "description": "Path joining - passes untrusted path components"
    },
    {
        "module": "pathlib.Path",
        "function": "__truediv__",
        "signature": "Path(base) / user_path",
        "type": "propagator", 
        "sink_args": [],
        "description": "Path concatenation - preserves taint through path operations"
    }
]

# CWE-78: OS Command Injection Examples  
CWE_78_EXAMPLES = [
    # Sources - APIs that return user-controlled command input
    {
        "module": "sys",
        "function": "argv",
        "signature": "sys.argv[1]",
        "type": "source",
        "sink_args": [],
        "description": "Command line arguments - user controlled input"
    },
    {
        "module": "flask.request",
        "function": "form.get",
        "signature": "flask.request.form.get('command')",
        "type": "source", 
        "sink_args": [],
        "description": "Form parameter - user controlled command input"
    },
    # Sinks - APIs that execute OS commands
    {
        "module": "subprocess",
        "function": "call",
        "signature": "subprocess.call(cmd, shell=True)",
        "type": "sink",
        "sink_args": ["cmd"],
        "description": "Command execution with shell - injection risk"
    },
    {
        "module": "os",
        "function": "system",
        "signature": "os.system(command)",
        "type": "sink",
        "sink_args": ["command"],
        "description": "Shell command execution - direct injection vector"
    },
    # Propagators - APIs that manipulate command strings
    {
        "module": "str",
        "function": "format",
        "signature": "cmd_template.format(user_input)",
        "type": "propagator",
        "sink_args": [],
        "description": "String formatting - passes tainted data to command strings"
    },
    {
        "module": "str",
        "function": "__add__", 
        "signature": "'cmd ' + user_input",
        "type": "propagator",
        "sink_args": [],
        "description": "String concatenation - builds command with tainted input"
    }
]

# CWE-79: Cross-Site Scripting Examples
CWE_79_EXAMPLES = [
    # Sources - APIs that return user-controlled web input
    {
        "module": "flask.request",
        "function": "args.get",
        "signature": "flask.request.args.get('search')",
        "type": "source",
        "sink_args": [],
        "description": "URL parameter - user controlled web input"
    },
    {
        "module": "django.http.HttpRequest",
        "function": "POST.get",
        "signature": "request.POST.get('comment')",
        "type": "source",
        "sink_args": [],
        "description": "POST data - user controlled form input"
    },
    # Sinks - APIs that output data to web responses
    {
        "module": "flask",
        "function": "render_template_string",
        "signature": "flask.render_template_string(template)",
        "type": "sink",
        "sink_args": ["template"],
        "description": "Template rendering - XSS if user input in template"
    },
    {
        "module": "django.http.HttpResponse",
        "function": "__init__",
        "signature": "HttpResponse(content)",
        "type": "sink",
        "sink_args": ["content"],
        "description": "HTTP response - XSS if unescaped user content"
    },
    # Propagators - APIs that manipulate web content
    {
        "module": "str",
        "function": "replace",
        "signature": "template.replace('{{data}}', user_input)",
        "type": "propagator",
        "sink_args": [],
        "description": "String replacement - passes tainted data to templates"
    },
    {
        "module": "str",
        "function": "format",
        "signature": "'<div>{}</div>'.format(user_input)",
        "type": "propagator",
        "sink_args": [],
        "description": "HTML formatting - embeds tainted data in markup"
    }
]

# CWE-89: SQL Injection Examples
CWE_89_EXAMPLES = [
    # Sources - APIs that return user-controlled database input
    {
        "module": "flask.request", 
        "function": "json.get",
        "signature": "flask.request.json.get('user_id')",
        "type": "source",
        "sink_args": [],
        "description": "JSON API input - user controlled database parameter"
    },
    {
        "module": "urllib.parse",
        "function": "parse_qs",
        "signature": "urllib.parse.parse_qs(query_string)['id'][0]",
        "type": "source",
        "sink_args": [],
        "description": "Query string parsing - user controlled URL parameter"
    },
    # Sinks - APIs that execute SQL queries
    {
        "module": "sqlite3.Cursor",
        "function": "execute",
        "signature": "cursor.execute(query)",
        "type": "sink",
        "sink_args": ["query"],
        "description": "SQL execution - injection risk with dynamic queries"
    },
    {
        "module": "sqlalchemy.engine.Engine",
        "function": "execute",
        "signature": "engine.execute(sql_text)",
        "type": "sink",
        "sink_args": ["sql_text"],
        "description": "SQLAlchemy execution - SQL injection vulnerability"
    },
    # Propagators - APIs that build SQL strings
    {
        "module": "str",
        "function": "format",
        "signature": "'SELECT * FROM users WHERE id={}'.format(user_id)",
        "type": "propagator",
        "sink_args": [],
        "description": "SQL string building - passes tainted data to queries"
    },
    {
        "module": "str",
        "function": "__mod__",
        "signature": "'SELECT * FROM table WHERE col=%s' % (user_input,)",
        "type": "propagator",
        "sink_args": [],
        "description": "SQL string interpolation - embeds user data in queries"
    }
]

# CWE-94: Code Injection Examples
CWE_94_EXAMPLES = [
    # Sources - APIs that return user-controlled code input
    {
        "module": "flask.request",
        "function": "data.decode",
        "signature": "flask.request.data.decode('utf-8')",
        "type": "source",
        "sink_args": [],
        "description": "Raw request body - user controlled code input"
    },
    {
        "module": "json",
        "function": "loads",
        "signature": "json.loads(request_text)['expression']",
        "type": "source",
        "sink_args": [],
        "description": "JSON payload - user controlled expression"
    },
    # Sinks - APIs that execute dynamic code
    {
        "module": "builtins",
        "function": "eval",
        "signature": "eval(expression)",
        "type": "sink",
        "sink_args": ["expression"],
        "description": "Dynamic evaluation - direct code injection risk"
    },
    {
        "module": "builtins",
        "function": "exec",
        "signature": "exec(code_string)",
        "type": "sink", 
        "sink_args": ["code_string"],
        "description": "Code execution - arbitrary code injection"
    },
    # Propagators - APIs that manipulate code strings
    {
        "module": "str",
        "function": "strip",
        "signature": "user_code.strip()",
        "type": "propagator",
        "sink_args": [],
        "description": "String cleaning - passes tainted code through"
    },
    {
        "module": "str",
        "function": "join",
        "signature": "'; '.join([base_code, user_code])",
        "type": "propagator",
        "sink_args": [],
        "description": "Code concatenation - combines safe and tainted code"
    }
]

# Main mapping
CWE_EXAMPLES = {
    "22": CWE_22_EXAMPLES,
    "78": CWE_78_EXAMPLES, 
    "79": CWE_79_EXAMPLES,
    "89": CWE_89_EXAMPLES,
    "94": CWE_94_EXAMPLES
}

def get_cwe_examples(cwe_id: str) -> List[Dict[str, Any]]:
    """Get few-shot examples for a specific CWE.
    
    Args:
        cwe_id: CWE identifier (e.g., "22", "78", "79", "89", "94")
        
    Returns:
        List of example dictionaries with source/sink/propagator classifications
    """
    return CWE_EXAMPLES.get(cwe_id, [])

def get_cwe_description(cwe_id: str) -> Dict[str, str]:
    """Get description and context for a specific CWE.
    
    Args:
        cwe_id: CWE identifier
        
    Returns:
        Dictionary with description and context
    """
    descriptions = {
        "22": {
            "name": "Path Traversal",
            "description": "The software uses external input to construct a pathname without proper neutralization of '..' sequences that can resolve to a location outside the intended directory.",
            "context": "Focus on file operations, path manipulations, and directory traversal patterns."
        },
        "78": {
            "name": "OS Command Injection", 
            "description": "The software constructs operating system commands using externally-influenced input without proper neutralization.",
            "context": "Focus on command execution, shell operations, and process spawning."
        },
        "79": {
            "name": "Cross-Site Scripting (XSS)",
            "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before placing it in output used as a web page.",
            "context": "Focus on web output, template rendering, and HTML generation."
        },
        "89": {
            "name": "SQL Injection",
            "description": "The software constructs SQL commands using externally-influenced input without proper neutralization.",
            "context": "Focus on database queries, SQL construction, and ORM operations."
        },
        "94": {
            "name": "Code Injection",
            "description": "The software constructs code using externally-influenced input without proper neutralization of special elements.",
            "context": "Focus on dynamic code execution, eval operations, and script generation."
        }
    }
    return descriptions.get(cwe_id, {"name": "Unknown", "description": "", "context": ""})
