"""

Python CodeQL Query Templates for Static Analysis Security Testing (SAST)

This module contains CodeQL query templates for Python projects, adapted from the original
Java-based templates. These templates are used to generate project-specific CodeQL queries
for detecting security vulnerabilities based on LLM-identified API candidates.

Key Changes from Java to Python:
- Updated imports to use Python CodeQL libraries
- Changed from Java AST nodes (Call, Method) to Python AST nodes (Call, Attribute, Name)
- Adapted query patterns for Python syntax and semantics
- Updated extension pack from codeql/java-all to codeql/python-all
- Added support for both module functions and class methods

Supported Patterns:
- Class method calls: obj.method()
- Module function calls: module.function()
- Direct function calls: function()
- Parameter analysis for function arguments
"""

QL_SOURCE_PREDICATE = """
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isGPTDetectedSource(DataFlow::Node src) {{
    exists(Call call |
        src.asExpr() = call and
        (
            {body}
        )
    )
}}

{additional}
"""

QL_SINK_PREDICATE = """
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isGPTDetectedSink(DataFlow::Node snk) {{
    exists(Call call |
        (
            {body}
        ) and
        snk.asExpr() = call
    )
}}

{additional}
"""

QL_SUBSET_PREDICATE = """
predicate isGPTDetected{kind}Part{part_id}(DataFlow::Node {node}) {{
{body}
}}
"""

CALL_QL_SUBSET_PREDICATE = "    isGPTDetected{kind}Part{part_id}({node})"

QL_STEP_PREDICATE = """
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isGPTDetectedStep(DataFlow::Node prev, DataFlow::Node next) {{
{body}
}}
"""

# Python-specific source body entry template
QL_METHOD_CALL_SOURCE_BODY_ENTRY = """
    (
        src.asExpr().(Call).getFunc().(Attribute).getAttr() = "{method}" and
        src.asExpr().(Call).getFunc().(Attribute).getObject().(Name).getId() = "{clazz}"
    )
"""

# Direct function call source entry
QL_FUNC_CALL_SOURCE_BODY_ENTRY = """
    (
        src.asExpr().(Call).getFunc().(Name).getId() = "{method}"
    )
"""

QL_FUNC_PARAM_SOURCE_ENTRY = """
    exists(Parameter p |
        src.asParameter() = p and
        p.getFunction().getName() = "{method}" and
        p.getFunction().getScope().(Class).getName() = "{clazz}" and
        ({params})
    )
"""

QL_FUNC_PARAM_NAME_ENTRY = """ p.getName() = "{arg_name}" """

QL_SUMMARY_BODY_ENTRY = """
    exists(Call c |
        (c.getAnArg() = prev.asExpr() or c.getFunc().(Attribute).getObject() = prev.asExpr())
        and c.getFunc().(Attribute).getObject().(Name).getId() = "{clazz}"
        and c.getFunc().(Attribute).getAttr() = "{method}"
        and c = next.asExpr()
    )
"""

QL_SINK_BODY_ENTRY = """
    exists(Call c |
        c.getFunc().(Attribute).getAttr() = "{method}" and
        c.getFunc().(Attribute).getObject().(Name).getId() = "{clazz}" and
        ({args})
    )
"""

# For direct function calls (no object)
QL_SINK_FUNC_BODY_ENTRY = """
    exists(Call c |
        c.getFunc().(Name).getId() = "{method}" and
        ({args})
    )
"""

QL_SINK_ARG_NAME_ENTRY = " c.getArg({arg_id}) = snk.asExpr() "

QL_SINK_ARG_THIS_ENTRY = " c.getFunc().(Attribute).getObject() = snk.asExpr() "

QL_BODY_OR_SEPARATOR = """
    or
"""

EXTENSION_YML_TEMPLATE = """
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: sinkModel
    data:
{sinks}
  - addsTo:
      pack: codeql/python-all
      extensible: sourceModel
    data:
{sources}
"""

EXTENSION_SRC_SINK_YML_ENTRY = """
      - ["{package}", "{clazz}", True, "{method}", "", "", "{access}", "{tag}", "manual"]
"""

EXTENSION_SUMMARY_YML_ENTRY = """
      - ["{package}", "{clazz}", True, "{method}", "", "", "{access_in}", "{access_out}", "{tag}", "manual"]
"""


def validate_python_api_entry(package, clazz, method):
    """
    Validate that an API entry makes sense for Python.
    
    Args:
        package: Package/module name (e.g., 'os', 'subprocess', 'builtins')
        clazz: Class name or module name for functions (e.g., 'Popen', 'subprocess', 'str')
        method: Method/function name (e.g., '__init__', 'run', 'open')
    
    Returns:
        tuple: (is_valid, warning_message)
    """
    warnings = []
    
    # Check for common Python patterns
    if package == 'builtins' and clazz != package:
        warnings.append(f"Built-in function '{method}' should typically have clazz='builtins'")
    
    if method in ['__init__', '__call__', '__enter__', '__exit__'] and package == clazz:
        warnings.append(f"Special method '{method}' called on module '{package}' - should be on a class")
    
    # Check for common security-relevant packages
    security_packages = ['os', 'subprocess', 'eval', 'exec', 'open', 'urllib', 'requests', 'flask', 'django']
    if package in security_packages and clazz == package and method == package:
        warnings.append(f"Redundant naming: package=clazz=method='{package}'")
    
    is_valid = len(warnings) == 0
    warning_msg = "; ".join(warnings) if warnings else None
    
    return is_valid, warning_msg


def validate_source_predicate(predicate_content: str) -> bool:
    """
    Validate a CodeQL source predicate for basic syntax correctness.
    
    Args:
        predicate_content: The full CodeQL predicate content as a string
        
    Returns:
        bool: True if predicate appears valid, False otherwise
    """
    try:
        # Basic checks for required components
        required_imports = ['import python', 'import semmle.python.dataflow']
        required_elements = ['predicate isGPTDetectedSource', 'DataFlow::Node src']
        
        for req_import in required_imports:
            if req_import not in predicate_content:
                print(f"⚠️  Missing required import: {req_import}")
                return False
                
        for req_element in required_elements:
            if req_element not in predicate_content:
                print(f"⚠️  Missing required element: {req_element}")
                return False
        
        # Check for balanced braces
        open_braces = predicate_content.count('{')
        close_braces = predicate_content.count('}')
        if open_braces != close_braces:
            print(f"⚠️  Unbalanced braces: {open_braces} open, {close_braces} close")
            return False
            
        return True
        
    except Exception as e:
        print(f"⚠️  Validation error: {e}")
        return False


def validate_sink_predicate(predicate_content: str) -> bool:
    """
    Validate a CodeQL sink predicate for basic syntax correctness.
    
    Args:
        predicate_content: The full CodeQL predicate content as a string
        
    Returns:
        bool: True if predicate appears valid, False otherwise
    """
    try:
        # Basic checks for required components
        required_imports = ['import python', 'import semmle.python.dataflow']
        required_elements = ['predicate isGPTDetectedSink', 'DataFlow::Node snk']
        
        for req_import in required_imports:
            if req_import not in predicate_content:
                print(f"⚠️  Missing required import: {req_import}")
                return False
                
        for req_element in required_elements:
            if req_element not in predicate_content:
                print(f"⚠️  Missing required element: {req_element}")
                return False
        
        # Check for balanced braces
        open_braces = predicate_content.count('{')
        close_braces = predicate_content.count('}')
        if open_braces != close_braces:
            print(f"⚠️  Unbalanced braces: {open_braces} open, {close_braces} close")
            return False
            
        return True
        
    except Exception as e:
        print(f"⚠️  Validation error: {e}")
        return False


def validate_taint_predicate(predicate_content: str) -> bool:
    """
    Validate a CodeQL taint propagator predicate for basic syntax correctness.
    
    Args:
        predicate_content: The full CodeQL predicate content as a string
        
    Returns:
        bool: True if predicate appears valid, False otherwise
    """
    try:
        # Basic checks for required components - taint predicates can vary more
        required_imports = ['python']  # More flexible for taint propagators
        required_elements = ['Call c', 'exists']
        
        for req_import in required_imports:
            if req_import not in predicate_content:
                print(f"⚠️  Missing required import: {req_import}")
                return False
                
        for req_element in required_elements:
            if req_element not in predicate_content:
                print(f"⚠️  Missing required element: {req_element}")
                return False
        
        # Check for balanced parentheses and braces
        open_parens = predicate_content.count('(')
        close_parens = predicate_content.count(')')
        if open_parens != close_parens:
            print(f"⚠️  Unbalanced parentheses: {open_parens} open, {close_parens} close")
            return False
            
        return True
        
    except Exception as e:
        print(f"⚠️  Validation error: {e}")
        return False


QL_SOURCE_PREDICATE = """\
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isGPTDetectedSource(DataFlow::Node src) {{
    exists(Call call |
        src.asExpr() = call and
        (
            {body}
        )
    )
}}

{additional}
"""

QL_SINK_PREDICATE = """\
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isGPTDetectedSink(DataFlow::Node snk) {{
    exists(Call call |
        (
            {body}
        ) and
        snk.asExpr() = call
    )
}}

{additional}
"""

QL_SUBSET_PREDICATE = """\
predicate isGPTDetected{kind}Part{part_id}(DataFlow::Node {node}) {{
{body}
}}
"""

CALL_QL_SUBSET_PREDICATE = "    isGPTDetected{kind}Part{part_id}({node})"

QL_STEP_PREDICATE = """\
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isGPTDetectedStep(DataFlow::Node prev, DataFlow::Node next) {{
{body}
}}
"""

QL_METHOD_CALL_SOURCE_BODY_ENTRY = """\
    (
        // Class method call: obj.method()
        exists(Call call |
            src.asExpr() = call and
            call.getFunc().(Attribute).getName() = "{method}" and
            (
                // When clazz represents a class name
                call.getFunc().(Attribute).getObject().pointsTo().getClass().getName() = "{clazz}"
                or
                // When clazz represents a module/package name  
                call.getFunc().(Attribute).getObject().(Name).getId() = "{clazz}"
            )
        )
        or
        // Module function call: module.function() or direct function()
        exists(Call call |
            src.asExpr() = call and
            (
                // Direct function call
                (call.getFunc().(Name).getId() = "{method}" and "{clazz}" = "{package}")
                or
                // Module.function call
                (call.getFunc().(Attribute).getName() = "{method}" and 
                 call.getFunc().(Attribute).getObject().(Name).getId() = "{package}")
            )
        )
    )\
"""

QL_FUNC_PARAM_SOURCE_ENTRY = """\
    exists(Parameter p |
        src.asParameter() = p and
        p.getFunction().getName() = "{method}" and
        p.getFunction().getScope().(Class).getName() = "{clazz}" and
        ({params})
    )\
"""

QL_FUNC_PARAM_NAME_ENTRY = """ p.getName() = "{arg_name}" """

QL_SUMMARY_BODY_ENTRY = """\
    exists(Call call |
        call.getAnArg() = prev.asExpr() and
        (
            // Class method call
            (call.getFunc().(Attribute).getName() = "{method}" and
             (call.getFunc().(Attribute).getObject().pointsTo().getClass().getName() = "{clazz}" or
              call.getFunc().(Attribute).getObject().(Name).getId() = "{clazz}"))
            or
            // Module function call
            (call.getFunc().(Name).getId() = "{method}" and "{clazz}" = "{package}")
            or
            (call.getFunc().(Attribute).getName() = "{method}" and 
             call.getFunc().(Attribute).getObject().(Name).getId() = "{package}")
        ) and
        call = next.asExpr()
    )\
"""

QL_SINK_BODY_ENTRY = """\
    exists(Call call |
        (
            // Class method call: obj.method()
            (call.getFunc().(Attribute).getName() = "{method}" and
             (call.getFunc().(Attribute).getObject().pointsTo().getClass().getName() = "{clazz}" or
              call.getFunc().(Attribute).getObject().(Name).getId() = "{clazz}"))
            or
            // Module function call: module.function() or direct function()
            (call.getFunc().(Name).getId() = "{method}" and "{clazz}" = "{package}")
            or
            (call.getFunc().(Attribute).getName() = "{method}" and 
             call.getFunc().(Attribute).getObject().(Name).getId() = "{package}")
        ) and
        ({args})
    )\
"""

QL_SINK_ARG_NAME_ENTRY = """ call.getArg({arg_id}) = snk.asExpr() """

QL_SINK_ARG_THIS_ENTRY = """ call.getFunc().(Attribute).getObject() = snk.asExpr() """

QL_BODY_OR_SEPARATOR = "\n    or\n"

EXTENSION_YML_TEMPLATE = """\
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: sinkModel
    data:
{sinks}
  - addsTo:
      pack: codeql/python-all
      extensible: sourceModel
    data:
{sources}
"""

EXTENSION_SRC_SINK_YML_ENTRY = """\
      - ["{package}", "{clazz}", True, "{method}", "", "", "{access}", "{tag}", "manual"]\
"""

EXTENSION_SUMMARY_YML_ENTRY = """\
      - ["{package}", "{clazz}", True, "{method}", "", "", "{access_in}", "{access_out}", "{tag}", "manual"]\
"""

def validate_python_api_entry(package, clazz, method):
    """
    Validate that an API entry makes sense for Python.
    
    Args:
        package: Package/module name (e.g., 'os', 'subprocess', 'builtins')
        clazz: Class name or module name for functions (e.g., 'Popen', 'subprocess', 'str')
        method: Method/function name (e.g., '__init__', 'run', 'open')
    
    Returns:
        tuple: (is_valid, warning_message)
    """
    warnings = []
    
    # Check for common Python patterns
    if package == 'builtins' and clazz != package:
        warnings.append(f"Built-in function '{method}' should typically have clazz='builtins'")
    
    if method in ['__init__', '__call__', '__enter__', '__exit__'] and package == clazz:
        warnings.append(f"Special method '{method}' called on module '{package}' - should be on a class")
    
    # Check for common security-relevant packages
    security_packages = ['os', 'subprocess', 'eval', 'exec', 'open', 'urllib', 'requests', 'flask', 'django']
    if package in security_packages and clazz == package and method == package:
        warnings.append(f"Redundant naming: package=clazz=method='{package}'")
    
    is_valid = len(warnings) == 0
    warning_msg = "; ".join(warnings) if warnings else None
    
    return is_valid, warning_msg


def validate_source_predicate(predicate_content: str) -> bool:
    """
    Validate a CodeQL source predicate for basic syntax correctness.
    
    Args:
        predicate_content: The full CodeQL predicate content as a string
        
    Returns:
        bool: True if predicate appears valid, False otherwise
    """
    try:
        # Basic checks for required components
        required_imports = ['import python', 'import semmle.python.dataflow']
        required_elements = ['predicate isGPTDetectedSource', 'DataFlow::Node src']
        
        for req_import in required_imports:
            if req_import not in predicate_content:
                print(f"⚠️  Missing required import: {req_import}")
                return False
                
        for req_element in required_elements:
            if req_element not in predicate_content:
                print(f"⚠️  Missing required element: {req_element}")
                return False
        
        # Check for balanced braces
        open_braces = predicate_content.count('{')
        close_braces = predicate_content.count('}')
        if open_braces != close_braces:
            print(f"⚠️  Unbalanced braces: {open_braces} open, {close_braces} close")
            return False
            
        return True
        
    except Exception as e:
        print(f"⚠️  Validation error: {e}")
        return False


def validate_sink_predicate(predicate_content: str) -> bool:
    """
    Validate a CodeQL sink predicate for basic syntax correctness.
    
    Args:
        predicate_content: The full CodeQL predicate content as a string
        
    Returns:
        bool: True if predicate appears valid, False otherwise
    """
    try:
        # Basic checks for required components
        required_imports = ['import python', 'import semmle.python.dataflow']
        required_elements = ['predicate isGPTDetectedSink', 'DataFlow::Node snk']
        
        for req_import in required_imports:
            if req_import not in predicate_content:
                print(f"⚠️  Missing required import: {req_import}")
                return False
                
        for req_element in required_elements:
            if req_element not in predicate_content:
                print(f"⚠️  Missing required element: {req_element}")
                return False
        
        # Check for balanced braces
        open_braces = predicate_content.count('{')
        close_braces = predicate_content.count('}')
        if open_braces != close_braces:
            print(f"⚠️  Unbalanced braces: {open_braces} open, {close_braces} close")
            return False
            
        return True
        
    except Exception as e:
        print(f"⚠️  Validation error: {e}")
        return False


def validate_taint_predicate(predicate_content: str) -> bool:
    """
    Validate a CodeQL taint propagator predicate for basic syntax correctness.
    
    Args:
        predicate_content: The full CodeQL predicate content as a string
        
    Returns:
        bool: True if predicate appears valid, False otherwise
    """
    try:
        # Basic checks for required components - taint predicates can vary more
        required_imports = ['python']  # More flexible for taint propagators
        required_elements = ['Call call', 'exists']
        
        for req_import in required_imports:
            if req_import not in predicate_content:
                print(f"⚠️  Missing required import: {req_import}")
                return False
                
        for req_element in required_elements:
            if req_element not in predicate_content:
                print(f"⚠️  Missing required element: {req_element}")
                return False
        
        # Check for balanced parentheses and braces
        open_parens = predicate_content.count('(')
        close_parens = predicate_content.count(')')
        if open_parens != close_parens:
            print(f"⚠️  Unbalanced parentheses: {open_parens} open, {close_parens} close")
            return False
            
        return True
        
    except Exception as e:
        print(f"⚠️  Validation error: {e}")
        return False
