/**
 * @name External API Calls
 * @description Identifies calls to external APIs in Python code
 * @kind table
 * @id python/external-api-calls
 */

import python

predicate isBuiltinFunction(string name) {
    name in [
        "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes", "callable",
        "chr", "classmethod", "compile", "complex", "delattr", "dict", "dir", "divmod",
        "enumerate", "eval", "exec", "filter", "float", "format", "frozenset", "getattr",
        "globals", "hasattr", "hash", "help", "hex", "id", "input", "int", "isinstance",
        "issubclass", "iter", "len", "list", "locals", "map", "max", "memoryview", "min",
        "next", "object", "oct", "open", "ord", "pow", "print", "property", "range",
        "repr", "reversed", "round", "set", "setattr", "slice", "sorted", "staticmethod",
        "str", "sum", "super", "tuple", "type", "vars", "zip", "__import__"
    ]
}

predicate isStandardLibrary(string moduleName) {
    moduleName in [
        "os", "sys", "re", "json", "datetime", "time", "collections", "itertools",
        "functools", "operator", "math", "random", "string", "io", "pathlib",
        "urllib", "http", "email", "html", "xml", "csv", "sqlite3", "logging",
        "threading", "multiprocessing", "subprocess", "socket", "ssl", "hashlib",
        "base64", "pickle", "copy", "warnings", "traceback", "inspect", "ast",
        "typing", "dataclasses", "enum", "contextlib", "weakref", "gc", "ctypes"
    ]
}

string getModuleName(Call call) {
    if exists(call.getFunc().(Attribute).getObject().(Name))
    then result = call.getFunc().(Attribute).getObject().(Name).getId()
    else result = "direct_call"
}

string getFunctionName(Call call) {
    if exists(call.getFunc().(Attribute))
    then result = call.getFunc().(Attribute).getAttr()
    else if exists(call.getFunc().(Name))
    then result = call.getFunc().(Name).getId()
    else result = "unknown"
}

/**
 * Get surrounding function/class context information
 */
string getScopeContext(Call call) {
    // Function context
    if exists(Function func | func = call.getScope())
    then 
        if exists(Class cls | cls = call.getScope().(Function).getScope())
        then result = "In method " + call.getScope().(Function).getName() + 
                     " of class " + call.getScope().(Function).getScope().(Class).getName()
        else result = "In function " + call.getScope().(Function).getName()
    // Class context (but not in a function)
    else if exists(Class cls | cls = call.getScope())
    then result = "In class " + call.getScope().(Class).getName()
    // Module level
    else result = "At module level"
}

/**
 * Get argument details for the function call
 */
// string getFunctionArguments(Call call) {
//     if count(call.getAnArg()) = 0
//     then
//         result = "no_args"
//     else 
//         result = concat(int i, string arg |
//             i in [0..count(call.getAnArg())-1] and
//             (
//                 if exists(call.getArg(i).(StringLiteral))
//                 then arg = "str_literal"
//                 else if exists(call.getArg(i).(IntegerLiteral))
//                 then arg = "int_literal"
//                 else if exists(call.getArg(i).(Name))
//                 then arg = call.getArg(i).(Name).getId()
//                 else arg = call.getArg(i).toString()
//             ) |
//             arg, ", " order by i
//         )
// }
string getFullSignature(Function f) {
    if f.getPositionalParameterCount() > 1
    then
        result = f.getName().toString() + "(" + 
            concat( int i | i in [0..f.getPositionalParameterCount()] | f.getArg(i).getName(), ", " order by i ) + ")"
    
    else if f.getPositionalParameterCount() = 1
    then
        result = f.getName().toString() + "(" + f.getArg(0).getName().toString()  +  ")"
    
    else
        result = f.getName().toString() + "()"
}

from 
    Call call,
    Function f,
    string module_name, 
    string function_name
where 
    // Get module and function names
    module_name = getModuleName(call) and
    function_name = getFunctionName(call) and
  
    // Filter for external calls (not builtins, not standard library)
    // not isBuiltinFunction(function_name) and
    // not isStandardLibrary(module_name) and
  
    // Filter out test files
    not call.getLocation().getFile().getRelativePath().matches("%test%") and
    not call.getLocation().getFile().getRelativePath().matches("%/tests/%") and
    not call.getLocation().getFile().getBaseName().matches("test_%") and
  
    // Only source files
    call.getLocation().getFile().fromSource()
  
select
    call.toString() as call_expression,
    module_name,
    function_name,
    module_name + "." + function_name as full_signature,
    count(call.getAnArg()) as num_args,
    call.getLocation().getFile().getRelativePath() as file_path,
    call.getLocation().getStartLine() as line_number,
    getScopeContext(call) as scope_context,
    // getFunctionArguments(call) as function_arguments
    getFullSignature(f) as full_singature