/**
 * @name Internal API Calls
 * @description Identifies calls to internal APIs (within the project) in Python code
 * @kind table
 * @id python/internal-api-calls
 */

import python

string getObjectName(Call call) {
  if exists(call.getFunc().(Attribute).getObject().(Name))
  then result = call.getFunc().(Attribute).getObject().(Name).getId()
  else result = "direct_call"
}

string getMethodName(Call call) {
  if exists(call.getFunc().(Attribute))
  then result = call.getFunc().(Attribute).getAttr()
  else if exists(call.getFunc().(Name))
  then result = call.getFunc().(Name).getId()
  else result = "unknown"
}

string getContainingFunction(Call call) {
  if exists(Function func | func = call.getScope())
  then result = call.getScope().(Function).getName()
  else result = "module_level"
}

string getContainingClass(Call call) {
  if exists(Class cls | cls = call.getScope() or cls = call.getScope().(Function).getScope())
  then 
    if exists(call.getScope().(Class))
    then result = call.getScope().(Class).getName()
    else result = call.getScope().(Function).getScope().(Class).getName()
  else result = "no_class"
}

/**
 * Enhanced code context with surrounding statements
 */
// string getExtendedContext(Call call) {
//     // Try to get the containing statement and its siblings for context
//     exists(Stmt containingStmt | 
//         containingStmt.getAChildNode*() = call |
//         result = "Statement context: " + containingStmt.toString() + 
//                  " [line " + containingStmt.getLocation().getStartLine().toString() + "]"
//     )
//     or
//     // If we can't find a containing statement, fall back to basic info
//     (
//         not exists(Stmt containingStmt | containingStmt.getAChildNode*() = call) and
//         result = "Expression context: " + call.toString() + 
//                  " [line " + call.getLocation().getStartLine().toString() + "]"
//     )
// }

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
 * Extract meaningful code context around the internal API call
 * Enhanced version with longer context information
 */
// string getCodeContext(Call call) {
//     // For assignment statements, show what's being assigned with more detail
//     exists(AssignStmt assign | 
//         assign = call.getParentNode*() and
//         assign.getATarget() instanceof Name |
//         result = "Assignment: " + assign.getATarget().(Name).getId() + " = " + call.toString() + 
//                  " (in " + assign.getScope().toString() + ")"
//     )
//     or
//     // For return statements with function context
//     exists(Return ret | 
//         ret = call.getParentNode*() |
//         result = "Return: " + call.toString() + " from function " + 
//                  ret.getScope().(Function).getName()
//     )
//     or 
//     // For if/while conditions with more context
//     exists(If ifstmt | 
//         ifstmt.getTest().getAChildNode*() = call |
//         result = "Condition: if " + ifstmt.getTest().toString() + 
//                  " (contains " + call.toString() + ")"
//     )
//     or
//     exists(While whilestmt | 
//         whilestmt.getTest().getAChildNode*() = call |
//         result = "Loop condition: while " + whilestmt.getTest().toString() + 
//                  " (contains " + call.toString() + ")"
//     )
//     or
//     // For function arguments with parent function info
//     exists(Call parentCall |
//         parentCall.getAnArg() = call or
//         parentCall.getAnArg().getAChildNode*() = call |
//         result = "Argument: " + call.toString() + " passed to " + 
//                  parentCall.getFunc().toString() + " in " + 
//                  parentCall.getScope().toString()
//     )
//     or
//     // For class method calls - show class context
//     exists(Function func | 
//         func = call.getScope() and
//         exists(Class cls | cls = func.getScope()) |
//         result = "Method call: " + call.toString() + " in " + 
//                  func.getName() + " of class " + 
//                  func.getScope().(Class).getName()
//     )
//     or
//     // Try/except context
//     exists(Try trystmt |
//         trystmt.getAStmt().getAChildNode*() = call |
//         result = "Try block: " + call.toString() + " in try-except"
//     )
//     or
//     exists(ExceptStmt exceptstmt |
//         exceptstmt.getAStmt().getAChildNode*() = call |
//         result = "Exception handler: " + call.toString() + " in except block"
//     )
//     or
//     // Default: enhanced with scope information
//     (
//         not exists(AssignStmt assign | assign = call.getParentNode*() and assign.getATarget() instanceof Name) and
//         not exists(Return ret | ret = call.getParentNode*()) and
//         not exists(If ifstmt | ifstmt.getTest().getAChildNode*() = call) and
//         not exists(While whilestmt | whilestmt.getTest().getAChildNode*() = call) and
//         not exists(Call parentCall | parentCall.getAnArg() = call or parentCall.getAnArg().getAChildNode*() = call) and
//         not exists(Try trystmt | trystmt.getAStmt().getAChildNode*() = call) and
//         not exists(ExceptStmt exceptstmt | exceptstmt.getAStmt().getAChildNode*() = call) and
//         result = "Statement: " + call.toString() + " in " + call.getScope().toString()
//     )
// }

/**
 * Get argument details for the function call
 */
string getFunctionArguments(Call call) {
    if count(call.getAnArg()) = 0
    then result = "no_args"
    else 
        result = concat(int i, string arg |
            i in [0..count(call.getAnArg())-1] and
            (
                if exists(call.getArg(i).(StringLiteral))
                then arg = "str_literal"
                else if exists(call.getArg(i).(IntegerLiteral))
                then arg = "int_literal"
                else if exists(call.getArg(i).(Name))
                then arg = call.getArg(i).(Name).getId()
                else arg = call.getArg(i).toString()
            ) |
            arg, ", " order by i
        )
}

/**
 * Find where the result of this call flows to (data flow destinations)
 */
// string getFlowsTo(Call call) {
//     // Assigned to variables
//     exists(AssignStmt assign | 
//         assign.getValue() = call or assign.getValue().getAChildNode*() = call |
//         result = "variable: " + assign.getATarget().(Name).getId()
//     )
//     or
//     // Returned from function
//     exists(Return ret | ret.getValue() = call or ret.getValue().getAChildNode*() = call |
//         result = "function_return"
//     )
//     or
//     // Passed as argument to another function
//     exists(Call parentCall, int argPos |
//         parentCall.getArg(argPos) = call |
//         result = "arg_" + argPos.toString() + "_of: " + parentCall.getFunc().toString()
//     )
//     or
//     // Used in conditional
//     exists(If ifstmt | ifstmt.getTest() = call or ifstmt.getTest().getAChildNode*() = call |
//         result = "if_condition"
//     )
//     or
//     // Default
//     (
//         not exists(AssignStmt assign | assign.getValue() = call or assign.getValue().getAChildNode*() = call) and
//         not exists(Return ret | ret.getValue() = call or ret.getValue().getAChildNode*() = call) and
//         not exists(Call parentCall | parentCall.getAnArg() = call) and
//         not exists(If ifstmt | ifstmt.getTest() = call or ifstmt.getTest().getAChildNode*() = call) and
//         result = "statement"
//     )
// }

/**
 * Find where the arguments to this call come from (data flow sources)
 */
// string getComesFrom(Call call) {
//     if count(call.getAnArg()) = 0
//     then result = "no_input"
//     else
//         result = concat(int i, string source |
//             i in [0..count(call.getAnArg())-1] and
//             (
//                 if exists(call.getArg(i).(StringLiteral))
//                 then source = "str_literal"
//                 else if exists(call.getArg(i).(IntegerLiteral))
//                 then source = "int_literal"
//                 else if exists(call.getArg(i).(Name))
//                 then source = "var: " + call.getArg(i).(Name).getId()
//                 else if exists(call.getArg(i).(Call))
//                 then source = "call: " + call.getArg(i).(Call).getFunc().toString()
//                 else if exists(call.getArg(i).(Attribute))
//                 then source = "attr: " + call.getArg(i).(Attribute).toString()
//                 else source = "expr: " + call.getArg(i).toString()
//             ) |
//             source, " | " order by i
//         )
// }

from Call call, string object_name, string method_name
where 
  // Get object and method names
  object_name = getObjectName(call) and
  method_name = getMethodName(call) and
  
  // Only calls from source files
  call.getLocation().getFile().fromSource() and
  
  // Filter out test files
  not call.getLocation().getFile().getRelativePath().matches("%test%") and
  not call.getLocation().getFile().getRelativePath().matches("%/tests/%") and
  not call.getLocation().getFile().getBaseName().matches("test_%") and
  
  // Include self/cls calls or function calls defined in project
  (
    object_name in ["self", "cls"] or
    exists(Function func | func.getName() = method_name and func.getLocation().getFile().fromSource())
  )
  
select
  call.toString() as call_expression,
  object_name,
  method_name,
  object_name + "." + method_name as full_signature,
  count(call.getAnArg()) as num_args,
  getContainingClass(call) as containing_class,
  getContainingFunction(call) as containing_function,
  call.getLocation().getFile().getRelativePath() as file_path,
  call.getLocation().getStartLine() as line_number,
  getScopeContext(call) as scope_context,
  getFunctionArguments(call) as function_arguments
//   getExtendedContext(call) as extended_context,
//   getComesFrom(call) as comes_from,
  //   getCodeContext(call) as code_context,
//   getFlowsTo(call) as flows_to
