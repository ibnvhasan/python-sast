/**
 * @name API Calls
 * @description Identifies API calls in python
 * @kind table
 * @id python/external-api-calls
 */

import python

// string getFullSignature(Function f) {
//     if f.getPositionalParameterCount() > 1
//     then
//         result = f.getName().toString() + "(" + 
//             concat( int i | i in [0..f.getPositionalParameterCount()] | f.getArg(i).getName(), ", " order by i ) + ")"
    
//     else if f.getPositionalParameterCount() = 1
//     then
//         result = f.getName().toString() + "(" + f.getArg(0).getName().toString()  +  ")"
    
//     else
//         result = f.getName().toString() + "()"
// }


// string getModule(Function f) {
//     if f.getScope() instanceof Module
//     then
//         result = f.getScope().getName()
//     else
//         result = "direct call"
// }

// string getClassName(Function f) {
//     if f.getScope() instanceof Class
//     then
//         result = f.getScope().getName()
//     else
//         result = "not in a class"
// }

// from
//     Function f
// where
//     not f.getLocation().getFile().getRelativePath().matches("%test%")
//     and not f.getLocation().getFile().getRelativePath().matches("%/tests/%")
//     and not f.getLocation().getFile().getBaseName().matches("test_%")
//     and f.inSource()
// select
//     getModule(f) as module_name,
//     getClassName(f) as class_name,
//     f.getName() as func_name,
//     getFullSignature(f) as full_signature,
//     f.getLocation().getFile().getRelativePath() + ":" + f.getLocation().getStartLine().toString() as file_path,
//     f as location_for_debugging

import python
string getSignature (Call c) {
    if c.getAPositionalArg()
    then
        result = ""
    else
        result = ""
}


from Call c
select
    c as call,
    c.getFunc().pointsTo() as points_to,
    c.getScope() as scope