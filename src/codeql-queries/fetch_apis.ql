/**
 * @name API Calls
 * @description Identifies API calls in python
 * @kind table
 * @id python/external-api-calls
 */

import python

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
    Function f
where
    not f.getLocation().getFile().getRelativePath().matches("%test%") and
    not f.getLocation().getFile().getRelativePath().matches("%/tests/%") and
    not f.getLocation().getFile().getBaseName().matches("test_%") and
    f.inSource()
select
    f.getName() as func_name,
    getFullSignature(f) as full_signature,
    f.getLocation().getFile().getRelativePath() + ":" + f.getLocation().getStartLine().toString() as file_path
