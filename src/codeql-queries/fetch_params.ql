/**
 * @name API Calls
 * @description Identifies API calls in python
 * @kind table
 * @id python/external-api-calls
 */

import python


from
    Function f,
    Parameter p
where
    exists(f.getArgByName(p.getName()) )
select
    f.getName() as function_name,
    p.getName() as parameter_name