/**
 * @name Simple Path traversal detection
 * @description Finds os.Open calls that may be vulnerable to path traversal
 * @kind problem
 * @problem.severity error
 * @id go/simple-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 */

import go

from CallExpr call
where
  call.getTarget().hasQualifiedName("os", "Open")
select call, "File operation that may be vulnerable to path traversal if user input is not sanitized."
