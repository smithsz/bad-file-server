/**
 * @name Path traversal vulnerability
 * @description Detects potential path traversal vulnerabilities where user input is used directly in file operations
 * @kind problem
 * @problem.severity error
 * @id go/path-traversal
 * @tags security
 *       external/cwe/cwe-022
 */

import go

from CallExpr openCall
where
  openCall.getTarget().hasQualifiedName("os", "Open")
select openCall, "Potential path traversal: file operation that may use unsanitized user input from URL parameters."
