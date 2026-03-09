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

from CallExpr openCall, CallExpr queryCall
where
  // Find calls to os.Open
  openCall.getTarget().hasQualifiedName("os", "Open") and
  // Find URL query parameter access
  queryCall.getTarget().hasQualifiedName("net/url", "Values", "Get") and
  // Check if query result flows to os.Open (simplified check)
  exists(DataFlow::Node source, DataFlow::Node sink |
    source.asExpr() = queryCall and
    sink.asExpr() = openCall.getAnArgument() and
    DataFlow::localFlow(source, sink)
  )
select openCall, "Potential path traversal: user input from URL parameter flows to file operation without sanitization."