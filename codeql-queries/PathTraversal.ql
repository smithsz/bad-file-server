/**
 * @name Path traversal vulnerability
 * @description Detects potential path traversal vulnerabilities where user input is used directly in file operations
 * @kind path-problem
 * @problem.severity error
 * @id go/path-traversal
 * @tags security
 *       external/cwe/cwe-022
 */

import go

from DataFlow::PathNode source, DataFlow::PathNode sink, DataFlow::Configuration cfg
where
  cfg.hasFlowPath(source, sink) and
  source.getNode().asExpr() instanceof CallExpr and
  sink.getNode().asExpr().(CallExpr).getTarget().hasQualifiedName("os", "Open")
select sink.getNode(), source, sink,
  "Potential path traversal: user input $@ flows to file operation without sanitization.", source.getNode(),
  "user input"
