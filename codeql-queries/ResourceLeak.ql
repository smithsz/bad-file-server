/**
 * @name Missing resource cleanup
 * @description Detects file operations that should have proper cleanup
 * @kind problem
 * @problem.severity warning
 * @id go/missing-defer-close
 * @tags security
 *       external/cwe/cwe-404
 *       reliability
 */

import go

from CallExpr openCall
where
  openCall.getTarget().hasQualifiedName("os", "Open") or
  openCall.getTarget().hasQualifiedName("os", "Create") or
  openCall.getTarget().hasQualifiedName("os", "OpenFile")
select openCall, "File operation that should be followed by defer close() to prevent resource leaks."