/**
 * @name Missing resource cleanup
 * @description Detects file operations without proper defer close() calls
 * @kind problem
 * @problem.severity warning
 * @id go/missing-defer-close
 * @tags security
 *       external/cwe/cwe-404
 *       reliability
 */

import go

from DataFlow::CallNode openCall, Variable fileVar
where
  (
    openCall.getTarget().hasQualifiedName("os", "Open") or
    openCall.getTarget().hasQualifiedName("os", "Create") or
    openCall.getTarget().hasQualifiedName("os", "OpenFile")
  ) and
  fileVar.getAWrite().getRhs() = openCall.asExpr() and
  not exists(DeferStmt defer, DataFlow::CallNode closeCall |
    closeCall.getTarget().getName() = "Close" and
    closeCall.getReceiver().asExpr() = fileVar.getAReference() and
    defer.getCall() = closeCall.asExpr()
  )
select openCall, "File opened without defer close(), which may lead to resource leaks."
