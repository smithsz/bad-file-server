/**
 * @name Command injection vulnerability
 * @description Detects command injection where user input flows to exec.Command
 * @kind problem
 * @problem.severity error
 * @id go/command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import go

from CallExpr call
where
  call.getTarget().hasQualifiedName("os/exec", "Command")
select call, "Potential command injection: exec.Command call that may use unsanitized user input."