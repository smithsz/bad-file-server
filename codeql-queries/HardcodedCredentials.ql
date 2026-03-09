/**
 * @name Hard-coded credentials
 * @description Detects hard-coded credentials in source code
 * @kind problem
 * @problem.severity error
 * @id go/hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-798
 */

import go

from ValueSpec v, string name
where
  v.getType().getUnderlyingType() instanceof StringType and
  v.getInit(0).(BasicLit).getValue().regexpMatch(".*(?i)(password|secret|key|token|api[_-]?key).*") and
  name = v.getNameExpr().getName() and
  name.regexpMatch(".*(?i)(password|secret|key|token|api).*")
select v, "Hard-coded credential found: " + name + " should be stored securely, not in source code."
