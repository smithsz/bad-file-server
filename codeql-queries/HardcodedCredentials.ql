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

from ValueSpec v, BasicLit lit
where
  lit = v.getInit(0) and
  lit.getValue().regexpMatch(".*(?i)(secret|password|key|token).*") and
  lit.getValue().length() > 5
select v, "Hard-coded credential found. Credentials should be stored securely, not in source code."