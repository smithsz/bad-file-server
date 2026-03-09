/**
 * @name Use of weak cryptographic algorithm
 * @description Detects use of MD5 or other weak cryptographic algorithms
 * @kind problem
 * @problem.severity warning
 * @id go/weak-crypto
 * @tags security
 *       external/cwe/cwe-327
 */

import go

from DataFlow::CallNode call
where
  call.getTarget().hasQualifiedName("crypto/md5", "New") or
  call.getTarget().hasQualifiedName("crypto/md5", "Sum") or
  call.getTarget().hasQualifiedName("crypto/sha1", "New") or
  call.getTarget().hasQualifiedName("crypto/sha1", "Sum")
select call, "Use of weak cryptographic algorithm (MD5/SHA1). Consider using SHA-256 or stronger."
