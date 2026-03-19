/**
 * @name Hard-coded credential data flow
 * @description Tracks hard-coded secrets to sensitive sinks like HTTP requests.
 * @kind problem
 * @problem.severity warning
 * @id go/hardcoded-credentials-flow
 * @tags security
 */

import go

/**
 * Global Data Flow Configuration
 */
module HardcodedSecretConfig implements DataFlow::ConfigSig {
  // 1. Define the Source: Any string literal matching our pattern
  predicate isSource(DataFlow::Node source) {
    exists(BasicLit lit |
      lit = source.asExpr() and
      lit.getValue().regexpMatch(".*(?i)(password|secret|key|token).*")
    )
  }

  // 2. Define the Sink: Arguments of http.Post
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallExpr call |
      call.getTarget().hasQualifiedName("net/http", "Post") and
      sink.asExpr() = call.getAnArgument()
    )
  }
}

// Instantiate the global flow module
module Flow = DataFlow::Global<HardcodedSecretConfig>;

from DataFlow::Node source, DataFlow::Node sink
where Flow::flow(source, sink)
select sink, "This HTTP Post uses a hard-coded secret originating from: " + source.toString()
