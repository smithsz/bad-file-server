/**
 * @name Command injection vulnerability
 * @description Detects command injection where user input flows to exec.Command without sanitization
 * @kind path-problem
 * @problem.severity error
 * @id go/command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import go

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("net/http", "Request", "FormValue") or
      call.getTarget().hasQualifiedName("net/url", "Values", "Get")
    |
      source = call.getResult()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("os/exec", "Command")
    |
      sink = call.getAnArgument()
    )
  }
}

from CommandInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection: user input $@ flows to exec.Command without sanitization.", source.getNode(),
  "user input"
