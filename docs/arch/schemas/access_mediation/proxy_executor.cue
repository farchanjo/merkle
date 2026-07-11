// DDD role: DomainService

package access_mediation

// #ProxyOperation enumerates all operations the Proxy Executor is authorized
// to perform on behalf of an LLM caller.  The enum is closed; adding a new
// operation requires an ADR and a schema update.
	"ssh.exec" |
	"ssh.copy" |
	"ssh.port_forward" |
	"ssh.shell" |
	"http.request" |
	"http.download" |
	"http.upload" |
	"spawn" |
	"write_tempfile"

// #SshExecInput describes the input shape for the "ssh.exec" operation.
#ProxyExecutor: {
	// operation identifies which external capability is exercised.
	operation: #ProxyOperation

	// audit_required is always true; present to make the invariant explicit.
	audit_required: true
}
