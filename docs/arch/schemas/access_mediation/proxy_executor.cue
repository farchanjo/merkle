// DDD role: DomainService

package access_mediation

// #ProxyOperation enumerates all operations the Proxy Executor is authorized
// to perform on behalf of an LLM caller.  The enum is closed; adding a new
// operation requires an ADR and a schema update.
#ProxyOperation:
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
#SshExecInput: {
	host:    string
	port:    int & >=1 & <=65535 | *22
	user:    string
	command: string
}

// #SshExecOutput describes the output shape for the "ssh.exec" operation.
#SshExecOutput: {
	exit_code: int
	stdout:    string
	stderr:    string
}

// #SshCopyInput describes the input shape for the "ssh.copy" operation.
#SshCopyInput: {
	host:        string
	port:        int & >=1 & <=65535 | *22
	user:        string
	local_path:  string
	remote_path: string
	direction:   "upload" | "download"
}

// #SshCopyOutput describes the output shape for the "ssh.copy" operation.
#SshCopyOutput: {
	bytes_transferred: int & >=0
	remote_path:       string
}

// #SshPortForwardInput describes the input shape for "ssh.port_forward".
#SshPortForwardInput: {
	host:        string
	port:        int & >=1 & <=65535 | *22
	user:        string
	local_port:  int & >=1 & <=65535
	remote_host: string
	remote_port: int & >=1 & <=65535
}

// #SshPortForwardOutput describes the output shape for "ssh.port_forward".
// ADR-0023: session_id (UuidV7) is returned so the operator can revoke the tunnel.
#SshPortForwardOutput: {
	local_port: int & >=1 & <=65535
	active:     bool
	// session_id is a UuidV7 opaque identifier for the active tunnel.
	// Pass to RevokePortForward to terminate the underlying ssh subprocess.
	session_id: string
	// local_addr is the bound address, e.g. "127.0.0.1:8080".
	local_addr: string
}

// #SshShellInput describes the input shape for the "ssh.shell" operation.
#SshShellInput: {
	host: string
	port: int & >=1 & <=65535 | *22
	user: string
	// commands is the ordered list of lines to send to the shell.
	commands: [...string]
}

// #SshShellOutput describes the output shape for the "ssh.shell" operation.
#SshShellOutput: {
	transcript: string
	exit_code:  int
}

// #HttpRequestInput describes the input shape for the "http.request" operation.
#HttpRequestInput: {
	url:    string
	method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
	// headers_public are injected as-is; auth headers come from the Secret.
	headers_public?: {[string]: string}
	body_template?:  string
}

// #HttpRequestOutput describes the output shape for the "http.request" operation.
#HttpRequestOutput: {
	status_code: int & >=100 & <=599
	// response_body is returned only when the Namespace Policy permits it.
	response_body?: string
	headers?:       {[string]: string}
}

// #HttpDownloadInput describes the input shape for the "http.download" operation.
#HttpDownloadInput: {
	url:        string
	local_path: string
}

// #HttpDownloadOutput describes the output shape for the "http.download" operation.
#HttpDownloadOutput: {
	bytes_written: int & >=0
	local_path:    string
}

// #HttpUploadInput describes the input shape for the "http.upload" operation.
#HttpUploadInput: {
	url:        string
	local_path: string
	method:     "POST" | "PUT" | *"POST"
}

// #HttpUploadOutput describes the output shape for the "http.upload" operation.
#HttpUploadOutput: {
	status_code: int & >=100 & <=599
}

// #SpawnInput describes the input shape for the "spawn" operation.
#SpawnInput: {
	program: string
	args:    [...string]
	// env_keys lists which Secret fields to inject as environment variables.
	env_keys: [...string]
	// working_dir is an optional override; defaults to the agent's cwd.
	working_dir?: string
}

// #SpawnOutput describes the output shape for the "spawn" operation.
#SpawnOutput: {
	exit_code: int
	// stdout_filtered contains the captured stdout with secret values redacted.
	stdout_filtered: string
	stderr_filtered: string
}

// #WriteTempfileInput describes the input shape for the "write_tempfile" operation.
#WriteTempfileInput: {
	// fifo controls whether the tempfile is a named pipe (FIFO) or a regular file.
	fifo: bool | *false
}

// #WriteTempfileOutput describes the output shape for the "write_tempfile" operation.
#WriteTempfileOutput: {
	// path is the absolute filesystem path of the created tempfile or FIFO.
	path: string
	// ttl_seconds is the remaining lifetime in seconds.
	ttl_seconds: int & >=1
}

// #ProxyExecutor is the domain service contract.  It resolves a Handle to its
// plaintext inside the agent process and invokes the appropriate external
// operation, ensuring secret material never crosses the MCP transport.
//
// The concrete implementation selects the operation-specific input/output
// shapes above.  This top-level definition records the allowed operation set
// and the invariant that every operation MUST produce an Audit Entry.
#ProxyExecutor: {
	// operation identifies which external capability is exercised.
	operation: #ProxyOperation

	// audit_required is always true; present to make the invariant explicit.
	audit_required: true
}
