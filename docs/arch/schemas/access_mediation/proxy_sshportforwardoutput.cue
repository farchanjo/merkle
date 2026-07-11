// DDD role: ValueObject

package access_mediation

#SshPortForwardOutput: {
	local_port: #LocalPort
	active: #Active
	// session_id is a UuidV7 opaque identifier for the active tunnel.
	// Pass to RevokePortForward to terminate the underlying ssh subprocess.
	session_id: #SessionId
	// local_addr is the bound address, e.g. "127.0.0.1:8080".
	local_addr: #LocalAddr
}

// #SshShellInput describes the input shape for the "ssh.shell" operation.
