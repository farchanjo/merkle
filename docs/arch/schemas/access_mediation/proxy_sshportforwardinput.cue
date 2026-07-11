// DDD role: ValueObject

package access_mediation

#SshPortForwardInput: {
	host: #Host
	port: #Port
	user: #User
	local_port: #LocalPort
	remote_host: #RemoteHost
	remote_port: #RemotePort
}

// #SshPortForwardOutput describes the output shape for "ssh.port_forward".
// ADR-0023: session_id (UuidV7) is returned so the operator can revoke the tunnel.
