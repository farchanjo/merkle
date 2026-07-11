// DDD role: ValueObject

package access_mediation

#SshExecInput: {
	host: #Host
	port: #Port
	user: #User
	command: #Command
}

// #SshExecOutput describes the output shape for the "ssh.exec" operation.
