// DDD role: ValueObject

package access_mediation

#SshShellInput: {
	host: #Host
	port: #Port
	user: #User
	// commands is the ordered list of lines to send to the shell.
	commands: #Commands
}

// #SshShellOutput describes the output shape for the "ssh.shell" operation.
