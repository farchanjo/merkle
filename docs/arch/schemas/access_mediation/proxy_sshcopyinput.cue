// DDD role: ValueObject

package access_mediation

#SshCopyInput: {
	host: #Host
	port: #Port
	user: #User
	local_path: #LocalPath
	remote_path: #RemotePath
	direction:   "upload" | "download"
}

// #SshCopyOutput describes the output shape for the "ssh.copy" operation.
