// DDD role: ValueObject

package access_mediation

// Primitive wrappers chunk 1

#ConsumerName: string
#ConsumerPid: int & >=1
#DenialReason: string
#EnvKeys: [...string]
#ExitCode: int
#Host: string
#LocalAddr: string
#LocalPath: string
#LocalPort: int & >=1 & <=65535
