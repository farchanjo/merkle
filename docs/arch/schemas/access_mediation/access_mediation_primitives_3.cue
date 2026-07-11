// DDD role: ValueObject

package access_mediation

// Primitive wrappers chunk 3

#RemoteHost: string
#RemotePath: string
#RemotePort: int & >=1 & <=65535
#ResponseBody: string
#SessionId: string
#SlashCommand: bool
#StatusCode: int & >=100 & <=599
#Stderr: string
#StderrFiltered: string
