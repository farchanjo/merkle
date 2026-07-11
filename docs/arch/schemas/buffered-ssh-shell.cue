// DDD role: ValueObject
package schemas
// #BufferedSshShellEnabled product gate.
// DDD role: ValueObject
#BufferedSshShellEnabled: true
// #BufferedSshShell path.
// DDD role: ValueObject
#BufferedSshShell: { enabled: #BufferedSshShellEnabled, path: "/v1/proxy/ssh/shell" }
