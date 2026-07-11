// DDD role: ValueObject

package schemas

// #PortForwardEnabled is the product gate flag.
// DDD role: ValueObject
#PortForwardEnabled: true

// #SshPortForward product gate posture.
// DDD role: ValueObject
#SshPortForward: {
	enabled: #PortForwardEnabled
	path:    "/v1/proxy/ssh/port-forward"
}
