// DDD role: ValueObject

package schemas

// #DevicePairHttpStatus is the success status for enrollment.
// DDD role: ValueObject
#DevicePairHttpStatus: 201

// #DevicePairEndpoint product gate.
// DDD role: ValueObject
#DevicePairEndpoint: {
	method: "POST"
	path:   "/v1/devices"
	status: #DevicePairHttpStatus
}
