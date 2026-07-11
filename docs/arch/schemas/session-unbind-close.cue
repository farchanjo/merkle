// DDD role: ValueObject
package schemas

// #SessionCloseEnabled product gate.
// DDD role: ValueObject
#SessionCloseEnabled: true

// #SessionUnbindClose posture for DELETE /v1/sessions.
// DDD role: ValueObject
#SessionUnbindClose: {
	enabled:                     #SessionCloseEnabled
	path:                        "/v1/sessions/{session_id}"
	method:                      "DELETE"
	clears_use_tokens:           true
	clears_tempfiles:            true
	kills_port_forwards:         true
	namespace_bindings_persist:  true
}
