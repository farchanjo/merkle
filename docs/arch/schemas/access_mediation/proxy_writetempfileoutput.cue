// DDD role: ValueObject

package access_mediation

#WriteTempfileOutput: {
	// path is the absolute filesystem path of the created tempfile or FIFO.
	path: #Path
	// ttl_seconds is the remaining lifetime in seconds.
	ttl_seconds: #TtlSeconds
}

// #ProxyExecutor is the domain service contract.  It resolves a Handle to its
// plaintext inside the agent process and invokes the appropriate external
// operation, ensuring secret material never crosses the MCP transport.
//
// The concrete implementation selects the operation-specific input/output
// shapes above.  This top-level definition records the allowed operation set
// and the invariant that every operation MUST produce an Audit Entry.
