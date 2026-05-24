// DDD role: ValueObject

package policy_permissions

// #RateLimitClass enumerates the operation classes subject to rate limiting.
// plaintext_reads: vault.get and vault.describe calls that return public metadata.
// use_token_resolves: Companion Socket dereferences of Use Tokens.
// reveals: vault.reveal operations returning plaintext to the MCP transport.
#RateLimitClass: "plaintext_reads" | "use_token_resolves" | "reveals"

// #RateLimit is the ValueObject encoding a per-class sliding-window rate limit.
// The enforcement window is rolling (not fixed-bucket).
#RateLimit: {
	class:          #RateLimitClass
	max_count:      int & >=1
	window_seconds: int & >=1
}
