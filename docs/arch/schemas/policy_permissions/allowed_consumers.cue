// DDD role: ValueObject

package policy_permissions

// #AllowedConsumers is the ValueObject encoding the glob allowlist of process names
// authorized to dereference Use Tokens via the Companion Socket for a Namespace.
// Globs are matched against the peer process name (resolved from PID on the socket).
// Pattern constraint: lowercase alphanumerics, hyphens, and glob wildcards (* ?) only.
// Examples: "ssh", "curl", "my-app-*", "vault-*".
#AllowedConsumers: {
	globs: [...(string & =~"^[a-z0-9*?-]+$")]
}
