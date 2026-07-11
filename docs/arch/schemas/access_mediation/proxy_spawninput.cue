// DDD role: ValueObject

package access_mediation

#SpawnInput: {
	program: #Program
	args: #Args
	// env_keys lists which Secret fields to inject as environment variables.
	env_keys: #EnvKeys
	// working_dir is an optional override; defaults to the agent's cwd.
	working_dir?: #WorkingDir
}

// #SpawnOutput describes the output shape for the "spawn" operation.
