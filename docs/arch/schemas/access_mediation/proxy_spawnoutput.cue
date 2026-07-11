// DDD role: ValueObject

package access_mediation

#SpawnOutput: {
	exit_code: #ExitCode
	// stdout_filtered contains the captured stdout with secret values redacted.
	stdout_filtered: #StdoutFiltered
	stderr_filtered: #StderrFiltered
}

// #WriteTempfileInput describes the input shape for the "write_tempfile" operation.
